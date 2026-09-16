package collector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// The collector's own security group.
//
// The CloudFormation template takes an existing group id rather than creating
// one, because the group has to exist before the Instaclustr firewall can
// allowlist it — the allowlist is asserted during install, and the stack does
// not exist yet at that point. So the CLI owns this group's lifecycle.

// CollectorEgressPorts are the only ports the collector ever opens outbound:
// 443 reaches the container registry, DBGorilla, and the Instaclustr API and
// its Prometheus endpoints; 5432 reaches the cluster.
var CollectorEgressPorts = []int32{443, 5432}

// collectorSGDescription is required by EC2 and doubles as provenance.
const collectorSGDescription = "DBGorilla collector egress (managed by the dbgorilla CLI)"

// CollectorSecurityGroupName is the group's name within its VPC. Names are
// unique per VPC, which is what makes the lookup below a reliable identity.
func CollectorSecurityGroupName(stackName string) string {
	if stackName == "" {
		stackName = "dbgorilla-collector"
	}
	return stackName + "-egress"
}

// EnsureCollectorSecurityGroup returns the id of the collector's security group
// in vpcID, creating it if absent, and reports whether this call created it so
// uninstall can avoid deleting a group it did not make.
//
// The group is created with no ingress at all — nothing connects *to* a
// collector — and egress narrowed to the ports it needs. EC2 attaches an
// allow-all egress rule to every new group, so that default is revoked; leaving
// it would make the narrowing cosmetic.
func EnsureCollectorSecurityGroup(ctx context.Context, client *ec2.Client, vpcID, stackName string) (string, bool, error) {
	if vpcID == "" {
		return "", false, errors.New("cannot create the collector security group without a VPC id")
	}
	name := CollectorSecurityGroupName(stackName)

	if id, err := findCollectorSecurityGroup(ctx, client, vpcID, name); err != nil {
		return "", false, err
	} else if id != "" {
		return id, false, nil
	}

	out, err := client.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(name),
		Description: aws.String(collectorSGDescription),
		VpcId:       aws.String(vpcID),
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeSecurityGroup,
			Tags: []ec2types.Tag{
				{Key: aws.String("Name"), Value: aws.String(name)},
				{Key: aws.String("ManagedBy"), Value: aws.String("dbgorilla-cli")},
			},
		}},
	})
	if err != nil {
		// A concurrent install may have won the race; adopt its group rather
		// than failing an otherwise fine install.
		if isDuplicateSGError(err) {
			if id, ferr := findCollectorSecurityGroup(ctx, client, vpcID, name); ferr == nil && id != "" {
				return id, false, nil
			}
		}
		return "", false, fmt.Errorf("cannot create the collector security group in %s: %w", vpcID, err)
	}
	id := aws.ToString(out.GroupId)

	if err := narrowCollectorEgress(ctx, client, id); err != nil {
		// Leaving a half-configured group behind would allow all egress under a
		// name that claims to be narrowed.
		_, _ = client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(id)})
		return "", false, err
	}
	return id, true, nil
}

// narrowCollectorEgress authorizes the ports the collector needs and removes
// the allow-all rule EC2 adds to every new group.
func narrowCollectorEgress(ctx context.Context, client *ec2.Client, groupID string) error {
	perms := make([]ec2types.IpPermission, 0, len(CollectorEgressPorts))
	for _, p := range CollectorEgressPorts {
		perms = append(perms, ec2types.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(p),
			ToPort:     aws.Int32(p),
			IpRanges: []ec2types.IpRange{{
				CidrIp:      aws.String("0.0.0.0/0"),
				Description: aws.String(collectorSGDescription),
			}},
		})
	}
	if _, err := client.AuthorizeSecurityGroupEgress(ctx, &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId:       aws.String(groupID),
		IpPermissions: perms,
	}); err != nil {
		return fmt.Errorf("cannot authorize collector egress on %s: %w", groupID, err)
	}

	// Revoke the default allow-all. Its absence is not an error: a group that
	// never had it is already in the state we want.
	_, err := client.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{
		GroupId: aws.String(groupID),
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("-1"),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
		}},
	})
	if err != nil && !isMissingPermissionError(err) {
		return fmt.Errorf("cannot revoke the default allow-all egress on %s: %w", groupID, err)
	}
	return nil
}

// findCollectorSecurityGroup looks the group up by name within the VPC, where
// names are unique. An empty id means it does not exist.
func findCollectorSecurityGroup(ctx context.Context, client *ec2.Client, vpcID, name string) (string, error) {
	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			{Name: aws.String("group-name"), Values: []string{name}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("cannot look up the collector security group in %s: %w", vpcID, err)
	}
	if len(out.SecurityGroups) == 0 {
		return "", nil
	}
	return aws.ToString(out.SecurityGroups[0].GroupId), nil
}

// DeleteCollectorSecurityGroup removes the group. It is safe to call when the
// group is already gone.
//
// The caller must delete the ECS service first: while a task's elastic network
// interface still references the group, EC2 refuses with DependencyViolation,
// and that refusal is surfaced rather than swallowed so the operator is not
// told a group was removed when it was not.
func DeleteCollectorSecurityGroup(ctx context.Context, client *ec2.Client, groupID string) error {
	if groupID == "" {
		return nil
	}
	_, err := client.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: aws.String(groupID)})
	if err == nil || isMissingSGError(err) {
		return nil
	}
	if isDependencyViolation(err) {
		return fmt.Errorf("security group %s is still in use — the collector's network interface has not been "+
			"released yet; retry in a minute or remove it from the console: %w", groupID, err)
	}
	return fmt.Errorf("cannot delete the collector security group %s: %w", groupID, err)
}

// EC2 reports these as error codes in the message; the SDK models them as
// generic API errors, so match on the code string.
func isDuplicateSGError(err error) bool { return awsErrorCodeIs(err, "InvalidGroup.Duplicate") }
func isMissingSGError(err error) bool   { return awsErrorCodeIs(err, "InvalidGroup.NotFound") }
func isMissingPermissionError(err error) bool {
	return awsErrorCodeIs(err, "InvalidPermission.NotFound")
}
func isDependencyViolation(err error) bool { return awsErrorCodeIs(err, "DependencyViolation") }

func awsErrorCodeIs(err error, code string) bool {
	if err == nil {
		return false
	}
	var ae interface{ ErrorCode() string }
	if errors.As(err, &ae) {
		return ae.ErrorCode() == code
	}
	return strings.Contains(err.Error(), code)
}
