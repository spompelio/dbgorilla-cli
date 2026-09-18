package cmd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dbgorilla/dbgorilla-cli/internal/collector"
	"github.com/dbgorilla/dbgorilla-cli/internal/style"
	"github.com/spf13/cobra"
)

// GCP-path seams: every operation that reaches a live Google Cloud project is
// substitutable, so the `--target gcp` workflow is testable without one.
var (
	gcpAvailable         = collector.GcpAvailable
	gcpIdentity          = collector.GcpIdentity
	gcpProject           = collector.GcpProject
	discoverGcpTarget    = collector.DiscoverGcpTarget
	resolveGcpSubnetwork = collector.ResolveGcpSubnetwork
	gcpSubnetworkPGA     = collector.SubnetworkPrivateGoogleAccess
	gcpDeploymentStatus  = collector.GcpDeploymentStatus
	deleteGcpDeployment  = collector.DeleteGcpDeployment
	scaleGcpMig          = collector.ScaleGcpMig
	restartGcpMig        = collector.RestartGcpMig
	tailGcpLogs          = collector.TailGcpLogs
	runGcpDeploy         = collector.GcpDeploy.Run
	ensureGcpSecrets     = collector.EnsureGcpSecrets
	deleteGcpSecrets     = collector.DeleteGcpSecrets
)

var (
	// gcpDeploymentNameRe is the service-account account_id grammar the
	// deployment name feeds.
	gcpDeploymentNameRe = regexp.MustCompile(`^[a-z](?:[-a-z0-9]{4,28})[a-z0-9]$`)
	// gcpProjectNumberRe matches a project number, which cannot stand in for
	// the project ID in service-account emails.
	gcpProjectNumberRe = regexp.MustCompile(`^[0-9]+$`)
	// gcpServiceAccountRe is the resource form Infrastructure Manager expects.
	gcpServiceAccountRe = regexp.MustCompile(`^projects/[^/]+/serviceAccounts/[^/@]+@[^/]+$`)
)

// awsOnlyFlags are refused on the gcp target rather than silently ignored.
var awsOnlyFlags = []string{
	"dbi-resource-id", "subnets", "security-group-id", "assign-public-ip", "stack-name",
	"template-url", "config", "run-grant", "grant-user", "grant-password",
}

func init() {
	installCmd.Flags().String("project", "", "GCP: project ID to act on (default: the credentials' project, GOOGLE_CLOUD_PROJECT, or gcloud's active configuration)")
	installCmd.Flags().String("deployment-name", collector.DefaultGcpDeploymentName, "GCP: Infrastructure Manager deployment name")
	installCmd.Flags().String("template-source", "", "GCP: deploy this Terraform template directory instead of the published one (must be a gs:// address)")
	installCmd.Flags().String("deploy-service-account", "", "GCP: service account Infrastructure Manager actuates Terraform as (projects/<project>/serviceAccounts/<email>)")
	installCmd.Flags().String("network", "", "GCP: VPC for the collector instance, as projects/<project>/global/networks/<name> (discovered from the database when omitted). The VPC needs egress to the internet (Cloud NAT) for the image pull and the DBGorilla connection")
	installCmd.Flags().String("subnetwork", "", "GCP: subnetwork for the collector instance (auto-selected when the VPC has exactly one in the database's region; required otherwise)")
	installCmd.Flags().Bool("allow-project-wide-login", false, "GCP: let the collector's service account use IAM database login on every Cloud SQL instance in the project, not only the monitored instance and its read replicas (drops the IAM Condition on roles/cloudsql.instanceUser)")
}

// runInstallGCP deploys the collector to a Compute Engine managed instance
// group via Infrastructure Manager.
func runInstallGCP(cmd *cobra.Command) error {
	apiURL, err := requireInstallSession(cmd)
	if err != nil {
		return err
	}
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// Flag checks first: they cost nothing.
	for _, f := range awsOnlyFlags {
		if cmd.Flags().Changed(f) {
			return fmt.Errorf("--%s applies to --target aws only", f)
		}
	}
	deployServiceAccount, _ := cmd.Flags().GetString("deploy-service-account")
	switch {
	case deployServiceAccount == "" && !dryRun:
		return errors.New("pass --deploy-service-account: the account Infrastructure Manager actuates Terraform as " +
			"(it needs roles/config.agent plus permission to create the collector's instance group and service account)")
	case deployServiceAccount != "" && !gcpServiceAccountRe.MatchString(deployServiceAccount):
		return fmt.Errorf("--deploy-service-account %q must be of the form projects/<project>/serviceAccounts/<email>", deployServiceAccount)
	}
	deploymentName, _ := cmd.Flags().GetString("deployment-name")
	if !gcpDeploymentNameRe.MatchString(deploymentName) {
		return fmt.Errorf("--deployment-name %q must be 6-30 chars of [a-z0-9-], starting with a letter and not ending with '-' "+
			"(it names the collector's service account and secrets)", deploymentName)
	}
	providerType, _ := cmd.Flags().GetString("provider-type")
	if !collector.ValidGcpProviderType(providerType) {
		return fmt.Errorf("--provider-type %q is not a Google Cloud provider (expected cloud_sql or alloydb)", providerType)
	}
	templateSource, _ := cmd.Flags().GetString("template-source")
	if templateSource == "" {
		templateSource = collector.HostedGcpTemplateSource()
	}

	prior, status, err := priorCloudInstall(dryRun, (*collector.State).IsGCP,
		func(st *collector.State) (string, error) {
			return gcpDeploymentStatus(st.Project, st.Region, st.DeploymentName)
		},
		"deployment", func(st *collector.State) string { return st.DeploymentName })
	if err != nil {
		return err
	}
	if prior != nil {
		return fmt.Errorf("collector deployment %q already exists (%s). "+
			"Run `dbg collector uninstall` first; changing an installed gcp collector in place is not supported yet",
			prior.DeploymentName, status)
	}

	if err := printCloudIdentity("Google Cloud", gcpAvailable, gcpIdentity); err != nil {
		return err
	}
	client, err := requireCollectorSupport(cmd, apiURL)
	if err != nil {
		return err
	}

	project, _ := cmd.Flags().GetString("project")
	if project == "" {
		if project, err = gcpProject(); err != nil {
			return err
		}
	}
	if gcpProjectNumberRe.MatchString(project) {
		return fmt.Errorf("project %q is a project number; pass the project ID (--project), "+
			"which names the collector's service account", project)
	}
	target, err := resolveGcpTarget(cmd, project)
	if err != nil {
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Target database: %s (%s)", target.InstanceID, target.Host)))

	if err := requireNoRuntime(dryRun,
		func() (string, error) { return gcpDeploymentStatus(project, target.Region, deploymentName) },
		"deployment", deploymentName, "--deployment-name"); err != nil {
		return err
	}

	dbPassword := dbPasswordFlag(cmd)
	if err := resolveGcpAuth(&target, dbPassword, deploymentName, project); err != nil {
		return err
	}

	network, _ := cmd.Flags().GetString("network")
	if network == "" {
		network = target.Network
	}
	if network == "" {
		return errors.New("could not determine the collector's VPC (the database reports no private network); pass --network")
	}
	subnetwork, _ := cmd.Flags().GetString("subnetwork")
	if subnetwork == "" {
		if subnetwork, err = resolveGcpSubnetwork(network, target.Region); err != nil {
			return err
		}
	}
	// Preflight, not a gate: without Private Google Access the instance's boot
	// script cannot fetch its secrets or pull the image, and the failure is an
	// opaque startup timeout the CLI never sees. A Cloud NAT also provides the
	// egress, so an off flag only warns.
	if pga, subnetPath, perr := gcpSubnetworkPGA(network, subnetwork, target.Region); perr == nil && !pga {
		fmt.Println(style.Warn(fmt.Sprintf(
			"⚠  subnetwork %s has Private Google Access OFF — without it (or a Cloud NAT) the "+
				"instance cannot reach Secret Manager or the registry at boot. Enable it with:\n"+
				"   gcloud compute networks subnets update %s --region=%s --enable-private-ip-google-access",
			subnetPath, lastPathSegmentOf(subnetPath), target.Region)))
	}

	targets := []collector.GcpTarget{target}
	commandsEnabled := resolveCommands(cmd, targets, gcpTargetLabel)
	allowProjectWideLogin, _ := cmd.Flags().GetBool("allow-project-wide-login")
	printGcpLoginScope(targets, allowProjectWideLogin, project)

	if dryRun {
		image, _ := resolveImage(cmd, nil)
		inputs, err := collector.GcpDeployInputs(collector.GcpStackInput{
			AgentID: "DRY-RUN", TenantID: "DRY-RUN",
			Image:                 image,
			Targets:               targets,
			Network:               network,
			Subnetwork:            subnetwork,
			Region:                target.Region,
			DeploymentName:        deploymentName,
			Project:               project,
			CommandsEnabled:       commandsEnabled,
			AllowProjectWideLogin: allowProjectWideLogin,
		})
		if err != nil {
			return err
		}
		fmt.Printf("\nDry run — probing the template for deployment %q (no identity minted, no secrets written):\n", deploymentName)
		printDeployParams(inputs, nil, "collector_config")
		printGcpSecretPlan(deploymentName)
		return runGcpDeploy(collector.GcpDeploy{
			Project: project, Region: target.Region, DeploymentName: deploymentName,
			TemplateSource: templateSource, DryRun: true,
		})
	}

	fmt.Println("Provisioning collector identity...")
	creds, err := client.ProvisionCollector()
	if err != nil {
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector provisioned (agent %s, tenant %s)", creds.AgentID, creds.TenantID)))

	image, imageSource := resolveImage(cmd, creds)
	image = pinImageOrWarn(image, "instance")
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector image: %s (%s)", image, imageSource)))

	inputs, err := collector.GcpDeployInputs(collector.GcpStackInput{
		AgentID:               creds.AgentID,
		TenantID:              creds.TenantID,
		Image:                 image,
		Endpoints:             endpointsFor(creds, cmd),
		Targets:               targets,
		Network:               network,
		Subnetwork:            subnetwork,
		Region:                target.Region,
		DeploymentName:        deploymentName,
		Project:               project,
		CommandsEnabled:       commandsEnabled,
		AllowProjectWideLogin: allowProjectWideLogin,
	})
	if err != nil {
		deprovisionOrWarn(client, creds.AgentID)
		return err
	}

	// The credentials go straight to Secret Manager, before the deploy: the
	// template only grants access to them, so they never reach Infrastructure
	// Manager (whose input values and state are readable by config.* roles).
	if err := ensureGcpSecrets(project, deploymentName, collector.GcpSecretValues{
		ServerSecret: creds.Secret,
		DBPassword:   dbPassword,
	}); err != nil {
		deleteGcpSecretsOrWarn(project, deploymentName)
		deprovisionOrWarn(client, creds.AgentID)
		return err
	}
	fmt.Println(style.Success("✓ Credentials written to Secret Manager (never sent to Infrastructure Manager)"))

	saveStateOrWarn(&collector.State{
		AgentID:        creds.AgentID,
		TenantID:       creds.TenantID,
		Domain:         creds.Domain,
		Target:         "gcp",
		Image:          image,
		TargetName:     target.DisplayName(),
		Project:        project,
		Region:         target.Region,
		DeploymentName: deploymentName,
		CreatedAt:      time.Now().UTC(),
	})

	fmt.Printf("Deploying to Compute Engine (deployment %q)...\n", deploymentName)
	deploy := collector.GcpDeploy{
		Project: project, Region: target.Region, DeploymentName: deploymentName,
		TemplateSource: templateSource, ServiceAccount: deployServiceAccount,
		Inputs: inputs,
	}
	if err := withSpinner("Deploying to Compute Engine…", func() error { return runGcpDeploy(deploy) }); err != nil {
		kept, derr := cloudDeployFailed(err, client, creds.AgentID, collector.GcpDeployTimeout(), "deployment", deploymentName,
			func() error {
				if err := withSpinner("Deleting the deployment…", func() error {
					return deleteGcpDeployment(project, target.Region, deploymentName)
				}); err != nil {
					return err
				}
				deleteGcpSecretsOrWarn(project, deploymentName)
				return nil
			},
			func() { deleteGcpSecretsOrWarn(project, deploymentName) },
			"   Watch it with: dbg collector status\n")
		if kept {
			printGcpGrantGuidance(target, deploymentName, project)
		}
		return derr
	}

	fmt.Println(style.Success(fmt.Sprintf("✓ Collector deploying to Compute Engine (deployment %s).", deploymentName)))
	printGcpGrantGuidance(target, deploymentName, project)
	fmt.Println("\nConfirm it connected with: dbg collector status")
	return nil
}

// printGcpSecretPlan names the Secret Manager secrets a real install writes.
// Only names are shown — no code path on the dry run holds a credential.
func printGcpSecretPlan(deploymentName string) {
	fmt.Println("    Secret Manager secrets the install writes (values never reach Infrastructure Manager):")
	for _, id := range collector.GcpSecretIDs(deploymentName) {
		fmt.Printf("      %s\n", id)
	}
}

// deleteGcpSecretsOrWarn is the rollback/uninstall counterpart of
// ensureGcpSecrets: best effort, with the console fallback named.
func deleteGcpSecretsOrWarn(project, deploymentName string) {
	if err := deleteGcpSecrets(project, deploymentName); err != nil {
		fmt.Println(style.Warn(fmt.Sprintf("⚠  could not delete the collector's Secret Manager secrets: %v "+
			"(delete %s-* in the console)", err, deploymentName)))
	}
}

// lastPathSegmentOf trims a resource path to its final name segment, for
// messages that quote a runnable gcloud command.
func lastPathSegmentOf(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// resolveGcpTarget picks and completes the database target. An ambiguous
// project becomes a picker on a real terminal; otherwise the candidates are
// listed in the error.
func resolveGcpTarget(cmd *cobra.Command, project string) (collector.GcpTarget, error) {
	id, _ := cmd.Flags().GetString("db-instance-id")
	providerType, _ := cmd.Flags().GetString("provider-type")
	seed := collector.GcpTarget{Project: project}
	if names, _ := cmd.Flags().GetString("db-name"); names != "" {
		seed.Databases = splitCSV(names)
	}
	seed.User, _ = cmd.Flags().GetString("db-user")

	target, err := discoverGcpTarget(id, providerType, seed)
	var amb *collector.AmbiguousTargetError
	if errors.As(err, &amb) && interactiveSelectable(cmd) {
		choice, perr := pickTarget(amb, "")
		if perr != nil {
			return collector.GcpTarget{}, perr
		}
		return discoverGcpTarget(choice.ID, choice.ProviderType, seed)
	}
	return target, err
}

// resolveGcpAuth settles the target's auth: --db-password forces password
// auth; otherwise IAM as the runtime service account's database identity.
func resolveGcpAuth(target *collector.GcpTarget, dbPassword, deploymentName, project string) error {
	if dbPassword != "" {
		target.AuthMethod = "password"
		return nil
	}
	// mysql + cloud_sql + gcp_iam is supported since the collector registered
	// the triples (live-tested 2026-09-04); the CLI's earlier refusal went
	// with the gate. The flag is spelled per engine — dots are illegal in
	// MySQL flag names.
	if !target.IamEnabled {
		flag := "cloudsql.iam_authentication"
		if target.Engine == "mysql" {
			flag = "cloudsql_iam_authentication"
		}
		return fmt.Errorf("Cloud SQL instance %q does not have IAM database authentication enabled — "+
			"turn on the %s flag, or pass --db-password for password auth",
			target.InstanceID, flag)
	}
	// The collector refuses IAM on the default per-instance server CA by name
	// (a minted token needs a verifiable transport, and that CA attests no
	// hostname). Refuse here, at install time, with the same ways out.
	if target.ProviderType == "cloud_sql" && target.ServerCaMode == "GOOGLE_MANAGED_INTERNAL_CA" {
		return fmt.Errorf("Cloud SQL instance %q uses the default per-instance server CA, which "+
			"IAM auth cannot verify — migrate it with `--server-ca-mode=GOOGLE_MANAGED_CAS_CA` "+
			"(one-way), or pass --db-password for password auth",
			target.InstanceID)
	}
	if target.User != "" {
		fmt.Println(style.Warn("⚠  --db-user only applies to password auth — IAM auth derives the " +
			"database user from the runtime service account; ignoring it"))
	}
	target.AuthMethod = "gcp_iam"
	sa := collector.GcpRuntimeServiceAccountFor(deploymentName, project)
	target.User = collector.GcpDatabaseUserFor(sa, target.Engine)
	return nil
}

// printGcpLoginScope says how far the collector's IAM database login reaches.
// The login roles bind on the project; on Cloud SQL an IAM Condition narrows
// roles/cloudsql.instanceUser to the monitored instance and its replicas, and
// dropping that is an explicit choice worth a warning. AlloyDB's login check
// matches no resource name, so there is nothing to narrow — say so. Either
// way the account only logs in where it has been registered as a database
// user.
func printGcpLoginScope(targets []collector.GcpTarget, allowProjectWide bool, project string) {
	scoped := collector.GcpLoginInstances(targets)
	switch {
	case len(scoped) > 0 && allowProjectWide:
		fmt.Println(style.Warn(fmt.Sprintf("⚠  --allow-project-wide-login: the collector's service account may use IAM login on "+
			"any Cloud SQL instance in project %s that registers it as a user (no IAM Condition on roles/cloudsql.instanceUser)", project)))
	case len(scoped) > 0:
		fmt.Println(style.Success(fmt.Sprintf("✓ IAM database login scoped to %s (IAM Condition on roles/cloudsql.instanceUser)",
			strings.Join(scoped, ", "))))
	}
	for _, t := range targets {
		if t.ProviderType == "alloydb" {
			fmt.Println(style.Warn(fmt.Sprintf("⚠  AlloyDB IAM login cannot be scoped by IAM Condition: the collector's service account may "+
				"log in to any AlloyDB instance in project %s that registers it as a user (roles/alloydb.databaseUser is project-wide)", project)))
			break
		}
	}
}

// printGcpGrantGuidance names the two grant steps IAM auth needs: registering
// the collector's service account as a database user, and the in-database
// read grants.
func printGcpGrantGuidance(target collector.GcpTarget, deploymentName, project string) {
	if target.AuthMethod != "gcp_iam" {
		return
	}
	sa := collector.GcpRuntimeServiceAccountFor(deploymentName, project)
	fmt.Println("\nGrant the collector database access:")
	if target.ProviderType == "alloydb" {
		// AlloyDB registers the literal username given; the collector logs in
		// as the trimmed form.
		fmt.Printf("  1. Register the service account as a database user:\n"+
			"     gcloud alloydb users create %s --cluster=%s --region=%s --type=IAM_BASED\n",
			target.User, target.ClusterID, target.Region)
	} else {
		fmt.Printf("  1. Register the service account as a database user:\n"+
			"     gcloud sql users create %s --instance=%s --type=cloud_iam_service_account\n",
			sa, target.InstanceID)
	}
	fmt.Printf("  2. Connect as an admin and grant read access to %q:\n", target.User)
	for _, stmt := range collector.GcpGrantStatements(target.User, target.Databases) {
		fmt.Printf("     %s\n", stmt)
	}
}

// gcpStatus reports a GCP-deployed collector's deployment state plus its
// control-plane connection.
func gcpStatus(cmd *cobra.Command, st *collector.State) error {
	return cloudStatus(cmd, st, "Deployment", st.DeploymentName, func() (string, error) {
		return gcpDeploymentStatus(st.Project, st.Region, st.DeploymentName)
	})
}
