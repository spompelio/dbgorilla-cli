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
	readGcpDeployment    = collector.GetGcpDeploymentSpec
	upgradeGcpImage      = collector.UpgradeGcpImage
	waitGcpMigStable     = collector.WaitGcpMigStable
	ensureGcpDBPassword  = collector.EnsureGcpDBPassword
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
	deploymentName, _ := cmd.Flags().GetString("deployment-name")
	if !gcpDeploymentNameRe.MatchString(deploymentName) {
		return fmt.Errorf("--deployment-name %q must be 6-30 chars of [a-z0-9-], starting with a letter and not ending with '-' "+
			"(it names the collector's service account and secrets)", deploymentName)
	}
	providerType, _ := cmd.Flags().GetString("provider-type")
	if !collector.ValidGcpProviderType(providerType) {
		return fmt.Errorf("--provider-type %q is not a Google Cloud provider (expected cloud_sql or alloydb)", providerType)
	}

	// An existing gcp collector isn't a conflict — it's an update: re-run with
	// a different --db-instance-id to change which database it monitors, or
	// with none to re-discover the same one (a new read replica joins the
	// login condition), in place (no re-mint, no teardown). Dry runs always
	// take the fresh path below.
	prior, status, err := priorCloudInstall(dryRun, (*collector.State).IsGCP,
		func(st *collector.State) (string, error) {
			return gcpDeploymentStatus(st.Project, st.Region, st.DeploymentName)
		},
		"deployment", func(st *collector.State) string { return st.DeploymentName })
	if err != nil {
		return err
	}
	if prior != nil {
		return runUpdateGCP(cmd, prior, status)
	}

	deployServiceAccount, _ := cmd.Flags().GetString("deploy-service-account")
	switch {
	case deployServiceAccount == "" && !dryRun:
		return errors.New("pass --deploy-service-account: the account Infrastructure Manager actuates Terraform as " +
			"(it needs roles/config.agent plus permission to create the collector's instance group and service account)")
	case deployServiceAccount != "" && !gcpServiceAccountRe.MatchString(deployServiceAccount):
		return fmt.Errorf("--deploy-service-account %q must be of the form projects/<project>/serviceAccounts/<email>", deployServiceAccount)
	}
	templateSource, _ := cmd.Flags().GetString("template-source")
	if templateSource == "" {
		templateSource = collector.HostedGcpTemplateSource()
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
	return resolveGcpTargetFrom(cmd, id, providerType, seed)
}

// resolveGcpTargetFrom is resolveGcpTarget with the id, provider hint and
// seed supplied — the update path defaults them from what the collector
// monitors now.
func resolveGcpTargetFrom(cmd *cobra.Command, id, providerType string, seed collector.GcpTarget) (collector.GcpTarget, error) {
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

// --- update and upgrade ------------------------------------------------------

// runUpdateGCP updates an installed gcp collector in place: the database it
// monitors (a re-run with --db-instance-id, or the same one re-discovered so
// a new read replica joins the login condition), its auth, and its
// query-analysis commands. Identity, endpoints, image and networking come
// from the deployment itself — nothing is re-minted, nothing torn down.
func runUpdateGCP(cmd *cobra.Command, st *collector.State, status string) error {
	// Where the collector runs cannot change in place.
	for _, f := range []string{"network", "subnetwork", "deploy-service-account"} {
		if cmd.Flags().Changed(f) {
			return fmt.Errorf("--%s cannot change an installed collector in place; "+
				"run `dbg collector uninstall` and re-install to move it", f)
		}
	}
	if p, _ := cmd.Flags().GetString("project"); p != "" && p != st.Project {
		return fmt.Errorf("collector %s runs in project %s; --project %s cannot move it in place "+
			"(run `dbg collector uninstall` and re-install)", st.AgentID, st.Project, p)
	}
	if n, _ := cmd.Flags().GetString("deployment-name"); cmd.Flags().Changed("deployment-name") && n != st.DeploymentName {
		return fmt.Errorf("collector %s is deployment %q; --deployment-name %q cannot rename it in place "+
			"(run `dbg collector uninstall` and re-install)", st.AgentID, st.DeploymentName, n)
	}
	if err := printCloudIdentity("Google Cloud", gcpAvailable, gcpIdentity); err != nil {
		return err
	}

	spec, err := readGcpDeployment(st.Project, st.Region, st.DeploymentName)
	if err != nil {
		return err
	}
	if spec == nil {
		return fmt.Errorf("deployment %q no longer exists — re-run to install fresh", st.DeploymentName)
	}
	stored, comp, err := gcpStoredComponent(spec, st.DeploymentName)
	if err != nil {
		return err
	}
	templateSource, err := gcpUpdateTemplateSource(spec.TemplateSource)
	if err != nil {
		return err
	}
	// As on install, --template-source names the directory to apply — for a
	// template under development, before it is published.
	if v, _ := cmd.Flags().GetString("template-source"); v != "" {
		templateSource = v
	}

	// Which database: the flag, else the one the collector monitors now.
	storedID, storedType := gcpStoredTargetID(comp)
	id, providerType := storedID, storedType
	if v, _ := cmd.Flags().GetString("db-instance-id"); v != "" {
		id = v
	}
	if v, _ := cmd.Flags().GetString("provider-type"); v != "" {
		providerType = v
	}
	sameTarget := id == storedID && providerType == storedType
	seed := collector.GcpTarget{Project: st.Project}
	if names, _ := cmd.Flags().GetString("db-name"); names != "" {
		seed.Databases = splitCSV(names)
	} else if sameTarget {
		seed.Databases = comp.Connect.Databases
	}
	seed.User, _ = cmd.Flags().GetString("db-user")
	target, err := resolveGcpTargetFrom(cmd, id, providerType, seed)
	if err != nil {
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Target database: %s (%s)", target.InstanceID, target.Host)))

	// Auth: a password given now wins; a password-auth collector keeps the
	// password already in Secret Manager unless --db-password "" asks for
	// the move to IAM; otherwise IAM, settled as on install.
	dbPassword := dbPasswordFlag(cmd)
	wantIAM := cmd.Flags().Changed("db-password") && dbPassword == ""
	if dbPassword == "" && !wantIAM && sameTarget && comp.Auth.Method == "password" {
		target.AuthMethod = "password"
		if target.User == "" {
			target.User = comp.Auth.User
		}
	} else if err := resolveGcpAuth(&target, dbPassword, st.DeploymentName, st.Project); err != nil {
		return err
	}
	targets := []collector.GcpTarget{target}

	// Query-analysis commands: the flags when given; otherwise what the
	// collector runs with now (a new target settles them as an install does).
	commandsEnabled := stored.Commands.Enabled
	if cmd.Flags().Changed("commands") || cmd.Flags().Changed("enable-commands") || !sameTarget {
		commandsEnabled = resolveCommands(cmd, targets, gcpTargetLabel)
	} else {
		targets[0].Commands = comp.Commands
	}
	// The login scope: the flag when given; otherwise what the deployment
	// chose. A deployment from before login_instances existed gets the
	// condition — that is the point of moving it forward.
	allowProjectWideLogin, _ := cmd.Flags().GetBool("allow-project-wide-login")
	if !cmd.Flags().Changed("allow-project-wide-login") {
		if v, declared := spec.Inputs["login_instances"]; declared && v == "" && comp.Provider.Type == "cloud_sql" {
			allowProjectWideLogin = true
		}
	}
	printGcpLoginScope(targets, allowProjectWideLogin, st.Project)

	inputs, err := collector.GcpDeployInputs(collector.GcpStackInput{
		AgentID:               stored.Dbgorilla.AgentID,
		TenantID:              stored.Dbgorilla.TenantID,
		Image:                 spec.Inputs["collector_image"],
		Endpoints:             gcpStoredEndpoints(stored, cmd),
		Targets:               targets,
		Network:               spec.Inputs["network"],
		Subnetwork:            spec.Inputs["subnetwork"],
		Region:                st.Region,
		DeploymentName:        st.DeploymentName,
		Project:               st.Project,
		CommandsEnabled:       commandsEnabled,
		StableEgress:          spec.Inputs["stable_egress"] == "true",
		NatSubnetCidr:         spec.Inputs["nat_subnet_cidr"],
		AllowProjectWideLogin: allowProjectWideLogin,
	})
	if err != nil {
		return err
	}

	if dbPassword != "" {
		if err := ensureGcpDBPassword(st.Project, st.DeploymentName, dbPassword); err != nil {
			return err
		}
		fmt.Println(style.Success("✓ Database password written to Secret Manager"))
	}
	st.TargetName = target.DisplayName()
	saveStateOrWarn(st)

	fmt.Printf("Updating collector %s in place (deployment %q, %s)...\n", st.AgentID, st.DeploymentName, status)
	deploy := collector.GcpDeploy{
		Project: st.Project, Region: st.Region, DeploymentName: st.DeploymentName,
		TemplateSource: templateSource, ServiceAccount: spec.ServiceAccount,
		Inputs: inputs, RequireExisting: true,
	}
	if err := withSpinner("Updating the deployment…", func() error { return runGcpDeploy(deploy) }); err != nil {
		return gcpUpdateFailed(err, st.DeploymentName)
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector updated (deployment %s).", st.DeploymentName)))
	awaitGcpRollout(st)
	if !sameTarget || target.AuthMethod != comp.Auth.Method {
		printGcpGrantGuidance(target, st.DeploymentName, st.Project)
	}
	fmt.Println("\nConfirm it connected with: dbg collector status")
	return nil
}

// runUpgradeGCP rolls the deployment to a new collector image, holding
// everything else — the deployment's own template and inputs.
func runUpgradeGCP(cmd *cobra.Command, st *collector.State, image string) error {
	// Over HTTP, as on aws: no container runtime to pull with, and an
	// unresolved tag leaves the deployment with an unchanged input and
	// therefore nothing to roll.
	pinned, err := pinImageRemote(image)
	if err != nil {
		return fmt.Errorf("cannot resolve %s to a fixed version: %w", image, err)
	}
	if done, err := checkUpgradeDirection(cmd, st.Image, pinned); done || err != nil {
		return err
	}
	fmt.Printf("Upgrading to %s...\n", pinned)
	if err := withSpinner("Updating the deployment…", func() error {
		return upgradeGcpImage(st.Project, st.Region, st.DeploymentName, pinned)
	}); err != nil {
		return gcpUpdateFailed(err, st.DeploymentName)
	}
	st.Image = pinned
	if err := collector.SaveState(st); err != nil {
		fmt.Println(style.Warn(fmt.Sprintf("⚠  upgraded, but could not update stored state: %v", err)))
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Upgrade applied (deployment %s).", st.DeploymentName)))
	awaitGcpRollout(st)
	return nil
}

// gcpStoredComponent reads the deployment's collector config back — strictly,
// so a key this CLI cannot model is refused rather than silently dropped from
// a running collector — and returns the one Google-hosted database it
// monitors. A deployment monitoring something else (the instaclustr source)
// is not this path's to modify.
func gcpStoredComponent(spec *collector.GcpDeploymentSpec, deploymentName string) (collector.Config, collector.Component, error) {
	decoded, err := collector.DecodeConfig(spec.Inputs["collector_config"])
	if err != nil {
		return collector.Config{}, collector.Component{},
			fmt.Errorf("could not read the collector config stored on deployment %q: %w", deploymentName, err)
	}
	conf, err := collector.StrictParseConfig(decoded)
	if err != nil {
		return collector.Config{}, collector.Component{},
			fmt.Errorf("could not read the collector config stored on deployment %q: %w", deploymentName, err)
	}
	if len(conf.Component) != 1 {
		return collector.Config{}, collector.Component{},
			fmt.Errorf("deployment %q monitors %d databases; this update path handles exactly one — "+
				"run `dbg collector uninstall` and re-install", deploymentName, len(conf.Component))
	}
	comp := conf.Component[0]
	if comp.Provider.Type != "cloud_sql" && comp.Provider.Type != "alloydb" {
		return collector.Config{}, collector.Component{},
			fmt.Errorf("deployment %q monitors a %s source, which this update path cannot modify. "+
				"Run `dbg collector uninstall` and re-run the matching `dbg collector install --provider %s --target gcp` instead",
				deploymentName, comp.Provider.Type, comp.Provider.Type)
	}
	return conf, comp, nil
}

// gcpStoredTargetID is the --db-instance-id and --provider-type that name
// what the deployment monitors now.
func gcpStoredTargetID(comp collector.Component) (id, providerType string) {
	if comp.Provider.Type == "alloydb" {
		return comp.Provider.Cluster + "/" + comp.Provider.Instance, "alloydb"
	}
	return comp.Provider.Instance, "cloud_sql"
}

// gcpStoredEndpoints are the deployment's own control-plane endpoints, with
// any explicit --*-url flag overriding — the same precedence an install has.
func gcpStoredEndpoints(conf collector.Config, cmd *cobra.Command) collector.Endpoints {
	e := collector.Endpoints{
		AuthBaseURL:  conf.Dbgorilla.AuthBaseURL,
		OtlpBaseURL:  conf.Dbgorilla.OtlpBaseURL,
		OpampBaseURL: conf.Dbgorilla.OpampBaseURL,
	}
	if v := authURLFlag(cmd); v != "" {
		e.AuthBaseURL = v
	}
	if v, _ := cmd.Flags().GetString("otlp-url"); v != "" {
		e.OtlpBaseURL = withDefaultPort(v)
	}
	if v, _ := cmd.Flags().GetString("opamp-url"); v != "" {
		e.OpampBaseURL = v
	}
	return e
}

// gcpUpdateTemplateSource decides which template an update applies. The
// deployment's own, normally; this CLI's newer published version when the
// deployment is behind (the inputs are re-rendered in full, so the newer
// contract is met); never an older one — a deployment ahead of this dbg would
// lose whatever the newer template added, so that refuses. A custom source
// (not the published layout) is kept as it is. --template-source overrides
// the result.
func gcpUpdateTemplateSource(deployed string) (string, error) {
	v := collector.GcpTemplateSourceVersion(deployed)
	cmp, ok := collector.CompareGcpTemplateVersions(v, collector.GcpTemplateVersion)
	switch {
	case !ok:
		return deployed, nil
	case cmp > 0:
		return "", fmt.Errorf("the deployment runs template %s, newer than the %s this dbg deploys — "+
			"update dbg first: dbg upgrade", v, collector.GcpTemplateVersion)
	case cmp < 0:
		fmt.Println(style.Warn(fmt.Sprintf("⚠  Moving the deployment from template %s to %s", v, collector.GcpTemplateVersion)))
		return collector.HostedGcpTemplateSource(), nil
	}
	return deployed, nil
}

// gcpUpdateFailed reports a failed in-place update or upgrade. Nothing is
// rolled back on any path: the deployment's previous revision is
// Infrastructure Manager's to keep, and the identity and local record stay
// valid.
func gcpUpdateFailed(err error, deploymentName string) error {
	switch {
	case errors.Is(err, collector.ErrDeployBusy):
		return fmt.Errorf("%w\n\nWait for it to finish, then re-run", err)
	case errors.Is(err, collector.ErrDeployTimeout):
		fmt.Println(style.Warn(fmt.Sprintf("⚠  Still applying after %s — deployment %s is most likely still converging.",
			collector.GcpDeployTimeout(), deploymentName)))
		fmt.Println("   Watch it with: dbg collector status")
		return nil
	case errors.Is(err, errInterrupted), errors.Is(err, collector.ErrDeployUnknown):
		return fmt.Errorf("%w\n\nNothing was rolled back. Run `dbg collector status` to see whether deployment %s converged; "+
			"if it failed, fix the issue and re-run", err, deploymentName)
	}
	return fmt.Errorf("%w\n\nNothing was rolled back: the collector may be running its previous configuration, or a partial one. "+
		"Fix the issue above and re-run; `dbg collector status` shows deployment %s's state", err, deploymentName)
}

// awaitGcpRollout waits for the instance group to settle on the new template.
// A slow rollout is reported, not fatal: the group converges on its own.
func awaitGcpRollout(st *collector.State) {
	err := withSpinner("Rolling the collector instance…", func() error {
		return waitGcpMigStable(st.Project, st.Region, st.DeploymentName)
	})
	if err != nil {
		fmt.Println(style.Warn(fmt.Sprintf("⚠  %v — check `dbg collector status`", err)))
		return
	}
	fmt.Println(style.Success("✓ Collector instance rolled to the new configuration"))
}
