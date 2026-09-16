package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/dbgorilla/dbgorilla-cli/internal/api"
	"github.com/dbgorilla/dbgorilla-cli/internal/collector"
	"github.com/dbgorilla/dbgorilla-cli/internal/preflight"
	"github.com/dbgorilla/dbgorilla-cli/internal/style"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Install-path seams. These indirect the three operations in runInstall that
// touch the Docker engine or a live database, so the install workflow can be
// exercised end-to-end in tests with fakes. Production defaults call the real
// implementations.
var (
	// dockerAvailable reports whether a usable Docker engine is reachable.
	dockerAvailable = collector.DockerAvailable
	// runPreflight runs the read-only database preflight against a DSN.
	runPreflight = preflight.Run
	// probeTLS asks the server whether it speaks TLS (seam for tests).
	probeTLS = preflight.ProbeTLS
	// runContainer starts the collector container (`docker run`). Method
	// expression (not a wrapping closure) so the default carries no uncovered
	// statement of its own -- collector.Runner.Run is func(collector.Runner) error.
	runContainer = collector.Runner.Run
	// checkWorkload probes the workload (pg_stat_statements) capability for
	// `dbg collector status`; stubbed in tests to avoid a live DB.
	checkWorkload = preflight.CheckWorkload
)

// AWS-path seams. Same purpose as the block above, for the operations that
// reach a live AWS account: without them the whole `--target aws` workflow is
// only exercisable against a real account with a real RDS instance, which in
// practice means it is exercised for the first time during a customer install.
var (
	awsAvailable      = collector.AwsAvailable
	awsIdentity       = collector.AwsIdentity
	awsAccountID      = collector.AwsAccountID
	awsRegion         = collector.AwsRegion
	discoverAwsTarget = collector.DiscoverAwsTarget
	stackStatus       = collector.StackStatus
	updateComponents  = collector.UpdateComponents
	deleteStack       = collector.DeleteStack
	upgradeImage      = collector.UpgradeImage
	checkNetworkPath  = collector.VerifyNetworkPath
	runGrant          = collector.RunGrant
	reachable         = collector.Reachable
	// runFargateDeploy / runFargateDeployQuiet are method expressions (not
	// wrapping closures) so the production defaults carry no uncovered
	// statement of their own.
	runFargateDeploy      = collector.FargateDeploy.Run
	runFargateDeployQuiet = collector.FargateDeploy.RunQuiet
	// containerHealth / containerRecentLogs read the local container's state after
	// start, so the crash-loop diagnosis is reachable without a Docker engine.
	containerHealth     = collector.Runner.Health
	containerRecentLogs = collector.Runner.RecentLogs
	// pinImage resolves an image tag to its digest before a container is
	// replaced, so an upgrade records what actually runs.
	pinImage = collector.PinnedRef
	// pinImageRemote resolves a tag to a digest over the registry's HTTP API,
	// for the AWS path where there is no container runtime to ask.
	pinImageRemote = collector.RemoteDigest
)

func init() {
	installCmd.Flags().String("name", "", "Display name for this database target (prompted if omitted)")
	installCmd.Flags().String("db-host", "localhost", "Database host")
	installCmd.Flags().Int("db-port", 5432, "Database port")
	installCmd.Flags().String("db-name", "", "Comma-separated database names (empty = all databases on the server)")
	installCmd.Flags().String("db-user", "", "Read-only database user (prompted if omitted)")
	installCmd.Flags().String("db-password", "", "Database password (prompted without echo if omitted; or set "+collector.DBPasswordEnv+")")
	installCmd.Flags().String("ssl-mode", "verify-full", "libpq ssl_mode: disable, require, verify-ca, verify-full (defaults to disable for --target docker, whose database is local and non-TLS by definition)")
	installCmd.Flags().String("image", collector.DefaultImage, "Collector container image")
	installCmd.Flags().Bool("yes", false, "Skip confirmation prompts")
	installCmd.Flags().Bool("dry-run", false, "Render config and print the docker command without minting, writing, or starting anything")
	installCmd.Flags().String("auth-url", "", "Override the auth host base URL (default: collector's deployment default)")
	installCmd.Flags().String("keycloak-url", "", "Deprecated: use --auth-url")
	_ = installCmd.Flags().MarkDeprecated("keycloak-url", "use --auth-url instead")
	installCmd.Flags().String("otlp-url", "", "Override the OTLP gateway base URL")
	installCmd.Flags().String("opamp-url", "", "Override the OpAMP websocket base URL")
	installCmd.Flags().String("ca-cert", "", "Path to a PEM CA bundle to trust (for private/internal-CA deployments)")
	installCmd.Flags().Bool("force", false, "Provision even if the database preflight reports failures")

	// --target selects where the collector runs; the cloud targets use the
	// flags below (auto-discovered from the database when omitted).
	installCmd.Flags().String("target", "docker", "Deploy target: 'docker' (local), 'aws' (Fargate), or 'gcp' (Compute Engine)")
	installCmd.Flags().String("db-instance-id", "", "AWS/GCP: RDS instance or Aurora cluster id; Cloud SQL instance or AlloyDB cluster[/instance] (auto-selected if exactly one)")
	installCmd.Flags().String("provider-type", "", "AWS/GCP: force aws_rds, aws_aurora, cloud_sql or alloydb (auto-detected if omitted)")
	installCmd.Flags().String("dbi-resource-id", "", "AWS: RDS DbiResourceId (discovered; scopes rds-db:connect)")
	installCmd.Flags().String("subnets", "", "AWS: comma-separated subnet IDs (discovered from the RDS instance)")
	installCmd.Flags().String("security-group-id", "", "AWS: security group for the collector task (discovered)")
	installCmd.Flags().String("assign-public-ip", "ENABLED", "AWS: ENABLED (default; public-subnet VPCs like the default VPC) or DISABLED (private subnets with a NAT gateway)")
	installCmd.Flags().String("stack-name", collector.DefaultStackName, "AWS: CloudFormation stack name")
	installCmd.Flags().String("template-url", "", "AWS: deploy this CloudFormation template instead of the published one (must be an S3 URL)")
	installCmd.Flags().String("config", "", "AWS: TOML file with [[database]] entries to monitor several databases from one collector (supersedes the single --db-* flags)")
	installCmd.Flags().Bool("enable-commands", true, "AWS/GCP: set false to forbid the collector issuing any query-analysis queries (a hard off; otherwise the per-database checklist / --commands decides)")
	installCmd.Flags().String("commands", "", "AWS/GCP: comma-separated query-analysis commands to allow per database (execute_query, explain). Empty + interactive prompts a per-database checklist; empty + non-interactive allows all; --commands=\"\" turns analysis off")
	installCmd.Flags().Bool("run-grant", false, "AWS: run the IAM grant automatically against each database, needing an admin DB login reachable from here (prompted when interactive; otherwise the SQL is printed)")
	installCmd.Flags().String("grant-user", "postgres", "AWS: admin database user for --run-grant")
	installCmd.Flags().String("grant-password", "", "AWS: admin database password for --run-grant (prompted without echo if omitted)")

	uninstallCmd.Flags().Bool("yes", false, "Skip the confirmation prompt")

	logsCmd.Flags().BoolP("follow", "f", false, "Follow log output")
	logsCmd.Flags().String("tail", "100", "Number of trailing log lines to show")

	collectorUpgradeCmd.Flags().String("image", collector.DefaultImage, "Collector image to upgrade to (default: this CLI's current version)")
	collectorUpgradeCmd.Flags().Bool("allow-downgrade", false, "Install an older collector version than the one currently running")

	collectorCmd.AddCommand(installCmd, statusCmd, listCmd, logsCmd, startCmd, stopCmd, restartCmd, collectorUpgradeCmd, uninstallCmd, encodeConfigCmd)
	rootCmd.AddCommand(collectorCmd)
}

var collectorCmd = &cobra.Command{
	Use:   "collector",
	Short: "Install and manage a local DBGorilla collector",
	Long: `Run the DBGorilla collector locally (in Docker) to connect a database in
your dev environment to DBGorilla.

  dbg collector install     Provision, configure, and start a collector
  dbg collector status      Show the collector's state and connection
  dbg collector logs        Tail the collector's logs
  dbg collector stop/start  Pause or resume without losing the identity
  dbg collector uninstall   Stop the collector and deprovision its identity

For NetApp Instaclustr sources (--provider instaclustr):
  dbg collector refresh-firewall  Re-allowlist this machine's current IP`,
}

// --- install --------------------------------------------------------------

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Provision, configure, and start a local collector",
	RunE:  runInstall,
}

func runInstall(cmd *cobra.Command, _ []string) error {
	// A managed-platform *source* (--provider) is orthogonal to the deploy
	// substrate (--target) and takes its own path before the target dispatch.
	// An unknown value must not silently fall through to the docker prompts.
	switch provider, _ := cmd.Flags().GetString("provider"); {
	case provider == "":
	case instaclustrSource(cmd):
		return runInstallInstaclustr(cmd)
	default:
		return fmt.Errorf("unknown --provider %q (expected 'instaclustr'; for RDS vs Aurora use --provider-type with --target aws)", provider)
	}
	switch target, _ := cmd.Flags().GetString("target"); target {
	case "", "docker", "local":
		return runInstallLocal(cmd)
	case "aws", "fargate":
		return runInstallAWS(cmd)
	case "gcp":
		return runInstallGCP(cmd)
	default:
		return fmt.Errorf("unknown --target %q (expected 'docker', 'aws', or 'gcp')", target)
	}
}

func runInstallLocal(cmd *cobra.Command) error {
	if dry, _ := cmd.Flags().GetBool("dry-run"); dry {
		return dryRunInstall(cmd)
	}

	apiURL, err := requireInstallSession(cmd)
	if err != nil {
		return err
	}
	if err := requireNoInstall(); err != nil {
		return err
	}

	// Environment preflight: Docker must be usable before we mint anything.
	if err := dockerAvailable(); err != nil {
		return err
	}

	client, err := requireCollectorSupport(cmd, apiURL)
	if err != nil {
		return err
	}

	// Gather the database target.
	target, err := resolveTarget(cmd)
	if err != nil {
		return err
	}
	password, err := resolveDBPassword(cmd)
	if err != nil {
		return err
	}

	// Reachability preflight from the host (the CLI runs on the host, so the
	// original loopback host is correct here, not the container rewrite).
	if err := checkReachable(target.HostDial()); err != nil {
		fmt.Println(style.Warn(fmt.Sprintf("⚠  %s", err)))
		if !confirm(cmd, "Continue anyway?") {
			return errors.New("aborted")
		}
	} else {
		fmt.Println(style.Success(fmt.Sprintf("✓ Database reachable at %s", target.HostDial())))
	}

	// Settle the TLS mode against what the server actually supports, before the
	// preflight connects with it. Nothing is provisioned yet, so a refusal here
	// costs the user nothing.
	if err := resolveTLSMode(cmd, &target, password); err != nil {
		return err
	}

	// Deep DB preflight (read-only) before we provision anything, so a
	// misconfigured database never gets a live collector identity.
	report := runPreflight(cmd.Context(), buildDSN(target, password))
	printPreflight(report)
	if report.Failed() {
		if force, _ := cmd.Flags().GetBool("force"); !force {
			return errors.New("database preflight failed; fix the items above, or rerun with --force")
		}
		fmt.Println(style.Warn("Continuing despite preflight failures (--force)."))
	}

	// Resolve + validate the optional CA cert before minting (fail fast).
	caCert, err := resolveCACert(cmd)
	if err != nil {
		return err
	}

	// Mint the collector identity. The user token authorizes the mint.
	fmt.Println(style.Info("Provisioning collector identity..."))
	creds, err := client.ProvisionCollector()
	if err != nil {
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector provisioned (agent %s, tenant %s)", creds.AgentID, creds.TenantID)))

	// Render config + materialize secrets. Endpoints come from the mint
	// response (non-prod deployments), with explicit --*-url flags overriding.
	cfg := collector.Build(creds.AgentID, creds.TenantID, target, endpointsFor(creds, cmd))
	rendered, err := cfg.Render()
	if err != nil {
		return err
	}
	if collector.IsLoopback(target.Host) {
		fmt.Println(style.Success(fmt.Sprintf("✓ Rewrote %s -> %s for in-container access", target.Host, collector.DockerHostInternal)))
	}
	return finishDockerInstall(cmd, client, creds, rendered, password, caCert,
		func(envPath string) error { return collector.WriteEnvFile(envPath, creds.Secret, password) },
		&collector.State{TargetName: target.Name}, func() {},
		"  dbg collector status     # check connection\n"+
			"  dbg collector logs -f    # watch it work")
}

// finishDockerInstall is the shared tail of every docker-target install:
// materialize config + secrets, resolve and digest-pin the image, start the
// container (rolling back the identity — plus whatever the caller adds via
// onFail — when it will not start), persist state, and confirm liveness.
// state arrives carrying only the caller's substrate-specific fields; the
// common ones are filled in here. nextSteps is the epilogue body.
func finishDockerInstall(cmd *cobra.Command, client *api.Client, creds *api.CollectorCredentials,
	rendered, dbPassword, caCert string, writeEnv func(envPath string) error,
	state *collector.State, onFail func(), nextSteps string) error {

	configPath, _ := collector.ConfigPath()
	envPath, _ := collector.EnvPath()
	if err := collector.StoreSecrets(creds.AgentID, creds.Secret, dbPassword); err != nil {
		onFail()
		return err
	}
	if err := collector.WriteConfig(configPath, rendered); err != nil {
		onFail()
		return err
	}
	if err := writeEnv(envPath); err != nil {
		onFail()
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Wrote config: %s", configPath)))

	// Resolve the collector image: explicit --image wins; else the version the
	// deployment blesses (preferred_collector_version); else the CLI default.
	image, imageSource := resolveImage(cmd, creds)
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector image: %s (%s)", image, imageSource)))

	// Pin to an immutable digest before running, so a deployment-blessed version
	// (a bare tag) is as reproducible and tamper-evident as the hard-pinned
	// default. Already-pinned refs pass through untouched.
	pinned, err := pinImage(image)
	if err != nil {
		onFail()
		return fmt.Errorf("resolving collector image digest: %w", err)
	}
	if pinned != image {
		fmt.Println(style.Success(fmt.Sprintf("✓ Pinned to digest: %s", pinned)))
	}
	image = pinned

	// Run the container.
	runner := collector.Runner{
		Name:        collector.DefaultContainerName,
		Image:       image,
		ConfigPath:  configPath,
		EnvFilePath: envPath,
		CACertPath:  caCert,
	}
	fmt.Println(style.Info(fmt.Sprintf("Starting collector container (%s)...", image)))
	if err := runContainer(runner); err != nil {
		// Roll back the just-minted identity so a failed start never orphans it.
		fmt.Println(style.Warn("Container failed to start; rolling back the provisioned identity..."))
		if derr := client.DeleteCollector(creds.AgentID); derr != nil {
			fmt.Println(style.Warn(fmt.Sprintf("⚠  could not auto-deprovision %s: %v (remove it from the console)", creds.AgentID, derr)))
		}
		collector.ClearSecrets(creds.AgentID)
		_ = os.Remove(configPath)
		_ = os.Remove(envPath)
		onFail()
		return fmt.Errorf("%w\n\nRolled back. Fix Docker and re-run `dbg collector install`", err)
	}

	// Persist state.
	state.AgentID = creds.AgentID
	state.TenantID = creds.TenantID
	state.Domain = creds.Domain
	state.ContainerName = runner.Name
	state.Image = image
	state.ConfigPath = configPath
	state.EnvFilePath = envPath
	state.CACertPath = caCert
	state.CreatedAt = time.Now().UTC()
	if err := collector.SaveState(state); err != nil {
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Container started: %s", runner.Name)))

	// A container that starts and immediately dies still "starts" as far as
	// `docker run` is concerned. Confirm it is actually up before reporting a
	// connection problem, or we blame the network for a crash on boot.
	if crashLooping(runner) {
		return errCollectorCrashLooping
	}

	// Verify connection (best-effort; not fatal).
	verifyConnection(client, creds.AgentID, caCert)

	fmt.Println()
	fmt.Println("Collector installed. Next:")
	fmt.Println(nextSteps)
	return nil
}

// dryRunInstall renders the config and prints the docker command the real
// install would run, without contacting the backend, writing files, storing
// secrets, or starting a container. Identity fields are placeholders.
// --- install --target aws --------------------------------------------------

// runInstallAWS deploys the collector to AWS Fargate via CloudFormation. It
// shares the local target's auth + provisioning, but resolves an RDS target
// (IAM auth, no password) and deploys a stack instead of running Docker.
func runInstallAWS(cmd *cobra.Command) error {
	apiURL, err := requireInstallSession(cmd)
	if err != nil {
		return err
	}

	// An existing AWS collector isn't a conflict — it's an update: re-run with a
	// different --config / --db-instance-id to change which databases it monitors,
	// in place (no re-mint, no teardown). A local Docker collector still blocks
	// (can't reconcile it here). Dry-run always takes the fresh path below.
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	prior, _, err := priorCloudInstall(dryRun, (*collector.State).IsAWS,
		func(st *collector.State) (string, error) { return stackStatus(st.StackName, st.Region) },
		"stack", func(st *collector.State) string { return st.StackName })
	if err != nil {
		return err
	}
	if prior != nil {
		return runUpdateAWS(cmd, prior)
	}

	if err := printCloudIdentity("AWS", awsAvailable, awsIdentity); err != nil {
		return err
	}
	client, err := requireCollectorSupport(cmd, apiURL)
	if err != nil {
		return err
	}

	targets, err := resolveAwsTargets(cmd)
	if err != nil {
		return err
	}
	// Settle each database's auth: --db-password forces password auth; otherwise
	// IAM when it's enabled; otherwise (interactive) offer a password fallback.
	dbPassword := dbPasswordFlag(cmd)
	if err := resolveAwsAuth(cmd, targets, &dbPassword, dryRun); err != nil {
		return err
	}

	// One Fargate task serves every component, so it has one VPC network config:
	// explicit --subnets/--security-group-id, else the first database's.
	subnets, sg := taskNetworking(cmd, targets)
	if len(subnets) == 0 || sg == "" {
		return errors.New("could not determine task networking (no subnets/security group discovered); pass --subnets and --security-group-id")
	}

	// Network-path preflight: statically verify (via VPC security-group rules)
	// that the collector's task networking can reach each database, so an
	// unreachable DB is caught here rather than after a deployed collector
	// silently fails to connect. Advisory — a gap warns (and asks, interactively)
	// but --force / non-interactive proceeds.
	if err := verifyNetworkPath(cmd, sg, subnets, targets); err != nil {
		return err
	}

	stackName, _ := cmd.Flags().GetString("stack-name")
	assignIP, _ := cmd.Flags().GetString("assign-public-ip")
	commandsEnabled := resolveCommands(cmd, targets, awsTargetLabel)
	region := awsRegion()
	accountID, err := awsAccountID()
	if err != nil {
		return err
	}
	templateURL, _ := cmd.Flags().GetString("template-url")
	if err := requireNoRuntime(dryRun,
		func() (string, error) { return stackStatus(stackName, region) },
		"stack", stackName, "--stack-name"); err != nil {
		return err
	}

	// Dry run: validate the template without minting an identity or creating
	// anything. Placeholder identity keeps the template shape valid.
	if dryRun {
		image, _ := resolveImage(cmd, nil)
		params, secrets, err := collector.AwsStackParams(collector.AwsStackInput{
			AgentID: "DRY-RUN", TenantID: "DRY-RUN",
			Image:           image,
			Region:          region,
			AccountID:       accountID,
			Targets:         targets,
			Subnets:         subnets,
			SecurityGroup:   sg,
			AssignPublicIP:  assignIP,
			CommandsEnabled: commandsEnabled,
			DBPassword:      dbPassword,
		})
		if err != nil {
			return err
		}
		fmt.Printf("\nDry run — validating the template for stack %q (%d database(s), no identity minted):\n", stackName, len(targets))
		printAwsParams(params, secrets)
		return runFargateDeploy(collector.FargateDeploy{
			StackName: stackName, Params: params, Secrets: secrets, DryRun: true, TemplateURL: templateURL,
		})
	}

	fmt.Println("Provisioning collector identity...")
	creds, err := client.ProvisionCollector()
	if err != nil {
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector provisioned (agent %s, tenant %s)", creds.AgentID, creds.TenantID)))

	image, imageSource := resolveImage(cmd, creds)
	image = pinImageOrWarn(image, "task")
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector image: %s (%s)", image, imageSource)))

	params, secrets, err := collector.AwsStackParams(collector.AwsStackInput{
		AgentID:         creds.AgentID,
		TenantID:        creds.TenantID,
		Image:           image,
		Endpoints:       endpointsFor(creds, cmd),
		Region:          region,
		AccountID:       accountID,
		Targets:         targets,
		Subnets:         subnets,
		SecurityGroup:   sg,
		AssignPublicIP:  assignIP,
		CommandsEnabled: commandsEnabled,
		ServerSecret:    creds.Secret,
		DBPassword:      dbPassword,
	})
	if err != nil {
		deprovisionOrWarn(client, creds.AgentID)
		return err
	}

	saveStateOrWarn(&collector.State{
		AgentID:    creds.AgentID,
		TenantID:   creds.TenantID,
		Domain:     creds.Domain,
		Target:     "aws",
		Image:      image,
		TargetName: targetsSummary(targets),
		StackName:  stackName,
		Region:     region,
		CreatedAt:  time.Now().UTC(),
	})

	fmt.Printf("Deploying to Fargate (stack %q, %d database(s))...\n", stackName, len(targets))
	deploy := collector.FargateDeploy{StackName: stackName, Params: params, Secrets: secrets, TemplateURL: templateURL}
	if err := deployStack(deploy, "Deploying to Fargate…"); err != nil {
		kept, derr := cloudDeployFailed(err, client, creds.AgentID, collector.DeployTimeout(), "stack", stackName,
			func() error { return deleteStack(stackName, region) }, nil,
			"   Watch it with: dbg collector status\n"+
				"   If it ends up failed, remove it with: dbg collector uninstall\n")
		if kept {
			applyGrants(cmd, targets)
		}
		return derr
	}

	fmt.Println(style.Success(fmt.Sprintf("✓ Collector deploying to Fargate (stack %s).", stackName)))

	applyGrants(cmd, targets)
	return nil
}

// runUpdateAWS updates an already-deployed AWS collector in place to monitor the
// databases now declared by --config / --db-instance-id, reusing its identity,
// secret, and networking — so "add or change a database" is one command with no
// teardown. targets is the full desired set (declarative), not a delta.
func runUpdateAWS(cmd *cobra.Command, st *collector.State) error {
	if err := awsAvailable(); err != nil {
		return err
	}
	targets, err := resolveAwsTargets(cmd)
	if err != nil {
		return err
	}
	// Settle auth exactly as the install path does. An update that adds a
	// password-auth database, or that rotates an existing password, has to reach
	// the stack's DbPassword parameter — reusing the previous value would leave
	// ${DBG_DB_PASSWORD} unresolved in the collector's config.
	dbPassword := dbPasswordFlag(cmd)
	if err := resolveAwsAuth(cmd, targets, &dbPassword, false); err != nil {
		return err
	}
	// Re-apply per-component query-analysis commands (the component env is
	// rebuilt on update). The global on/off gate is preserved by UpdateComponents
	// via UsePreviousValue, so it stays whatever the install set.
	resolveCommands(cmd, targets, awsTargetLabel)
	fmt.Printf("Updating collector %s in place to monitor %d database(s)...\n", st.AgentID, len(targets))
	if err := withSpinner("Updating collector…", func() error {
		return updateComponents(st.StackName, st.Region, targets, dbPassword)
	}); err != nil {
		return err
	}
	st.TargetName = targetsSummary(targets)
	if err := collector.SaveState(st); err != nil {
		fmt.Println(style.Warn(fmt.Sprintf("⚠  updated the stack, but could not update local state: %v", err)))
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector updated (stack %s) — ECS is rolling the task.", st.StackName)))
	applyGrants(cmd, targets)
	return nil
}

// applyGrants either runs the collector's DB grant automatically (--run-grant,
// using an admin login reachable from here) or prints the SQL for the operator
// to run. When a run fails (e.g. a private database unreachable from this host),
// it degrades to printing that database's SQL — so the customer is never stuck.
//
// Which databases need a grant, and whether they are reachable, is decided by
// collector.PlanGrants; this is the prompt-and-print half.
func applyGrants(cmd *cobra.Command, targets []collector.AwsTarget) {
	run, _ := cmd.Flags().GetBool("run-grant")
	// Offer to run it when the flag wasn't set and we have a terminal — but only
	// if the database is actually reachable from here. A private DB usually isn't
	// reachable from where the CLI runs, and offering a run that can only fail is
	// worse than just printing the SQL. An explicit --run-grant still attempts it
	// (the user may be on a bastion and know better), so skip the probe then.
	offer := !run && !cmd.Flags().Changed("run-grant") && interactiveSelectable(cmd)
	var probe func(string) error
	if offer {
		probe = reachable
	}
	plan := collector.PlanGrants(targets, probe)
	if len(plan.Targets) == 0 {
		return
	}
	if offer {
		if len(plan.Unreachable) > 0 {
			fmt.Printf("(%s isn't reachable from here — printing the grant SQL to run where it is.)\n",
				strings.Join(plan.Unreachable, ", "))
		} else {
			run = promptYesNo("Run the collector's DB grant now? (needs a DB admin login)", false)
		}
	}
	if !run {
		fmt.Println("\nFinal step — grant the collector's IAM user access inside each database:")
		for _, t := range plan.Targets {
			printGrantFor(t)
		}
		return
	}

	adminUser, _ := cmd.Flags().GetString("grant-user")
	adminPass, _ := cmd.Flags().GetString("grant-password")
	if adminPass == "" {
		adminPass = promptGrantPassword(adminUser)
	}
	fmt.Println("\nGranting the collector's IAM user access inside each database...")
	for _, t := range plan.Targets {
		dsn := collector.AdminDSN(adminUser, adminPass, t)
		if err := runGrant(cmd.Context(), dsn, collector.GrantStatements(t.User, t.Databases)); err != nil {
			fmt.Println(style.Warn(fmt.Sprintf("⚠  couldn't reach/grant %s from here (%v).\n"+
				"   A private database often isn't reachable from where you run the CLI — run this SQL where it is:", t.InstanceID, err)))
			printGrantFor(t)
			continue
		}
		fmt.Println(style.Success(fmt.Sprintf("✓ Granted %s access on %s", t.User, t.InstanceID)))
	}
}

// deployStack runs a Fargate deploy under a spinner when interactive (output
// captured, shown only on failure); non-interactive streams CloudFormation
// progress so CI logs stay useful.
func deployStack(deploy collector.FargateDeploy, title string) error {
	if !interactiveTerminal() {
		return runFargateDeploy(deploy)
	}
	var out string
	err := withSpinner(title, func() error {
		var e error
		out, e = runFargateDeployQuiet(deploy)
		return e
	})
	if err != nil && out != "" {
		fmt.Println(out)
	}
	return err
}

func printGrantFor(t collector.AwsTarget) {
	fmt.Printf("    -- on %s:\n", t.InstanceID)
	for _, s := range collector.GrantStatements(t.User, t.Databases) {
		fmt.Printf("    %s\n", s)
	}
}

func promptGrantPassword(adminUser string) string {
	return promptPasswordOptional(fmt.Sprintf("Admin DB password for %q (to run the grant)", adminUser))
}

// resolveAwsTargets resolves every database the collector will monitor: the N
// entries of a --config file, or the single database described by the --db-*
// flags. Each is discovery-completed into a full AwsTarget.
func resolveAwsTargets(cmd *cobra.Command) ([]collector.AwsTarget, error) {
	if path, _ := cmd.Flags().GetString("config"); path != "" {
		return resolveAwsTargetsFromConfig(path)
	}
	get := func(name string) string { v, _ := cmd.Flags().GetString(name); return v }

	// No specific database named + a real terminal: discover the candidates and
	// let the user check off one or more — the interactive multi-database path.
	if get("db-instance-id") == "" && interactiveSelectable(cmd) {
		seed := collector.AwsTarget{User: get("db-user"), SSLMode: get("ssl-mode"), ProviderType: get("provider-type")}
		if dbPasswordFlag(cmd) != "" {
			seed.AuthMethod = "password"
		}
		one, err := discoverAwsTarget("", seed.ProviderType, seed)
		var amb *collector.AmbiguousTargetError
		switch {
		case errors.As(err, &amb):
			chosen, perr := pickTargets(amb)
			if perr != nil {
				return nil, perr
			}
			return discoverChoices(chosen, seed)
		case err == nil:
			return []collector.AwsTarget{one}, nil // exactly one — nothing to pick
		}
		// zero candidates or another error: fall through to the single path,
		// which surfaces the actionable message.
	}

	t, err := resolveAwsTarget(cmd)
	if err != nil {
		return nil, err
	}
	return []collector.AwsTarget{t}, nil
}

// pickTargets shows a filterable multi-select of the ambiguous candidates and
// returns the chosen ones — the interactive route to a multi-database collector.
func pickTargets(amb *collector.AmbiguousTargetError) ([]collector.TargetChoice, error) {
	cands := amb.Candidates()
	byID := make(map[string]collector.TargetChoice, len(cands))
	opts := make([]huh.Option[string], 0, len(cands))
	for _, c := range cands {
		byID[c.ID] = c
		opts = append(opts, huh.NewOption(fmt.Sprintf("%s (%s)", c.ID, collector.ProviderLabel(c.ProviderType)), c.ID))
	}
	var picked []string
	ms := huh.NewMultiSelect[string]().
		Title("Select the databases to monitor").
		Description("space toggles · / filters · enter confirms").
		Options(opts...).
		Filterable(true).
		Validate(func(sel []string) error {
			if len(sel) == 0 {
				return errors.New("select at least one database")
			}
			return nil
		}).
		Value(&picked)
	if err := runForm(ms); err != nil {
		return nil, err
	}
	out := make([]collector.TargetChoice, 0, len(picked))
	for _, id := range picked {
		out = append(out, byID[id])
	}
	return out, nil
}

// discoverChoices discovery-completes each picked candidate into a full target.
func discoverChoices(choices []collector.TargetChoice, seed collector.AwsTarget) ([]collector.AwsTarget, error) {
	targets := make([]collector.AwsTarget, 0, len(choices))
	for _, c := range choices {
		t, err := discoverAwsTarget(c.ID, c.ProviderType, seed)
		if err != nil {
			return nil, fmt.Errorf("resolving %q: %w", c.ID, err)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// resolveAwsTargetsFromConfig loads a multi-database file and discovery-completes
// each entry (explicit fields in the file win; the rest is discovered).
func resolveAwsTargetsFromConfig(path string) ([]collector.AwsTarget, error) {
	cfg, err := collector.LoadAwsConfig(path)
	if err != nil {
		return nil, err
	}
	targets := make([]collector.AwsTarget, 0, len(cfg.Databases))
	for _, d := range cfg.Databases {
		seed := d.Seed()
		t := seed
		if !seed.Complete() {
			t, err = discoverAwsTarget(seed.InstanceID, seed.ProviderType, seed)
			if err != nil {
				return nil, fmt.Errorf("resolving database %q: %w", seed.InstanceID, err)
			}
		} else {
			if t.ProviderType == "" {
				t.ProviderType = "aws_rds"
			}
			if t.User == "" {
				t.User = collector.DefaultDBUser
			}
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// taskNetworking picks the single VPC network config the Fargate task runs with:
// explicit --subnets/--security-group-id win; otherwise the first database's
// discovered networking (every monitored database must be reachable from it).
func taskNetworking(cmd *cobra.Command, targets []collector.AwsTarget) (subnets []string, sg string) {
	if v, _ := cmd.Flags().GetString("subnets"); v != "" {
		subnets = splitCSV(v)
	} else if len(targets) > 0 {
		subnets = targets[0].Subnets
	}
	if v, _ := cmd.Flags().GetString("security-group-id"); v != "" {
		sg = v
	} else if len(targets) > 0 {
		sg = targets[0].SecurityGroup
	}
	return subnets, sg
}

// verifyNetworkPath runs the static VPC reachability check and reports it: a
// reachable database prints a ✓, an unreachable or unverifiable one prints a ⚠
// with the exact fix and — when interactive and not --force — asks whether to
// continue. A failure of the check itself (e.g. missing ec2:Describe*
// permissions) never hard-blocks the install; it warns and proceeds.
func verifyNetworkPath(cmd *cobra.Command, sg string, subnets []string, targets []collector.AwsTarget) error {
	findings, err := checkNetworkPath(cmd.Context(), sg, subnets, targets)
	if err != nil {
		fmt.Println(style.Warn(fmt.Sprintf("⚠  could not verify the network path (%v); continuing", err)))
		return nil
	}
	blocked := false
	for _, f := range findings {
		if f.Reachable {
			fmt.Println(style.Success(fmt.Sprintf("✓ Network path: %s reachable on port %d — %s", f.Target, f.Port, f.Detail)))
			continue
		}
		blocked = true
		fmt.Println(style.Warn(fmt.Sprintf("⚠  Network path: %s — %s", f.Target, f.Detail)))
		if f.Remediation != "" {
			fmt.Printf("     fix: %s\n", f.Remediation)
		}
	}
	if force, _ := cmd.Flags().GetBool("force"); blocked && !force {
		if !confirm(cmd, "Some databases may be unreachable from the collector. Continue anyway?") {
			return errors.New("aborted; fix the security-group rule above, or pass --force to deploy anyway")
		}
	}
	return nil
}

// targetsSummary is a short human label for the monitored databases, stored in
// state and shown by `status` (e.g. "prod-pg" or "prod-pg (+2 more)").
func targetsSummary(targets []collector.AwsTarget) string {
	if len(targets) == 0 {
		return ""
	}
	if len(targets) == 1 {
		return targets[0].Name
	}
	return fmt.Sprintf("%s (+%d more)", targets[0].Name, len(targets)-1)
}

// resolveAwsTarget gathers explicit --db-* flags, then auto-discovers the rest
// from the RDS instance. A fully-specified target skips discovery entirely.
func resolveAwsTarget(cmd *cobra.Command) (collector.AwsTarget, error) {
	get := func(name string) string { v, _ := cmd.Flags().GetString(name); return v }
	provider := get("provider-type")
	t := collector.AwsTarget{
		Name:          get("name"),
		InstanceID:    get("db-instance-id"),
		DbiResourceID: get("dbi-resource-id"),
		User:          get("db-user"),
		SSLMode:       get("ssl-mode"),
		ProviderType:  provider,
		Databases:     splitCSV(get("db-name")),
		Subnets:       splitCSV(get("subnets")),
		SecurityGroup: get("security-group-id"),
	}
	// A --db-password opts this database into password auth instead of IAM.
	if dbPasswordFlag(cmd) != "" {
		t.AuthMethod = "password"
	}
	if t.Complete() {
		if t.ProviderType == "" {
			t.ProviderType = "aws_rds"
		}
		if t.User == "" {
			t.User = collector.DefaultDBUser
		}
		return t, nil
	}
	target, err := discoverAwsTarget(t.InstanceID, provider, t)
	// When auto-selection is ambiguous and we have a real terminal, let the
	// user pick instead of failing. Non-interactive (piped/CI/--yes) keeps the
	// old behavior: surface the error and ask for --db-instance-id.
	var amb *collector.AmbiguousTargetError
	if errors.As(err, &amb) && interactiveSelectable(cmd) {
		choice, perr := pickTarget(amb, ", or --config to monitor several")
		if perr != nil {
			return collector.AwsTarget{}, perr
		}
		return discoverAwsTarget(choice.ID, choice.ProviderType, t)
	}
	return target, err
}

// interactiveSelectable reports whether we can prompt the user to choose: stdin
// is a terminal and they didn't pass --yes (which means "no prompts").
func interactiveSelectable(cmd *cobra.Command) bool {
	if yes, _ := cmd.Flags().GetBool("yes"); yes {
		return false
	}
	return stdinIsTerminal()
}

// pickTarget prints the ambiguous candidates and reads the user's choice.
// moreHint names any further way out, appended to the --db-instance-id hint.
func pickTarget(amb *collector.AmbiguousTargetError, moreHint string) (collector.TargetChoice, error) {
	cands := amb.Candidates()
	fmt.Println("Multiple databases found. Select one to monitor:")
	for i, c := range cands {
		fmt.Printf("  [%d] %s (%s)\n", i+1, c.ID, collector.ProviderLabel(c.ProviderType))
	}
	fmt.Printf("  (or re-run with --db-instance-id%s)\n", moreHint)
	choice := prompt("Enter a number", "1")
	n, err := strconv.Atoi(strings.TrimSpace(choice))
	if err != nil || n < 1 || n > len(cands) {
		return collector.TargetChoice{}, fmt.Errorf("invalid selection %q; re-run with --db-instance-id", choice)
	}
	return cands[n-1], nil
}

// resolveAwsAuth prints each target and settles its auth. Password auth is used
// when --db-password was given; when IAM auth isn't enabled on a database and we
// have a terminal (single database, real run), it offers a password fallback
// rather than only warning; otherwise it warns and confirms.
func resolveAwsAuth(cmd *cobra.Command, targets []collector.AwsTarget, dbPassword *string, dryRun bool) error {
	for i := range targets {
		t := &targets[i]
		fmt.Println(style.Success(fmt.Sprintf("✓ Target database: %s (%s)", t.InstanceID, t.Host)))
		if t.AuthMethod == "password" || t.IAMAuthOn {
			continue // password already chosen, or IAM available (the default)
		}
		// IAM DB auth isn't enabled. Offer password auth as the fallback.
		if len(targets) == 1 && !dryRun && *dbPassword == "" && interactiveSelectable(cmd) {
			fmt.Printf("  IAM database authentication isn't enabled on %s.\n", t.InstanceID)
			if pw := promptPasswordOptional("  Enter a read-only DB password to use password auth (blank = keep IAM)"); pw != "" {
				t.AuthMethod = "password"
				*dbPassword = pw
				continue
			}
		}
		fmt.Println(style.Warn(fmt.Sprintf("⚠  IAM database authentication is not enabled on %s — enable it "+
			"(RDS console → Modify → 'IAM DB authentication') or the collector cannot connect.", t.InstanceID)))
		if !confirm(cmd, "Continue anyway?") {
			return errors.New("aborted")
		}
	}
	return nil
}

// commandsForcedOff reports an explicit hard "no query analysis" — for policies
// that forbid the collector issuing any queries: --enable-commands=false, or
// --commands="" (an explicitly empty list). Absent either, analysis is offered
// (the checklist / --commands / the all-commands default decide the specifics).
func commandsForcedOff(cmd *cobra.Command) bool {
	if cmd.Flags().Changed("commands") {
		v, _ := cmd.Flags().GetString("commands")
		return strings.TrimSpace(v) == "" // --commands="" = off
	}
	if cmd.Flags().Changed("enable-commands") {
		v, _ := cmd.Flags().GetBool("enable-commands")
		return !v
	}
	return false
}

// promptCommands shows a per-database checklist of the engine's query-analysis
// commands, all pre-selected. On error/cancel it falls back to allowing all.
// An engine with no catalog has nothing to ask about.
func promptCommands(engine, label string) []string {
	catalog := collector.CommandCatalog(engine)
	if len(catalog) == 0 {
		return nil
	}
	opts := make([]huh.Option[string], 0, len(catalog))
	for _, c := range catalog {
		opts = append(opts, huh.NewOption(commandLabel(c), c).Selected(true))
	}
	picked := append([]string(nil), catalog...) // default: all
	ms := huh.NewMultiSelect[string]().
		Title(fmt.Sprintf("Query-analysis commands for %s", label)).
		Description("space toggles · enter confirms · none = off for this database").
		Options(opts...).
		Value(&picked)
	if err := runForm(ms); err != nil {
		return catalog
	}
	return collector.CommandsFor(engine, picked)
}

// commandLabel is the human-facing description of a command in the picker.
func commandLabel(cmd string) string {
	switch cmd {
	case collector.CmdExecuteQuery:
		return "execute_query — read pg_stat_* / system views"
	case collector.CmdExplain:
		return "explain — EXPLAIN / EXPLAIN ANALYZE query plans"
	default:
		return cmd
	}
}

// promptYesNo asks a themed yes/no with the given default. Callers gate on
// interactiveSelectable, so this only runs with a real terminal.
func promptYesNo(question string, defaultYes bool) bool {
	v := defaultYes
	if err := runForm(huh.NewConfirm().Title(question).Affirmative("Yes").Negative("No").Value(&v)); err != nil {
		return defaultYes
	}
	return v
}

// promptPasswordOptional reads a password without echo; returns "" if left blank.
func promptPasswordOptional(label string) string {
	var v string
	if err := runForm(huh.NewInput().Title(label).EchoMode(huh.EchoModePassword).Value(&v)); err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// awsSecretParams are the stack parameters a dry run must never print.
var awsSecretParams = []string{"ServerSecret", "DbPassword", "InstaclustrApiKey"}

// printAwsParams prints the stack's deploy parameters for a dry run, decoding
// the config so it shows the TOML that would be deployed rather than an opaque
// blob. Secrets never enter the printable params map (AwsStackParams keeps them
// apart by construction); only their presence is shown, derived as a boolean so
// no code path prints a credential.
func printAwsParams(params, secrets map[string]string) {
	printDeployParams(params, nil, "CollectorConfig")
	printSecretPresence(awsSecretParams, secrets)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func dryRunInstall(cmd *cobra.Command) error {
	target, err := resolveTarget(cmd)
	if err != nil {
		return err
	}
	// Preview the TLS mode the real run would settle on, or the dry run would
	// advertise a config the install does not produce. Never prompts here.
	previewTLSMode(cmd, &target)
	cfg := collector.Build("<minted-on-install>", "<minted-on-install>", target, endpointsFromFlags(cmd))
	rendered, err := cfg.Render()
	if err != nil {
		return err
	}
	configPath, _ := collector.ConfigPath()
	envPath, _ := collector.EnvPath()
	image, _ := cmd.Flags().GetString("image")
	caCert, _ := cmd.Flags().GetString("ca-cert")
	if caCert != "" {
		if abs, err := filepath.Abs(caCert); err == nil {
			caCert = abs
		}
	}
	runner := collector.Runner{
		Name:        collector.DefaultContainerName,
		Image:       image,
		ConfigPath:  configPath,
		EnvFilePath: envPath,
		CACertPath:  caCert,
	}

	fmt.Println(style.Info("DRY RUN — nothing was provisioned, written, or started."))
	fmt.Println()
	if collector.IsLoopback(target.Host) {
		fmt.Println(style.Info(fmt.Sprintf("Would rewrite %s -> %s for in-container access.", target.Host, collector.DockerHostInternal)))
	}
	fmt.Println(style.Info(fmt.Sprintf("Would write config:   %s", configPath)))
	fmt.Println(style.Info(fmt.Sprintf("Would write env-file: %s (0600; %s, %s)", envPath, collector.SecretEnv, collector.DBPasswordEnv)))
	fmt.Println()
	fmt.Println(style.Info("--- collector.toml ---"))
	fmt.Print(rendered)
	fmt.Println(style.Info("--- docker command ---"))
	fmt.Println(runner.RunCommandString())
	return nil
}

// --- status ---------------------------------------------------------------

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the local collector's state and connection",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, _ []string) error {
	st, err := collector.LoadState()
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Println(style.Warn("No collector installed. Run: dbg collector install"))
		return nil
	}

	if st.IsAWS() {
		return awsStatus(cmd, st)
	}
	if st.IsGCP() {
		return gcpStatus(cmd, st)
	}
	if st.IsHelm() {
		return helmStatus(cmd, st)
	}

	runner := collector.Runner{Name: st.ContainerName}
	exists, running, _ := runner.Running()

	fmt.Printf("Agent:      %s\n", st.AgentID)
	fmt.Printf("Tenant:     %s\n", st.TenantID)
	fmt.Printf("Target:     %s\n", st.TargetName)
	fmt.Printf("Image:      %s\n", st.Image)
	fmt.Printf("Config:     %s\n", st.ConfigPath)
	switch {
	case !exists:
		fmt.Println(style.Error("Container:  missing (run `dbg collector install` again or `dbg collector start`)"))
	case running:
		fmt.Println(style.Success("Container:  running"))
	default:
		fmt.Println(style.Warn("Container:  stopped (run `dbg collector start`)"))
	}

	// Live control-plane status (best-effort).
	printConnectionStatus(cmd, st.AgentID)

	// Workload capability (best-effort): re-probe pg_stat_statements in the
	// `postgres` maintenance DB the collector uses to gate workload, so the
	// "topology works but the Queries views are empty" case is diagnosable here
	// rather than only at install time (dbgorilla-cli#14).
	printWorkloadStatus(cmd.Context(), st)
	return nil
}

// printConnectionStatus prints the collector's control-plane connection state
// (best-effort; silent when not logged in). Shared by the docker + aws status.
func printConnectionStatus(cmd *cobra.Command, agentID string) {
	if _, err := requireLogin(); err != nil {
		return
	}
	client := newAPIClient(cmd)
	cs, err := client.FetchCollectorStatus(agentID)
	switch {
	case err != nil:
		fmt.Println(style.Warn(fmt.Sprintf("Connection: unknown (%v)", err)))
	case cs == nil:
		fmt.Println(style.Warn("Connection: not yet seen by control plane"))
	default:
		fmt.Println(style.Success(fmt.Sprintf("Connection: %s", orUnknown(cs.Status))))
	}
}

// awsStatus reports an AWS-deployed collector's CloudFormation stack status
// plus its control-plane connection.
func awsStatus(cmd *cobra.Command, st *collector.State) error {
	return cloudStatus(cmd, st, "Stack", st.StackName, func() (string, error) {
		return stackStatus(st.StackName, st.Region)
	})
}

// helmStatus reports an in-cluster (Helm) collector. There is no container to
// inspect and no stack to describe -- the release belongs to the customer's
// cluster, which this CLI has no credentials for and deliberately does not ask
// for. What it can answer is the question that actually matters: has the control
// plane seen this agent.
//
// The runtime lines say plainly where to look instead of guessing, because a
// blank field reads as "broken" and an honest pointer does not.
func helmStatus(cmd *cobra.Command, st *collector.State) error {
	fmt.Printf("Agent:      %s\n", st.AgentID)
	fmt.Printf("Tenant:     %s\n", st.TenantID)
	fmt.Printf("Target:     cnpg — %s\n", st.TargetName)
	fmt.Printf("Config:     %s\n", st.ConfigPath)
	fmt.Printf("Release:    %s (namespace %s)\n", orUnknown(st.ReleaseName), orUnknown(st.ReleaseNamespace))
	fmt.Printf("Runtime:    in-cluster — inspect it with:\n")
	fmt.Printf("              kubectl --context <your-context> -n %s get pods -l app.kubernetes.io/name=dbg-collector\n",
		orUnknown(st.ReleaseNamespace))

	// The live answer. This is the whole reason state is written for a Helm
	// install: without it `dbg collector list` shows the collector while
	// `status` claims none is installed, and a customer reads that as a broken
	// CLI rather than an unsupported install path.
	printConnectionStatus(cmd, st.AgentID)
	return nil
}

// printWorkloadStatus recovers the monitored target from the installed config +
// keychain and prints whether the workload (pg_stat_statements) capability is
// satisfied. Entirely best-effort: any missing piece just omits the line.
func printWorkloadStatus(ctx context.Context, st *collector.State) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := collector.LoadConfig(st.ConfigPath)
	if err != nil || len(cfg.Component) == 0 {
		return
	}
	_, dbPassword, err := collector.LoadSecrets(st.AgentID)
	if err != nil {
		return
	}
	comp := cfg.Component[0]
	target := collector.Target{
		Host:      collector.DialHost(comp.Connect.Host), // host-side view
		Port:      comp.Connect.Port,
		Databases: comp.Connect.Databases,
		User:      comp.Auth.User,
		SSLMode:   comp.Connect.SSLMode,
	}
	// Bound the probe so status never hangs on an unreachable DB.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res := checkWorkload(ctx, buildDSN(target, dbPassword))
	switch res.Severity {
	case preflight.OK:
		fmt.Println(style.Success("Workload:   collecting (pg_stat_statements in the postgres maintenance DB)"))
	case preflight.Warn:
		fmt.Println(style.Warn(fmt.Sprintf("Workload:   unknown (%s)", res.Detail)))
	default:
		fmt.Println(style.Error(fmt.Sprintf("Workload:   NOT collecting -- %s", res.Detail)))
		for _, f := range res.Fix {
			fmt.Printf("            %s\n", f)
		}
	}
}

// --- list -----------------------------------------------------------------

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all collectors registered to your tenant",
	RunE:  runList,
}

func runList(cmd *cobra.Command, _ []string) error {
	if _, err := requireAPIURL(cmd); err != nil {
		return err
	}
	if _, err := requireLogin(); err != nil {
		return err
	}
	client := newAPIClient(cmd)
	items, err := client.ListCollectors()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("No collectors registered to your tenant.")
		return nil
	}

	// Note which agent is the one installed locally, if any.
	localAgent := ""
	if st, _ := collector.LoadState(); st != nil {
		localAgent = st.AgentID
	}

	fmt.Println(style.Info(fmt.Sprintf("%-38s  %-10s  %s", "AGENT ID", "STATUS", "DETAIL")))
	for _, it := range items {
		id := firstString(it, "agent_id", "id", "agentId")
		status := firstString(it, "status", "state", "connection_status")
		detail := firstString(it, "name", "hostname", "instance_id")
		marker := ""
		if id != "" && id == localAgent {
			marker = "  (this machine)"
		}
		fmt.Printf("%-38s  %-10s  %s%s\n", orUnknown(id), orUnknown(status), detail, marker)
	}
	return nil
}

// firstString returns the first non-empty string value among the given keys.
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// --- encode-config --------------------------------------------------------

var encodeConfigCmd = &cobra.Command{
	Use:   "encode-config <config.toml>",
	Short: "Encode a collector config for the CloudFormation CollectorConfig parameter",
	Long: `Encode a collector.toml for the AWS CloudFormation template's CollectorConfig
parameter.

The console renders stack parameters as a single-line field, so the config is
base64-encoded. ` + "`dbg collector install --target aws`" + ` does this for you; run this only when
launching the template by hand:

    dbgorilla collector encode-config config.toml

Secrets belong in the ServerSecret / DbPassword parameters, not in the config.
Reference them from the config as ${DBG_SERVER_SECRET} and ${DBG_DB_PASSWORD}.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("could not read %s: %w", args[0], err)
		}
		// Parse before encoding: a typo caught here beats a Fargate task that
		// crash-loops on a bad config after the stack has already deployed.
		if _, err := collector.ParseConfig(string(raw)); err != nil {
			return fmt.Errorf("%s is not a valid collector config: %w", args[0], err)
		}
		// Comments count against the parameter's 4096-byte budget but mean
		// nothing to the collector, so drop them and re-check the result parses.
		compact := collector.CompactConfig(string(raw))
		if _, err := collector.ParseConfig(compact); err != nil {
			return fmt.Errorf("%s changed meaning when comments were stripped (please report this): %w", args[0], err)
		}
		encoded, err := collector.EncodeConfig(compact)
		if err != nil {
			return err
		}
		fmt.Println(encoded)
		return nil
	},
}

// --- logs / lifecycle -----------------------------------------------------

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show the collector's logs",
	RunE: func(cmd *cobra.Command, _ []string) error {
		st, err := requireRunnableState("logs")
		if err != nil {
			return err
		}
		follow, _ := cmd.Flags().GetBool("follow")
		if st.IsAWS() {
			return collector.TailLogs(collector.LogGroupFor(st.StackName), st.Region, follow)
		}
		if st.IsGCP() {
			return tailGcpLogs(st.Project, st.Region, st.DeploymentName, follow)
		}
		tail, _ := cmd.Flags().GetString("tail")
		return dockerRunner(st).Logs(follow, tail)
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the stopped collector container",
	RunE: func(_ *cobra.Command, _ []string) error {
		st, err := requireRunnableState("start")
		if err != nil {
			return err
		}
		if st.IsAWS() {
			if err := collector.ScaleService(st.StackName, st.Region, 1); err != nil {
				return err
			}
		} else if st.IsGCP() {
			if err := scaleGcpMig(st.Project, st.Region, st.DeploymentName, 1); err != nil {
				return err
			}
		} else if err := dockerRunner(st).Start(); err != nil {
			return err
		}
		fmt.Println(style.Success("✓ Started"))
		return nil
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the collector container (identity is preserved)",
	RunE: func(_ *cobra.Command, _ []string) error {
		st, err := requireRunnableState("stop")
		if err != nil {
			return err
		}
		if st.IsAWS() {
			if err := collector.ScaleService(st.StackName, st.Region, 0); err != nil {
				return err
			}
		} else if st.IsGCP() {
			if err := scaleGcpMig(st.Project, st.Region, st.DeploymentName, 0); err != nil {
				return err
			}
		} else if err := dockerRunner(st).Stop(); err != nil {
			return err
		}
		fmt.Println(style.Success("✓ Stopped"))
		return nil
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the collector container",
	RunE: func(_ *cobra.Command, _ []string) error {
		st, err := requireRunnableState("restart")
		if err != nil {
			return err
		}
		if st.IsAWS() {
			if err := collector.RestartService(st.StackName, st.Region); err != nil {
				return err
			}
		} else if st.IsGCP() {
			if err := restartGcpMig(st.Project, st.Region, st.DeploymentName); err != nil {
				return err
			}
		} else if err := dockerRunner(st).Restart(); err != nil {
			return err
		}
		fmt.Println(style.Success("✓ Restarted"))
		return nil
	},
}

// --- upgrade --------------------------------------------------------------

var collectorUpgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade the collector to the newest (or a specified) version",
	RunE:  runCollectorUpgrade,
}

func runCollectorUpgrade(cmd *cobra.Command, _ []string) error {
	st, err := requireRunnableState("upgrade")
	if err != nil {
		return err
	}
	// --image override, else the version this CLI ships as current. (Resolving a
	// deployment-blessed version without re-provisioning isn't wired yet.)
	image, _ := resolveImage(cmd, nil)

	if st.IsGCP() {
		return errors.New("upgrade is not supported for the gcp target yet; run `dbg collector uninstall` and re-install with --image")
	}

	// Resolve the tag to a digest BEFORE deciding whether to act. The default
	// is a moving tag, and a tag cannot be compared against what is running --
	// so without this, every run would tear down a healthy container to
	// install the image it is already running. Costs a pull on a run that then
	// declines to do anything, which is the cheaper mistake.
	var target string
	if st.IsAWS() {
		// Over HTTP: the AWS path has no container runtime to pull with, and an
		// unresolved tag leaves CloudFormation with an unchanged parameter and
		// therefore nothing to do.
		pinned, err := pinImageRemote(image)
		if err != nil {
			return fmt.Errorf("cannot resolve %s to a fixed version: %w", image, err)
		}
		target = pinned
	} else {
		pinned, err := pinImage(image)
		if err != nil {
			return err
		}
		target = pinned
	}

	// The default image comes from this binary, so "upgrade" from an
	// out-of-date CLI would otherwise roll a newer collector BACKWARDS and
	// print a success message doing it. Compare before touching anything.
	if done, err := checkUpgradeDirection(cmd, st.Image, target); done || err != nil {
		return err
	}
	fmt.Printf("Upgrading to %s...\n", target)

	if st.IsAWS() {
		if err := upgradeImage(st.StackName, st.Region, target); err != nil {
			return err
		}
		fmt.Println(style.Success("✓ Upgrade initiated; ECS is rolling the task. Check `dbg collector status`."))
		st.Image = target
	} else {
		pinned := target
		runner := dockerRunner(st)
		runner.Image = pinned
		_ = runner.Remove()
		if err := runContainer(runner); err != nil {
			return err
		}
		fmt.Println(style.Success(fmt.Sprintf("✓ Upgraded to %s", pinned)))
		st.Image = pinned
	}

	if err := collector.SaveState(st); err != nil {
		fmt.Println(style.Warn(fmt.Sprintf("⚠  upgraded, but could not update stored state: %v", err)))
	}
	return nil
}

// checkUpgradeDirection decides whether an upgrade should go ahead, given what
// the collector is running now and what this run resolved.
//
// done=true means there is nothing to do and the command should exit cleanly;
// a non-nil error means the upgrade was refused. Both leave the running
// collector untouched.
//
// The rule: never move a collector backwards without being told to. An
// unrecognisable pair (a different repository, a digest-only reference, a tag
// like "latest" or a commit sha) is NOT refused — that would block every
// legitimate upgrade to a custom or locally-built image.
func checkUpgradeDirection(cmd *cobra.Command, current, target string) (done bool, err error) {
	cmp, ok := collector.CompareImages(current, target)
	if !ok {
		return false, nil // cannot tell; proceed as before
	}
	if cmp == 0 {
		// Rebuilding the container to install what is already running is pure
		// downtime for no change.
		fmt.Println(style.Success(fmt.Sprintf("✓ Already on %s — nothing to upgrade.", target)))
		return true, nil
	}
	if cmp > 0 {
		return false, nil // a real upgrade
	}
	if allow, _ := cmd.Flags().GetBool("allow-downgrade"); allow {
		fmt.Println(style.Warn(fmt.Sprintf(
			"⚠  Downgrading from %s to %s because --allow-downgrade was passed.", current, target)))
		return false, nil
	}
	return false, fmt.Errorf(
		"refusing to downgrade the collector.\n"+
			"  Running: %s\n"+
			"  This CLI would install: %s\n\n"+
			"  The version to install comes from this CLI when --image is not given, so an\n"+
			"  out-of-date dbg downgrades a newer collector. Update dbg first: dbg upgrade\n"+
			"  To install the older version anyway, pass --allow-downgrade",
		current, target)
}

// --- uninstall ------------------------------------------------------------

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop the collector and deprovision its identity",
	RunE:  runUninstall,
}

func runUninstall(cmd *cobra.Command, _ []string) error {
	st, err := collector.LoadState()
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Println(style.Warn("No collector installed."))
		return nil
	}
	if !confirm(cmd, fmt.Sprintf("Remove collector %s and deprovision its identity?", st.AgentID)) {
		return errors.New("aborted")
	}

	// Remove the runtime (an in-cluster release is the operator's to remove);
	// the identity is deprovisioned below either way.
	if st.IsHelm() {
		fmt.Println(style.Warn("⚠  This collector runs in your cluster and this CLI cannot remove it. Run:"))
		fmt.Printf("     helm uninstall %s --namespace %s\n",
			orUnknown(st.ReleaseName), orUnknown(st.ReleaseNamespace))
		fmt.Println("   Its identity is deprovisioned below either way, so the release will stop being accepted.")
	} else if st.IsAWS() {
		if err := deleteStack(st.StackName, st.Region); err != nil {
			fmt.Println(style.Warn(fmt.Sprintf("⚠  %v", err)))
		} else {
			fmt.Println(style.Success(fmt.Sprintf("✓ Stack %s deletion started", st.StackName)))
		}
	} else if st.IsGCP() {
		// Infrastructure Manager answers only once the resources are destroyed.
		err := withSpinner("Deleting the deployment…", func() error {
			return deleteGcpDeployment(st.Project, st.Region, st.DeploymentName)
		})
		if errors.Is(err, errInterrupted) {
			return fmt.Errorf("%w: the deployment may still be deleting and the identity was NOT deprovisioned. "+
				"Check `dbg collector status`, then run `dbg collector uninstall` again", err)
		}
		if err != nil {
			fmt.Println(style.Warn(fmt.Sprintf("⚠  %v (delete deployment %s from the console)", err, st.DeploymentName)))
		} else {
			fmt.Println(style.Success(fmt.Sprintf("✓ Deployment %s deleted", st.DeploymentName)))
			// The CLI owns the deployment's Secret Manager secrets (the
			// template only reads them); remove them once nothing does.
			deleteGcpSecretsOrWarn(st.Project, st.DeploymentName)
		}
	} else {
		runner := collector.Runner{Name: st.ContainerName}
		if err := runner.Remove(); err != nil {
			fmt.Println(style.Warn(fmt.Sprintf("⚠  could not remove container: %v", err)))
		} else {
			fmt.Println(style.Success("✓ Container removed"))
		}
	}

	// An Instaclustr install's firewall rule needs the provisioning key this
	// CLI deliberately never stores, so removal is the user's step — but a
	// silent orphan (the machine's IP allowlisted forever) is not acceptable.
	if st.InstaclustrClusterID != "" {
		switch {
		case st.CollectorSecurityGroupID != "":
			// A VPC-resident collector was allowlisted by security group, so
			// there is no address left behind — but the entry still grants
			// whatever now occupies that security group.
			fmt.Println(style.Warn(fmt.Sprintf(
				"⚠  The Instaclustr cluster's firewall still allows security group %s.", st.CollectorSecurityGroupID)))
		case st.IsAWS() || st.IsGCP():
			fmt.Println(style.Warn("⚠  The Instaclustr cluster's firewall still allows the collector's egress IP."))
		default:
			fmt.Println(style.Warn("⚠  The Instaclustr cluster's firewall still allows this machine's IP."))
		}
		switch {
		case st.SecurityGroupRuleID != "":
			fmt.Printf("   Remove rule %s on the cluster's Firewall Rules page (or via the API).\n", st.SecurityGroupRuleID)
		case st.FirewallRuleID != "":
			fmt.Printf("   Remove rule %s on the cluster's Firewall Rules page (or via the API).\n", st.FirewallRuleID)
		default:
			fmt.Println("   Review the cluster's Firewall Rules page and remove the entry if no longer wanted.")
		}
	}

	// Deprovision the identity on the backend.
	deprovisioned := false
	if _, err := requireLogin(); err == nil {
		client := newAPIClient(cmd)
		if err := client.DeleteCollector(st.AgentID); err != nil {
			fmt.Println(style.Warn(fmt.Sprintf("⚠  could not deprovision identity: %v", err)))
		} else {
			fmt.Println(style.Success("✓ Identity deprovisioned"))
			deprovisioned = true
		}
	} else {
		fmt.Println(style.Warn("⚠  not logged in; cannot deprovision the identity."))
	}

	// Keep local state if deprovision did not succeed, so the user can retry
	// after re-logging in rather than orphaning the identity.
	if !deprovisioned {
		fmt.Println()
		fmt.Printf("The container was removed, but identity %s is still provisioned.\n", st.AgentID)
		fmt.Println("Run `dbg login`, then `dbg collector uninstall` again to deprovision it.")
		return nil
	}

	// Clear local secrets, env-file, config, state.
	collector.ClearSecrets(st.AgentID)
	_ = os.Remove(st.EnvFilePath)
	_ = os.Remove(st.ConfigPath)
	_ = collector.RemoveState()
	fmt.Println(style.Success("✓ Local config and secrets cleared"))
	return nil
}

// --- helpers --------------------------------------------------------------

func requireState() (*collector.State, error) {
	st, err := collector.LoadState()
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("no collector installed. Run: dbg collector install")
	}
	return st, nil
}

// requireRunnableState is requireState for the lifecycle verbs that drive a
// runtime this CLI started -- logs, start, stop, restart, upgrade.
//
// An in-cluster release is not one of those. Falling through would run the
// Docker path against an empty container name, so the command would fail with a
// Docker error about a collector that is running perfectly well in Kubernetes.
// Naming the equivalent kubectl/helm command is the useful answer; `status` and
// `uninstall` deliberately still accept a Helm collector.
func requireRunnableState(verb string) (*collector.State, error) {
	st, err := requireState()
	if err != nil {
		return nil, err
	}
	if st.IsHelm() {
		return nil, fmt.Errorf("this collector runs in your cluster as Helm release %q, so `dbg collector %s` does not drive it.\n"+
			"  logs:            kubectl --context <your-context> -n %s logs -l app.kubernetes.io/name=dbg-collector\n"+
			"  stop / start:    kubectl --context <your-context> -n %s scale deploy/%s --replicas=0 (or 1)\n"+
			"  upgrade:         helm upgrade %s %s --namespace %s --reuse-values\n"+
			"`dbg collector status` and `dbg collector uninstall` do work here",
			orUnknown(st.ReleaseName), verb,
			orUnknown(st.ReleaseNamespace), orUnknown(st.ReleaseNamespace), orUnknown(st.ReleaseName),
			orUnknown(st.ReleaseName), collector.DefaultChartRef, orUnknown(st.ReleaseNamespace))
	}
	return st, nil
}

func dockerRunner(st *collector.State) collector.Runner {
	return collector.Runner{
		Name:        st.ContainerName,
		Image:       st.Image,
		ConfigPath:  st.ConfigPath,
		EnvFilePath: st.EnvFilePath,
		CACertPath:  st.CACertPath,
	}
}

// runnerFromState loads the collector's saved state and hydrates a docker Runner
// from it (errors when no collector is installed). A thin composition of
// requireState + dockerRunner, kept as the convention for docker-only callers.
func runnerFromState() (collector.Runner, error) {
	st, err := requireState()
	if err != nil {
		return collector.Runner{}, err
	}
	return dockerRunner(st), nil
}

// buildDSN constructs a libpq URL for the preflight connection from the host's
// perspective (the original host, not the container rewrite). Uses the first
// configured database, or "postgres" when monitoring all databases.
func buildDSN(t collector.Target, password string) string {
	db := "postgres"
	if len(t.Databases) > 0 {
		db = t.Databases[0]
	}
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(t.User, password),
		Host:   net.JoinHostPort(t.Host, strconv.Itoa(t.Port)),
		Path:   "/" + db,
	}
	q := url.Values{}
	if t.SSLMode != "" {
		q.Set("sslmode", t.SSLMode)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// printPreflight renders a preflight report with severity markers + fixes.
func printPreflight(rep preflight.Report) {
	for _, r := range rep.Results {
		mark := style.Success("✓")
		switch r.Severity {
		case preflight.Warn:
			mark = style.Warn("⚠")
		case preflight.Fail:
			mark = style.Error("✗")
		}
		fmt.Printf("%s %s — %s\n", mark, r.Name, r.Detail)
		for _, f := range r.Fix {
			fmt.Printf("    %s\n", f)
		}
	}
}

// resolveCACert validates --ca-cert and returns an absolute path (or "").
func resolveCACert(cmd *cobra.Command) (string, error) {
	p, _ := cmd.Flags().GetString("ca-cert")
	if p == "" {
		return "", nil
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("--ca-cert: %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("--ca-cert: %w", err)
	}
	return abs, nil
}

// resolveImage picks the collector image to run. Precedence: an explicit --image
// flag (operator override) > the version the deployment blesses via
// preferred_collector_version > the CLI's built-in default.
func resolveImage(cmd *cobra.Command, creds *api.CollectorCredentials) (image, source string) {
	if cmd.Flags().Changed("image") {
		v, _ := cmd.Flags().GetString("image")
		return v, "--image override"
	}
	if creds != nil && creds.PreferredCollectorVersion != "" {
		return collector.ImageForVersion(creds.PreferredCollectorVersion),
			"version " + creds.PreferredCollectorVersion + " blessed by deployment"
	}
	v, _ := cmd.Flags().GetString("image") // the flag's built-in default
	return v, "CLI default"
}

// endpointsFromFlags reads the optional endpoint overrides. Empty values fall
// back to the collector's built-in production defaults. (Phase 2 replaces these
// flags with values from the deployment's .well-known discovery doc.)
func endpointsFromFlags(cmd *cobra.Command) collector.Endpoints {
	otlp, _ := cmd.Flags().GetString("otlp-url")
	opamp, _ := cmd.Flags().GetString("opamp-url")
	return collector.Endpoints{
		AuthBaseURL: authURLFlag(cmd),
		// Same port defaulting as endpointsFor. The exporter needs an explicit
		// host:port and fails on a bare host, so a flag value has to be treated
		// identically whichever path rendered it -- otherwise the config a
		// provisioning run produces and the config a flags-only run produces
		// differ from the same input, and only one of them starts.
		OtlpBaseURL:  withDefaultPort(otlp),
		OpampBaseURL: opamp,
	}
}

// authURLFlag returns the auth host override, preferring --auth-url and falling
// back to the deprecated --keycloak-url so existing scripts keep working.
func authURLFlag(cmd *cobra.Command) string {
	if v, _ := cmd.Flags().GetString("auth-url"); v != "" {
		return v
	}
	v, _ := cmd.Flags().GetString("keycloak-url")
	return v
}

// endpointsFor resolves the collector endpoints: start from the mint response
// (backend supplies these for non-prod deployments), then let any explicit
// --*-url flag override. Empty fields fall back to the collector's prod
// defaults.
func endpointsFor(creds *api.CollectorCredentials, cmd *cobra.Command) collector.Endpoints {
	e := collector.Endpoints{
		AuthBaseURL:  creds.AuthHost(),
		OtlpBaseURL:  creds.OtlpBaseURL,
		OpampBaseURL: creds.OpampBaseURL,
	}
	if v := authURLFlag(cmd); v != "" {
		e.AuthBaseURL = v
	}
	if v, _ := cmd.Flags().GetString("otlp-url"); v != "" {
		e.OtlpBaseURL = v
	}
	if v, _ := cmd.Flags().GetString("opamp-url"); v != "" {
		e.OpampBaseURL = v
	}
	// The OTLP exporter needs an explicit host:port; a bare "https://host"
	// (no port) makes otelcol fail with "missing port in address". Default to
	// the scheme's standard port when the endpoint omits one.
	e.OtlpBaseURL = withDefaultPort(e.OtlpBaseURL)
	return e
}

// withDefaultPort adds the scheme's standard port to a URL whose host omits one.
// Leaves the value untouched if it already has a port, is empty, or is unparseable.
func withDefaultPort(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Port() != "" {
		return raw
	}
	switch u.Scheme {
	case "https":
		u.Host += ":443"
	case "http":
		u.Host += ":80"
	default:
		return raw
	}
	return u.String()
}

// isLocalDatabase reports whether a host is this machine. Loopback names plus
// the Docker host alias, which is what a loopback target becomes for the
// containerized collector. Only these may have TLS dropped automatically.
func isLocalDatabase(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.Trim(h, "[]")
	return collector.IsLoopback(h) || h == collector.DockerHostInternal
}

// probeTLSSupport runs the capability probe with a bound timeout. A nil
// command context (tests, or a command invoked outside Execute) is tolerated.
func probeTLSSupport(cmd *cobra.Command, target collector.Target, password string) preflight.TLSSupport {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	// The probe is a courtesy, not a gate: bound it so an unresponsive host
	// delays the install by seconds rather than hanging it.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return probeTLS(ctx, preflight.ProbeTLSDSN(buildDSN(target, password)))
}

// previewTLSMode applies the dry run's share of the TLS decision: the safe,
// automatic loopback case, and a note for the case that would need consent. It
// never prompts and never changes anything outside target.
func previewTLSMode(cmd *cobra.Command, target *collector.Target) {
	if cmd.Flags().Changed("ssl-mode") {
		return
	}
	if probeTLSSupport(cmd, *target, "") != preflight.TLSUnsupported {
		return
	}
	if isLocalDatabase(target.Host) {
		fmt.Println(style.Warn(fmt.Sprintf(
			"⚠  %s does not accept TLS connections; it is on this machine, so the install would use ssl_mode=disable.",
			target.HostDial())))
		target.SSLMode = "disable"
		return
	}
	fmt.Println(style.Warn(fmt.Sprintf(
		"⚠  %s does not accept TLS connections and is not on this machine.", target.HostDial())))
	fmt.Println("   The real install would stop and ask you to confirm sending credentials")
	fmt.Println("   in clear text, or to pass --ssl-mode explicitly.")
}

// resolveTLSMode settles the connection's TLS mode by asking the server what it
// supports, rather than making the user discover a flag.
//
// The rule that governs it: never silently drop TLS for a database that is not
// on this machine. Auto-selecting no-TLS for loopback is safe -- the traffic
// never leaves the host. For any other host, no-TLS means the collector's
// queries and the database password cross a network in the clear, so it takes
// an explicit choice. Negotiating that away because the far end said "no TLS"
// is the shape of a downgrade attack.
//
// An explicit --ssl-mode is always honored and skips probing entirely.
func resolveTLSMode(cmd *cobra.Command, target *collector.Target, password string) error {
	if cmd.Flags().Changed("ssl-mode") {
		return nil // the user chose; nothing to infer
	}

	support := probeTLSSupport(cmd, *target, password)
	if support != preflight.TLSUnsupported {
		// Supported, or undeterminable. Keep the secure default and let the
		// real preflight report anything genuinely wrong.
		return nil
	}

	if isLocalDatabase(target.Host) {
		fmt.Println(style.Warn(fmt.Sprintf("⚠  %s does not accept TLS connections.", target.HostDial())))
		fmt.Println("   It is on this machine, so the connection never leaves it — continuing without TLS.")
		fmt.Println("   Pass --ssl-mode explicitly to choose for yourself.")
		target.SSLMode = "disable"
		return nil
	}

	// Remote and refusing TLS: state what was observed, then require a choice.
	fmt.Println(style.Warn(fmt.Sprintf("⚠  %s does not accept TLS connections, and it is not on this machine.", target.HostDial())))
	fmt.Println("   Without TLS the collector's queries and the database password cross")
	fmt.Println("   the network in clear text, readable by anything in between.")
	fmt.Println("   Nothing has been provisioned yet.")

	if !interactiveSelectable(cmd) {
		// Deterministic for CI: never auto-downgrade, including under --yes.
		return fmt.Errorf(
			"refusing to connect to %s without TLS on an unattended run.\n"+
				"  If clear text is genuinely what you want, say so explicitly: --ssl-mode disable\n"+
				"  If the database should have TLS, check the host and port first",
			target.HostDial())
	}
	if !promptYesNo("Connect to this remote database without TLS?", false) {
		return fmt.Errorf("aborted: %s refuses TLS and connecting without it was declined", target.HostDial())
	}
	target.SSLMode = "disable"
	return nil
}

func resolveTarget(cmd *cobra.Command) (collector.Target, error) {
	host, _ := cmd.Flags().GetString("db-host")
	port, _ := cmd.Flags().GetInt("db-port")
	user, _ := cmd.Flags().GetString("db-user")
	name, _ := cmd.Flags().GetString("name")
	sslMode, _ := cmd.Flags().GetString("ssl-mode")
	dbList, _ := cmd.Flags().GetString("db-name")

	if user == "" {
		user = prompt("Read-only database user", "")
	}
	if user == "" {
		return collector.Target{}, errors.New("a database user is required")
	}
	if name == "" {
		name = prompt("Name for this target", user)
	}

	var databases []string
	for _, d := range strings.Split(dbList, ",") {
		if s := strings.TrimSpace(d); s != "" {
			databases = append(databases, s)
		}
	}

	return collector.Target{
		Name:      name,
		Host:      host,
		Port:      port,
		Databases: databases,
		User:      user,
		SSLMode:   sslMode,
	}, nil
}

func resolveDBPassword(cmd *cobra.Command) (string, error) {
	if p, _ := cmd.Flags().GetString("db-password"); p != "" {
		return p, nil
	}
	if p := os.Getenv(collector.DBPasswordEnv); p != "" {
		return p, nil
	}
	fmt.Print("Database password: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("cannot read password: %w", err)
	}
	pw := strings.TrimSpace(string(b))
	if pw == "" {
		return "", errors.New("a database password is required")
	}
	return pw, nil
}

// checkReachable does a quick TCP dial so the most common local-dev failure
// (DB not running / wrong port) is caught before we provision anything.
func checkReachable(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach database at %s: %v\n   Check the host/port, that Postgres is running, and that it accepts TCP connections", addr, err)
	}
	_ = conn.Close()
	return nil
}

// errCollectorCrashLooping ends the install non-zero once the container has
// been shown to be restart-looping. The diagnosis is already printed.
var errCollectorCrashLooping = errors.New("collector container is not staying up")

// crashLooping watches the container briefly after start and reports whether it
// is restart-looping rather than running. It prints the diagnosis (including
// the container's own error lines) and returns true.
//
// Without this the install printed a green "Container started" over a container
// that was dying every two seconds, then blamed the control plane -- and
// suggested a private CA, which is the wrong fix for a crash on boot.
func crashLooping(runner collector.Runner) bool {
	// Two samples a few seconds apart: a restart loop shows either an explicit
	// "restarting" state or a RestartCount that has moved.
	state, restarts, err := containerHealth(runner)
	if err != nil {
		return false // cannot tell; stay quiet rather than cry wolf
	}
	if state != "restarting" && restarts == 0 {
		time.Sleep(4 * time.Second)
		state, restarts, err = containerHealth(runner)
		if err != nil {
			return false
		}
	}
	if state != "restarting" && restarts == 0 {
		return false
	}

	fmt.Println()
	fmt.Println(style.Error(fmt.Sprintf(
		"✗ The collector container is not staying up (docker state: %s, restarts: %d).", state, restarts)))
	if logs := containerRecentLogs(runner, 15); logs != "" {
		fmt.Println()
		fmt.Println("   Its last output:")
		for _, line := range strings.Split(logs, "\n") {
			fmt.Printf("     %s\n", line)
		}
	}
	fmt.Println()
	fmt.Println("   This is a startup failure, not a connection problem. Common causes:")
	fmt.Println("     - the config file could not be read inside the container; on Docker Desktop,")
	fmt.Println("       Colima or Rancher Desktop the config directory must be a shared path, or")
	fmt.Println("       the bind mount silently becomes an empty directory")
	fmt.Println("     - the image cannot run on this architecture")
	fmt.Println()
	fmt.Println("   Inspect with: dbg collector logs")
	return true
}

// verifyConnection polls the control plane briefly for the collector to come
// online. Non-fatal: a slow first connect is normal.
func verifyConnection(client *api.Client, agentID, caCert string) {
	fmt.Print(style.Info("Verifying connection"))
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		fmt.Print(".")
		cs, err := client.FetchCollectorStatus(agentID)
		if err == nil && cs != nil && isConnected(cs.Status) {
			fmt.Println()
			fmt.Println(style.Success(fmt.Sprintf("✓ Collector connected (%s)", cs.Status)))
			return
		}
		time.Sleep(3 * time.Second)
	}
	fmt.Println()
	fmt.Println(style.Warn("⚠  Not connected yet — this can take a moment on first start."))
	fmt.Println("   Check `dbg collector status` and `dbg collector logs -f`.")
	if caCert == "" {
		fmt.Println("   If your deployment uses an internal/private CA, re-run with")
		fmt.Println("   --ca-cert /path/to/ca.pem so the collector trusts its endpoints.")
	}
}

func isConnected(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "connected", "online", "ready", "ok":
		return true
	}
	return false
}

func prompt(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func confirm(cmd *cobra.Command, question string) bool {
	if yes, _ := cmd.Flags().GetBool("yes"); yes {
		return true
	}
	if interactiveTerminal() {
		return promptYesNo(question, false)
	}
	fmt.Printf("%s [y/N]: ", question)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
