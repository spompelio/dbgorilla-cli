# Changelog

## v0.6.1

### Fixed

- `dbg collector install --provider instaclustr` now connects to the cluster's
  primary to create the `dbgorilla_monitor` role. It previously used whichever
  node the cluster API listed first; that API reports the same role for every
  PostgreSQL node, so on a multi-node cluster the install failed about half the
  time with `cannot execute CREATE ROLE in a read-only transaction`. The
  primary is identified by `pg_is_in_recovery()`, as the collector already does
  during discovery.

- On a cluster created without public addresses, the temporary firewall rule
  names the address the cluster sees this machine arrive from, rather than its
  public egress address — which admitted the wrong host and still left setup
  unable to connect.

- The install no longer aborts when the cluster's default user cannot grant
  `pg_read_all_data`. On a managed cluster that grant is refused outright —
  PostgreSQL 16 and later require ADMIN OPTION on a role to grant it, and the
  default user holds no membership in it — so the install used to fail at the
  last statement of role setup, having already created a perfectly usable role.
  It now warns and continues, and says what the role can still do: monitoring,
  topology and schema capture are unaffected, and only running a query or an
  EXPLAIN against a table would need SELECT granted on that table directly.

### Added

- The install reports where a cluster runs and how it is reachable: the
  provider account it belongs to, its own VPC, and whether it was created
  without public addresses. Account residency and address side are independent
  — a cluster in your own cloud account still has public addresses unless it
  was created private, and is dialled publicly from outside its VPC.

- A cluster created without public addresses can only be set up from inside its
  network, so the install checks the route first and says what would make it
  work — the VPN, a peered VPC, or a bastion — instead of timing out. An
  unrecognised route warns and continues, because a route out the same
  interface is indistinguishable from no route at all.

## v0.6.0

### Added

- `dbg collector install --provider instaclustr --cluster-id <id>` monitors a
  NetApp Instaclustr managed PostgreSQL cluster. The install discovers the
  cluster through the Instaclustr Cluster Management API, creates a read-only
  `dbgorilla_monitor` role via the cluster's default user (no superuser, no
  support ticket), allowlists this machine's public IP on the cluster
  firewall, and runs the collector locally in Docker. The database *source*
  (`--provider`) is independent of the deploy substrate (`--target`); other
  targets for this source come later.

- Two Instaclustr API keys with two fates: the provisioning key
  (`--instaclustr-api-key` / `INSTACLUSTR_PROVISIONING_API_KEY`) does the
  setup from your machine and is never stored; the read-only key
  (`--instaclustr-readonly-key` / `INSTACLUSTR_READONLY_API_KEY`) is the only
  one the collector keeps, for node discovery.

- `dbg collector refresh-firewall` re-allowlists the collector's current
  public IP on the Instaclustr cluster firewall and retires the stale rule
  this CLI created for the previous IP — never a rule it does not own. The
  fix for the "my ISP changed my address and the collector went quiet" day-2
  case. On an AWS deploy it allowlists the stack's Elastic IP instead of
  this machine's address.

- `--provider instaclustr --target aws` deploys the collector to Fargate.
  Networking is explicit (`--subnets`/`--security-group-id` — there is no
  RDS instance to discover it from), and by default the task runs behind a
  NAT gateway with an Elastic IP (`--stable-egress`, requiring `--vpc-id`
  and `--nat-subnet-cidr`), so the firewall entry the install creates stays
  valid across every task restart. The stack's new `EgressIP` output is the
  address on the allowlist. Template v1.1 adds the optional
  `InstaclustrApiKey` secret parameter (the read-only key, injected as
  `INSTACLUSTR_API_KEY`) and the stable-egress resources.

- `--provider instaclustr --target gcp` deploys the collector to Compute
  Engine via Infrastructure Manager. Networking is explicit
  (`--region`/`--network` — there is no Cloud SQL instance to discover it
  from), and by default the instance lives in a template-owned subnetwork
  routed through a Cloud NAT with a reserved static address
  (`--stable-egress`, requiring `--nat-subnet-cidr`); the NAT is scoped to
  only that subnetwork, so it never collides with one the VPC already has.
  The deployment's new `egress_ip` output is the address on the allowlist,
  and `refresh-firewall` reads it the way it reads the AWS stack's
  `EgressIP`. GCE template v1.3 adds the stable-egress
  resources, gates the Cloud SQL/AlloyDB project roles behind
  `database_roles` (off for Instaclustr), and drops the secret input
  variables entirely: the CLI writes `<deployment>-server-secret`,
  `-db-password` and `-instaclustr-api-key` to Secret Manager itself, so no
  credential reaches Infrastructure Manager's input values or state.

## v0.5.3

### Added

- `setup-ide` installs a short DBGorilla skill for Claude Code, at
  `~/.claude/skills/dbgorilla/SKILL.md` (or under the project's `.claude/`
  with `--scope project`). Registering the MCP server gave the agent the
  tools but not the habit of using them; the skill triggers on database work
  — SQL, schema, migrations, indexes, slow queries, database errors — and
  says to check the live component before reasoning from the source alone.
  Re-running rewrites it only when the shipped text has changed.

- `setup-ide --remove` undoes the setup: it strips the `dbgorilla` MCP entry
  from the selected clients and removes the skill, leaving every other entry
  and setting in those files untouched, and backing each one up first. There
  was previously no way to un-configure a client short of editing its config
  by hand. It works with no session and no reachable deployment.

- `setup-ide --rotate-key` issues a new MCP API key on purpose, for when you
  believe the current one has been exposed. Every client still holding the
  old key stops working until you re-run `setup-ide` there, and the command
  says so.

- `whoami` now prints the role, the user id and the organization id underneath
  the identity line, without being asked. `whoami` is run to answer an identity
  question, and the answer is usually pasted into a support thread or an issue,
  where the ids are the part that identifies anything. Scripts parsing the
  single line this command used to print should move to `whoami --json`.

- `login --verbose` prints the same block on success. `login` is run to get past
  it rather than to read it, so its default stays one line.

- `doctor` prints the role and the ids under its `Auth + API` line, indented to
  line up with it. `doctor` output exists to be pasted into a support thread,
  and it was the one place that showed who you are without showing anything
  that identifies the account.

### Changed

- `logout` now revokes the MCP API key as well as clearing the login tokens.
  Previously it cleared only the tokens, so an editor configured through
  `setup-ide` kept working after sign-out — and that key does not expire. If
  the deployment cannot be reached, sign-out still completes and says the key
  is still live. The MCP entries in your editors are left in place, and stop
  working; `setup-ide --remove` takes those out.

- `whoami --json` matches the API's own field names: `tenant` is now
  `organization`, `user_id` is now `id`, and `role` is included. `is_admin` is
  gone — it was never populated by any deployment. A script reading the old
  names was reading fields that were always empty, and needs the new ones.

### Fixed

- `setup-ide` no longer invalidates your MCP API key every time it runs. The
  backend issues one key per user and a mint overwrites the stored one, so
  each run silently killed the key already in use — anyone with it configured
  in a second editor, or anywhere outside an editor, found those rejected
  later, at use, with nothing at setup time having said so. `setup-ide` now
  reuses the existing key and mints only when there is none, so configuring
  another client leaves the ones already working alone.

- `login`, `whoami` and `doctor` name your organization instead of printing its
  UUID. The CLI read the organization name, the user id and an admin flag under
  key names the API does not send, so all three arrived empty and the output
  fell back to the raw identifier. Nothing reported an error — the id was simply
  what you saw where the name belonged.

- `login` no longer warns about the identity provider being on its own
  subdomain. Signing in printed two multi-line warnings whose own text said the
  situation was normal — because it is: the identity provider on a sibling
  subdomain of the API is the ordinary deployment. The warning now fires only
  when an endpoint leaves the API's registrable domain, which is the case it was
  written for, and says so in one line naming the host.

- Auto-detecting the sign-in mode no longer reads a broken deployment as one
  without SSO. Every non-200 from the device-config endpoint was treated as
  "this deployment has no SSO" and dropped to a password prompt, so a 502 from
  a proxy in front of a dead backend, a 503 mid-deploy, or a 401 from something
  guarding the path all produced a request for credentials on behalf of a
  deployment that was not working — and discarded the status code that would
  have explained it. Only a 404, the deployment answering that it genuinely has
  no SSO, still falls back to password sign-in. Everything else now names the
  status.

## v0.5.2

### Fixed

- `collector install --target aws` and `collector upgrade --target aws` pin the
  collector to an exact image rather than a tag. A tag left the CloudFormation
  parameter unchanged between releases, so an upgrade had nothing to act on and
  did nothing; and ECS re-pulls a tag whenever a task starts, so the collector
  could change version on a restart nobody asked for. AWS now behaves like a
  local install: upgrade moves it, nothing else does, and `collector status`
  reports the exact version running.

## v0.5.1

### Changed

- Release artifacts are now signed to a Sigstore bundle
  (`<artifact>.sigstore.json`) instead of a detached `.sig`. Signing is
  keyless, and the bundle carries the signature, the signing certificate and
  the transparency-log entry together, so a download can be verified straight
  from the release page:

  ```sh
  cosign verify-blob \
    --bundle dbg-darwin-arm64.sigstore.json \
    --certificate-identity-regexp '^https://github\.com/dbgorilla/dbgorilla-cli/\.github/workflows/release\.yml@refs/tags/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    dbg-darwin-arm64
  ```

  Releases up to and including v0.5.0 publish `.sig` files; verify those
  through their build provenance with
  `gh attestation verify <file> --repo dbgorilla/dbgorilla-cli`.

- A prerelease tag no longer bumps the Homebrew formula. The tap upload was
  unconditional, so a release candidate — or a tag cut to exercise the release
  pipeline — would have pointed every `brew upgrade` at a build that was not
  meant for general use.

### Fixed

- `collector upgrade` installs the newest published collector. It previously
  installed a version fixed when the CLI was built, so re-running it could not
  move a collector forward. `--image <repo>:<version>` installs a specific
  version instead.

  Local installs still record an immutable digest, so what a collector is
  running stays exact. On `--target aws` the image resolves when the task
  starts, so a restart can pick up a newer collector without `upgrade` being
  run.

  An upgrade that resolves to what is already running is now a no-op rather
  than a container rebuild.

- `dbg login` printed every device-flow endpoint warning twice. Auto-detecting
  the sign-in mode fetched and validated the device configuration, discarded
  it, and the device flow then fetched and validated the same thing again --
  so a deployment whose Keycloak runs on its own subdomain (the normal case)
  produced four alarming warning blocks for two conditions, on the first
  command after install. The configuration is now fetched once and reused, and
  each warning prints once. The warning text is unchanged.
- A configured API URL that redirects elsewhere now says so. A deployment that
  has moved answers every path with a redirect to its new home, usually the
  site root rather than the matching path. The CLI followed it, landed on a web
  page that returns HTTP 200, and failed while reading JSON — reporting
  `invalid character '<' looking for beginning of value`, which gives the user
  nothing to act on. Redirects to a different host are now refused, and the
  error names the host, states that nothing beyond the original request was
  sent, and gives the command to point at it deliberately. Same-host redirects
  are unaffected.
- Relatedly, an endpoint that answers with a web page rather than JSON is now
  named as such instead of surfacing a decoder error about a stray `<`.
- Auto-detecting the sign-in mode no longer hides a wrong API URL. `dbg login`
  with no `--mode` treated every device-config failure as "this deployment has
  no SSO" and dropped to a password prompt — so a stale URL produced a prompt
  for credentials on behalf of a deployment the CLI never reached, and the error
  explaining it was discarded. A 404 still falls back to password sign-in; a
  deployment that never answered as itself now surfaces the reason.

## v0.5.0

### Changed

- `collector install` now works out what TLS mode the database supports instead
  of making you guess a flag. Stock Postgres ships with `ssl=off`, so the
  documented command used to fail on every standard local setup with "server
  does not support SSL" and a hint pointing the wrong way. The CLI now asks the
  server first (nothing is provisioned at that point) and reacts:

  - A database **on this machine** (loopback, or the Docker host alias) that
    refuses TLS is handled automatically — the traffic never leaves the host —
    and the CLI says so rather than failing.
  - A database **anywhere else** that refuses TLS is never downgraded silently.
    The CLI states plainly that queries and the database password would cross
    the network in clear text and asks for an explicit yes; unattended runs
    (including `--yes`) refuse outright and tell you to pass `--ssl-mode
    disable` if that is genuinely intended.
  - An explicit `--ssl-mode` is always honored and skips the probe entirely,
    and `--target aws` is unchanged.

  `--dry-run` previews the same decision, so it no longer advertises a config
  the real install would not produce.
- A missing `pg_stat_statements` in `shared_preload_libraries` is now a
  preflight **warning** rather than a hard failure. The collector runs and
  reports schema topology without it; it gates query-performance data only.
  Blocking meant a new user had to `ALTER SYSTEM` and restart their database
  before seeing anything work.
- The CLI now defaults its API URL to the hosted production deployment
  (`https://app.dbgorilla.com`) when nothing is configured. Every existing
  configuration layer still overrides it: `--api-url`, `DBGORILLA_API_URL`,
  the user config file, then the system config file. Homebrew installs — which
  cannot know a deployment URL at install time — now work with `dbg login`
  alone; self-hosted deployments are unaffected because their install script
  writes the deployment URL into the user config. `dbg config get api-url` and
  `dbg doctor` report `source: default` when the fallback is in use, and
  commands no longer error with "no DBGorilla API URL configured".

### Fixed

- `collector upgrade` no longer silently downgrades a running collector. The
  version it installs comes from the CLI binary itself when `--image` is not
  given, so running it from an out-of-date `dbg` rolled a newer collector
  backwards and printed "✓ Upgraded" doing it. It now compares the two
  versions first: an older target is refused (with `--allow-downgrade` to
  override), an identical one exits without rebuilding the container, and a
  reference it cannot order — a custom image, a floating tag, a collector
  installed before the version was recorded — proceeds as before.
- Three shipped messages told users to run `dbg install --target aws`, which is
  not a command: `install` lives under `collector`, so anyone who copied the
  printed text got "unknown command". Corrected in the `encode-config` help,
  both stack-parameter errors, and `examples/collector-aws.toml`.
- Preflight's remediation for a failed connection pointed the wrong way: a
  server with TLS *disabled* was told to set `--ssl-mode require (or
  verify-full)`, which fails again. The advice now reflects what actually
  happened, and names `disable` where that is the fix.
- `collector install` no longer reports success over a collector that is
  crash-looping. It re-checks the container's state and restart count after
  start, prints the container's own last output, and names the likely cause
  (commonly a config directory the container runtime cannot bind-mount)
  instead of blaming a private CA.
- Collector secrets fall back to a `0600` file when the OS keyring is
  unavailable, mirroring how login tokens are already stored. Previously the
  install aborted *after* the collector identity had been provisioned, leaving
  an orphaned identity server-side on headless Linux, WSL, and CI hosts.
- Backend errors carrying an HTML body (an SPA catch-all, proxy, or login
  portal answering instead of the API) no longer dump the page into the
  terminal. The CLI names the situation and points at `dbg config get api-url`;
  long JSON bodies are truncated.
- The AWS-target grant instructions (printed after install, or run by
  `--run-grant`) now include `GRANT pg_read_all_data` (PostgreSQL 14+). Without
  it the schema-topology scraper fails on every cycle -- its `pg_dump` needs
  SELECT on the monitored tables, which `pg_monitor` does not confer. Note this
  permits the collector to read table contents; installations that must forbid
  that can omit the grant at the cost of the topology feature. The grant runs
  last, so on PostgreSQL 13 and older every other grant still lands.

## v0.4.0

### Added

- `collector install --target aws` deploys the collector as an AWS Fargate task
  instead of a local Docker container, for monitoring RDS and Aurora Postgres.
  It discovers the database, its subnets, and its security groups, then creates
  a CloudFormation stack holding the ECS cluster, task, IAM roles, log group,
  and a Secrets Manager secret for the collector's credentials. `--target
  docker` remains the default and is unchanged.
- Multi-database collectors. One Fargate collector can monitor several
  databases: pass `--config` a TOML file with a `[[database]]` entry per
  database, or pick them from a checklist when the CLI finds more than one.
- Network-path verification before deploy. The CLI reads the VPC's
  security-group rules and reports whether the collector will actually be
  admitted to each database on its port, with the exact ingress rule to add
  when it won't. This catches the "deployed successfully but silently cannot
  connect" case before the stack is created.
- IAM database authentication by default, with `rds-db:connect` scoped to each
  database's resource ID rather than granted account-wide. The CLI prints the
  SQL a database admin must run, or runs it directly with `--run-grant`.
  `--db-password` opts a database into password authentication instead, and the
  password is stored in Secrets Manager rather than the task definition.
- Per-database query-analysis controls. `--commands` selects which analysis
  queries (`execute_query`, `explain`) the collector may run against each
  database; an interactive checklist appears when the flag is omitted, and
  `--enable-commands=false` forbids them outright.
- The AWS-target lifecycle commands: `collector status`, `logs`, `start`,
  `stop`, `restart`, `upgrade`, and `uninstall` all operate on the Fargate
  deployment when the collector was installed with `--target aws`. The target
  is recorded at install time, so these need no extra flag.
- `collector encode-config`, which encodes a collector config for the
  CloudFormation `CollectorConfig` parameter — for launching the stack by hand
  from the AWS console rather than through the CLI.
- The CloudFormation template is published at a stable URL and versioned on its
  own contract (currently v1.0), independent of the CLI's version. Customers
  can read and security-review the exact file their account will deploy before
  running anything, and `--template-url` deploys a self-hosted copy instead.

### Changed

- The default collector image moves to 0.3.3, which carries RDS certificates in
  the container's system trust root. This matters for the AWS target, where the
  CLI defaults to `verify-full` TLS against RDS and Aurora endpoints.

### Notes

- The AWS target requires HTTPS access to the published template. A CLI that
  cannot reach it fails with an explanatory error rather than deploying a
  possibly-stale local copy; use `--template-url` where egress is restricted.

## v0.3.1

### Changed

- Collector config renames the `keycloak_base_url` key to `auth_base_url`, and
  `collector install` gains an `--auth-url` flag (the old `--keycloak-url` flag
  is deprecated). The former name is still read as a fallback, so existing
  `collector.toml` files and scripts keep working; update them to `auth_base_url`
  at your convenience.

## v0.3.0

### Added

- Colorized status output across commands (login, whoami, doctor, setup-ide,
  collector, config, logout), via a new `--color`/`--no-color` flag pair.
  Color auto-detects a real terminal and honors `NO_COLOR` and `TERM=dumb`,
  so piped or incompatible output stays plain text.

### Fixed

- `dbg login` now honors Ctrl-C during the password-mode credential prompt
  instead of ignoring the interrupt.
- `dbg upgrade` runs `brew upgrade` against the `dbgorilla` formula rather
  than a nonexistent `dbg` formula.
- Preflight gates the `pg_stat_statements` check on the Postgres maintenance
  database, avoiding false failures where the extension isn't present
  cluster-wide.

## v0.2.0

### Added

- `dbg collector` — install and manage a local-dev collector.
- `go install github.com/dbgorilla/dbgorilla-cli/cmd/dbgorilla@latest` support
  via the `cmd/dbgorilla` layout.

### Fixed

- Auth: SSO/device-flow sessions now refresh at Keycloak rather than the
  backend.
- `dbg version` falls back to Go build info for `go install` builds where
  ldflags aren't injected.
- `setup-ide` Claude Code registration is now idempotent; added a
  topology-permission preflight, corrected the OTLP port, and a `--ca-cert`
  hint for private-CA deployments.

## v0.1.4 — Initial release

First release of the DBGorilla CLI.

### Commands

- `dbg login` — Sign in via Keycloak SSO (RFC 8628 device flow) with auto-fallback to username/password.
- `dbg logout` — Clear stored credentials.
- `dbg whoami` — Show the signed-in user and organization.
- `dbg setup-ide` — Mint an MCP API key and register DBGorilla in every detected MCP client. Supports Claude Code (via `claude mcp add` or direct write), Cursor, VS Code, opencode, and Gemini CLI. Detects Claude Desktop and prints manual setup instructions (its remote MCP requires the Settings → Connectors UI flow). Use `--list-clients` to see what's supported and detected; `--client <slug>` to target specific tools; `--scope user|project` to override the per-client default; `--print-config` to emit the JSON entry; `--dry-run` to preview without writing. All writes are merged with backups; existing MCP servers and unrelated config keys are preserved; JSONC files are refused rather than overwritten.
- `dbg doctor` — Verify auth, API reachability, MCP key, and IDE config.
- `dbg config {set, get, unset}` — Manage the deployment URL and other settings.
- `dbg version` — Print version info.

### Distribution

- Homebrew tap: `brew install dbgorilla/tap/dbg`
- On-prem install script served from the customer's DBGorilla backend at `/install.sh` — air-gapped friendly.
- Cross-platform binaries on [GitHub Releases](https://github.com/dbgorilla/dbgorilla-cli/releases).

### Compatibility

Requires a DBGorilla deployment that exposes the Keycloak device-flow auth-config endpoint and the MCP API-key endpoints. Contact your DBGorilla administrator if unsure.

### Notes

- API URL resolution: flag > env > user config > system config (IT-deployed via MDM).
- Tokens persist in the OS keychain (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows) with a `0600` file fallback for headless boxes.
- `dbg setup-ide` shells to `claude mcp add` so managed Claude allowlist policies are respected. Use `--print-admin-allowlist` to get the IT-facing snippet for the Claude admin console.

### TLS / private CA

On-prem deployments using an internal CA need two trust-store updates:

1. **OS-level CA trust** for `dbgorilla` itself (deploy via MDM; `--insecure` works as a stopgap).
2. **`NODE_EXTRA_CA_CERTS`** pointing at the CA bundle for Claude Code. Node doesn't read macOS Keychain on its own; without this, Claude Code rejects the MCP server's certificate even if `curl` and Safari trust it. Do not use `NODE_TLS_REJECT_UNAUTHORIZED=0` — it disables verification for every HTTPS connection in the process. See README for details.
