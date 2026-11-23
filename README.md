# ServerForge

ServerForge is an MIT-licensed CLI for defining reusable Ubuntu server provisioning profiles. Milestone 1 ships profile creation, validation, and read-only preflight for Ubuntu 22.04, 24.04, and 26.04 LTS. The CLI runs without root. You can store the executable and profiles in separate locations and remove the executable by deleting that file.

A profile can describe a local Ubuntu machine or an Ubuntu target reached over SSH. All preflight checks run on the local machine. For an SSH profile, the report covers the controller and marks the remote checks as deferred. Execution plans, apply-time approvals, provisioning, dry-run, resume, idempotency and SSH lockout safeguards belong to later milestones.

## Build and run

Use Go 1.26 with the latest patch release.

```sh
go build -o ./bin/serverforge ./cmd/serverforge
./bin/serverforge init --output ./profile.yaml
./bin/serverforge validate --config ./profile.yaml
./bin/serverforge preflight --config ./profile.yaml --json --log-json
```

`init` asks about services first and then collects the target and settings relevant to the selection. The Security Wizard offers UFW, Fail2ban, and automatic security updates separately. Each defaults to **Skip**. The choices express intent for a profile only. If you create a profile with PostgreSQL, MySQL, MariaDB, or Redis, enter its credentials and an Ansible Vault passphrase at the masked prompts. Keep the passphrase in a password manager. After you choose **Save profile**, ServerForge creates an owner-only file with mode `0600` and preserves any existing destination.

For non-interactive use, supply an existing profile to `validate` or `preflight`. Example profiles are in `examples/`. Copy and adapt one for your target. Commands return exit code `0` on success, `1` for an operational error or failing check, and `2` for invalid command syntax. `--json` writes reports to stdout and `--log-json` emits JSON diagnostic events on stderr. The interactive wizard uses stderr for its terminal UI, so reserve JSON log collection for non-interactive commands.

Preflight checks the local Ubuntu release, privilege context, and tooling on `PATH` using filesystem reads. Missing Ansible tooling and Python on a clean local target appear as warnings. A missing SSH client or unsupported local release fails preflight. JSON reports include the scope, individual check statuses, and whether any check in that scope failed. A successful controller report leaves the remote OS, access, and services unverified.

## Version 1 profile schema

A profile is one YAML mapping. `version: 1` and `target.connection` are required. `local` uses the current machine. `ssh` requires a hostname or unbracketed IP address, an SSH username, and the existing SSH port in `target.host`, `target.user`, and `target.port`. The profile contains no SSH private key or login password.

| Section | Fields and constraints |
| --- | --- |
| `modules` | Optional list of `docker`, `docker_compose`, `nginx`, `caddy`, `postgresql`, `mysql`, `mariadb`, `redis`, and `ssl`. Compose requires Docker, and SSL requires one web server. Choose at most one of Nginx and Caddy and at most one of MySQL and MariaDB per target. |
| `databases` | One mapping per selected database engine, using the module name as the key. Each accepts `name`, `user`, and `port`. Use letters, digits, and underscores in identifiers, beginning with a letter or underscore. |
| `web` | Required for Nginx or Caddy. Set a fully qualified `domain` and an `http_port`. |
| `tls` | Required for `ssl`. Set a certificate contact `email` and HTTPS `port`. |
| `redis` | Required for Redis. Set its `port`. |
| `security` | Optional `ufw`, `fail2ban`, and `security_updates` choices. Each accepts literal `true` or `false` and defaults to `false` when omitted. |
| `vault` | Required when a database or Redis module is selected. Use a YAML block scalar containing only an Ansible Vault AES256 envelope. The encrypted YAML mapping uses `postgresql_password`, `mysql_password`, `mariadb_password`, and `redis_password` as applicable. |

Ports must be in the range 1–65535 and unique within the profile, including the existing SSH port when configured. For non-interactive profiles with credentials, encrypt a YAML mapping with `ansible-vault` and embed only the ciphertext. Ansible can read mapping input from stdin, so automation can supply it directly from a secret manager. Validation checks the Vault envelope without decrypting it. Use the stored Vault passphrase to verify the encrypted content separately.

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/serverforge/` | Executable entry point and signal handling |
| `internal/cli/` | Cobra commands, output, exit codes, and structured diagnostics |
| `internal/config/` | Versioned profile schema, validation, and file I/O |
| `internal/wizard/` | Huh prompts and the Security Wizard |
| `internal/vault/` | Ansible Vault encryption and envelope validation |
| `internal/preflight/` | Read-only local and controller checks |
| `examples/` | Local and SSH profile examples |
| `tests/` | Terminal integration tests |
| `.github/workflows/ci.yml` | Ubuntu CI for formatting, vetting, tests, build, and CLI smoke checks |

## Local testing

```sh
go vet ./...
go test -race -cover ./...
```

The suite tests profile validation, concurrent file creation, preflight against simulated hosts, log redaction, and Vault encryption. The Ansible compatibility test runs when `ansible-vault` is available. Set `SERVERFORGE_REQUIRE_ANSIBLE_VAULT=1` to require it. With Python, `pexpect`, and `PyYAML` installed, run `python tests/wizard_smoke.py ./bin/serverforge` to exercise the real terminal wizard with fake credentials.

For an isolated Ubuntu smoke check, build a Linux binary for the container architecture. Then run it in an Ubuntu image with no network, a read-only filesystem, and read-only mounts.

```sh
CGO_ENABLED=0 GOOS=linux go build -o ./bin/serverforge ./cmd/serverforge
docker run --rm --network none --read-only --cap-drop ALL \
  --mount "type=bind,source=$PWD/bin/serverforge,target=/serverforge,readonly" \
  --mount "type=bind,source=$PWD/examples/local.yaml,target=/example.yaml,readonly" \
  ubuntu:24.04 /serverforge preflight --config /example.yaml --json
```
