# Deploy layout

## Dockerfile (`deploy/Dockerfile`)

- Multi-stage build: `golang` builder → `distroless/static-debian12:nonroot` runtime
- Static binary (`CGO_ENABLED=0`), stripped with `-ldflags="-s -w"`
- Runs as UID 65532 (`nonroot`); no shell or package manager in the final image

## Docker Compose (`deploy/docker-compose.yml`)

Runtime hardening applied to the `api` service:

| Control | Setting |
|---------|---------|
| Read-only root FS | `read_only: true` + `tmpfs: /tmp` |
| Capabilities | `cap_drop: [ALL]` |
| Privilege escalation | `security_opt: no-new-privileges:true` |

Postgres runs with a dedicated data volume. Init scripts in `deploy/init-db.sql` create the `vault_app` least-privilege role.

## Quick start

```sh
make db-up
make migrate-up
make grant-app-role
make run
```

See [docs/BACKUP.md](../docs/BACKUP.md) for `pg_dump` / `pg_restore` procedures.
