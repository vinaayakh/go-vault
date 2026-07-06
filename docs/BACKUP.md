# Database backup and restore

Basic PostgreSQL backup procedures for local development and Docker Compose deployments.

## Prerequisites

- `pg_dump` and `psql` (ships with PostgreSQL client tools)
- Connection URL with sufficient privileges (`DATABASE_SUPERUSER_URL` for full restores)

## Backup (logical dump)

With Docker Compose running (`make db-up`):

```sh
pg_dump "postgres://vault_root:devpassword@localhost:5432/vault?sslmode=disable" \
  --format=custom \
  --file=secure-vault-backup.dump
```

Custom format supports parallel restore and selective table recovery.

Plain SQL (human-readable):

```sh
pg_dump "postgres://vault_root:devpassword@localhost:5432/vault?sslmode=disable" \
  > secure-vault-backup.sql
```

## Restore

**Warning:** restore overwrites existing data in the target database.

Custom format:

```sh
pg_restore --clean --if-exists \
  --dbname="postgres://vault_root:devpassword@localhost:5432/vault?sslmode=disable" \
  secure-vault-backup.dump
```

Plain SQL:

```sh
psql "postgres://vault_root:devpassword@localhost:5432/vault?sslmode=disable" \
  -f secure-vault-backup.sql
```

After restoring schema, re-apply the least-privilege app role if needed:

```sh
make grant-app-role
```

## Operational notes

- Back up **before** running `make migrate-down` or destructive schema changes.
- Store dump files outside the repo; they contain ciphertext and auth material.
- For production, automate encrypted off-site backups and test restores regularly.
