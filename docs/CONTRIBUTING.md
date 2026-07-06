# Contributing

## Before opening a PR

1. Run `go test -race ./...` and `npm --prefix web run typecheck`.
2. After editing `api/openapi.yaml`, run `make openapi`.
3. After editing `db/queries/` or `db/schema.sql`, run `make sqlc` (Linux or CI — sqlc may not run on all Windows hosts).
4. Ensure pre-commit hooks pass: `make precommit`.

## GitHub repository settings (manual)

These cannot be enforced from code; configure in the GitHub UI:

### Branch protection on `main`

- Require pull request before merging
- Require status checks: `build & test (race)`, `integration tests (Postgres)`, `golangci-lint`, `govulncheck`, `web`, `e2e`, `sqlc drift check`
- Do not allow bypassing the above settings

### Signed commits

- Enable "Require signed commits" on `main` (GPG or SSH signing locally)

### Dependabot

Configured in `.github/dependabot.yml` for Go modules, npm (`web/`), and GitHub Actions.

## Security reporting

Do not open public issues for vulnerabilities. Describe the issue privately to the maintainer.

## Contract-first API changes

Edit `api/openapi.yaml` first, regenerate clients (`make openapi`), then implement handlers. Never hand-edit `internal/api/gen/` or `web/src/api/gen/types.ts`.

Cryptographic wire formats are documented in [docs/THREAT_MODEL.md](THREAT_MODEL.md) §8.
