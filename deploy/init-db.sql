-- Creates the least-privilege application role used by cmd/server at runtime.
-- The superuser (vault_root) is used only for migrations (golang-migrate).
-- vault_app gets DML only — no DDL, no TRUNCATE, no DROP.
--
-- This script runs once when the container is first initialised
-- (docker-entrypoint-initdb.d). Re-creating the container re-runs it.

CREATE ROLE vault_app WITH LOGIN PASSWORD 'apppassword';

-- Permissions are granted after the migration creates the tables.
-- See Makefile target migrate-up which also calls grant-app-role.
