# Database Migrations (Alembic)

This document explains how to create, apply, and roll back database schema
migrations for Net Sentry.  Net Sentry uses [Alembic](https://alembic.sqlalchemy.org/)
with a SQLAlchemy Core + ORM setup, and defaults to **SQLite** while optionally
supporting **PostgreSQL** (see [docker-compose.yml](../../docker-compose.yml),
`--profile postgres`).

---

## Prerequisites

```bash
# Activate the virtual environment (always work inside it)
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
.venv\Scripts\Activate.ps1      # Windows PowerShell

pip install -e ".[dev]"
```

Set the database URL either in `config.yaml` or via environment variable:

```bash
# SQLite (default — no setup needed)
export DATABASE_URL="sqlite:///data/net-sentry.db"

# PostgreSQL (requires the "postgres" profile in docker-compose)
export DATABASE_URL="postgresql+pg8000://btwifi:btwifi@localhost:5432/btwifi"
```

---

## First-time database setup

```bash
# Apply all pending migrations to bring the schema to HEAD
alembic upgrade head
```

If the database file does not exist yet, Alembic (via `alembic/env.py`) will
create it automatically on the first `upgrade` run.

---

## Check the current revision

```bash
alembic current
```

---

## View migration history

```bash
alembic history --verbose
```

---

## Creating a new migration

### Autogenerate (recommended)

When you change `src/models.py`, Alembic can detect the diff and generate the
migration script automatically:

```bash
alembic revision --autogenerate -m "add_snmp_info_column"
```

Review the generated file in `alembic/versions/` before applying it — check
that the `upgrade()` and `downgrade()` functions look correct.

### Empty / hand-written migration

```bash
alembic revision -m "drop_legacy_extra_info"
```

Then edit `alembic/versions/<rev>_drop_legacy_extra_info.py` by hand.

---

## Applying migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Apply exactly one step forward
alembic upgrade +1

# Apply to a specific revision
alembic upgrade abc123
```

---

## Rolling back

```bash
# Roll back one step
alembic downgrade -1

# Roll all the way back to an empty schema
alembic downgrade base

# Roll back to a specific revision
alembic downgrade abc123
```

---

## Stamping (marking without running SQL)

If the database was created outside of Alembic (e.g. by `init_database()`
calling `Base.metadata.create_all()`), stamp it at the current head so future
`upgrade` runs will not try to re-apply already-applied migrations:

```bash
alembic stamp head
```

---

## CI / production checklist

1. `alembic upgrade head` is **idempotent** — safe to run on every deploy.
2. Always run migrations **before** starting the application server.
3. For zero-downtime deploys, write additive migrations (new columns with
   defaults, new tables) and only drop columns/tables in a follow-up release.
4. Keep `alembic/versions/` committed to the repository — never edit or delete
   a revision that has already been applied in production.

---

## Migration files in this project

| Revision | Description |
|----------|-------------|
| `001_initial_schema` | Creates `devices` and `visibility_windows` tables |
| `002_reconnect_count` | Adds `reconnect_count` column to `devices` |

---

## Switching to PostgreSQL

1. Start the Postgres container:

   ```bash
   docker compose --profile postgres up -d postgres
   ```

2. Set the URL:

   ```bash
   export DATABASE_URL="postgresql+pg8000://btwifi:btwifi@localhost:5432/btwifi"
   ```

3. Apply migrations:

   ```bash
   alembic upgrade head
   ```

4. Start Net Sentry normally — `init_database()` will use the PostgreSQL URL.

The `purge_old_windows()` function supports both databases; the `VACUUM`
step is **silently skipped** on PostgreSQL (it is not needed in the same way,
and PostgreSQL has its own auto-vacuum daemon).
