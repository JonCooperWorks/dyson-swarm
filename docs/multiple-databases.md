# Multiple Databases

Swarm supports two storage backends behind the same persistence traits:

- SQLite is the default for a single host. It keeps the deploy simple and is
  still the recommended path for the current Dyson host.
- Postgres is for shared or HA deployments where the database must outlive one
  machine and support external backup/replication tooling.

There is no automatic startup migration between backends. Switching databases
is an explicit operator action through `swarmctl db transfer`.

## Selection

Backend selection is controlled by `database_backend` and `database_url` in
`config.toml`. `DatabaseBackend` lives in `crates/core/src/config.rs`, and
`db::open_configured` in `crates/core/src/db/mod.rs` opens either SQLite or
Postgres.

`open_configured` returns one `BackendStores` struct with an `Arc<dyn ...>` for
every persistence trait. Server and CLI code consume that struct instead of a
concrete pool, so a new store method or store trait must compile for both
backends.

## File Map

```text
crates/core/src/db/*.rs        SQLite stores
crates/core/src/db/pg/*.rs     Postgres stores
crates/core/migrations/sqlite  SQLite migrations
crates/core/migrations/postgres Postgres migrations
crates/core/migrations/equivalence.toml dialect-equivalence list
crates/core/build.rs           migration parity check
```

## Parity Guards

Layer A is the store surface. `BackendStores` is constructed once for SQLite
and once for Postgres. If a trait method is added and a Pg store does not
implement it, `cargo build --features postgres` fails.

Layer B is migration parity. `crates/core/build.rs` reads both migration trees,
strips the numeric prefix, compares logical names in order, and emits a
generated `migration_parity.rs`. Adding `migrations/sqlite/0043_foo.sql`
without `migrations/postgres/0043_foo.sql` fails the build with a message like:

```text
migration parity failed; missing postgres migrations: [foo]; missing sqlite migrations: []
```

Dialect-specific SQL differences are listed in `migrations/equivalence.toml`
with pinned SQLite/Postgres fingerprints. If either side changes later, the
build fails until a contributor reviews the logical schema parity and updates
the pinned hash.

## Transfer Command

`db transfer` intentionally lives only on `swarmctl`. The `swarm` server
binary does not expose database maintenance subcommands; keep destructive
operator actions out of the long-running service entry point.

Use:

```sh
swarmctl db transfer \
  --from sqlite \
  --to postgres \
  --source-url /var/lib/dyson-swarm/state.db \
  --target-url postgres://user:pass@host/db \
  --dangerous-confirm-overwrite
```

The command refuses to run without `--dangerous-confirm-overwrite` and prints a
destructive-action banner naming the target URL. The target must be empty
across every app table; there is no `--force`. Both directions are supported,
and the target write is transactional. If the command aborts mid-flight, fix
the cause and rerun after confirming the target is still empty.

The transfer copies raw table rows rather than using the store traits. That
keeps sealed ciphertext, hashes, lookup prefixes, and audit columns byte-faithful.

## Live Switch Runbook

1. Stop `dyson-swarm` and `dyson-egress-proxy`.
2. Snapshot the SQLite file and keep the age key directory with it.
3. Stand up an empty Postgres database.
4. Run `swarmctl db transfer --from sqlite --to postgres ... --dangerous-confirm-overwrite`.
5. Flip `database_backend=postgres` and `database_url` in the deploy config.
6. Redeploy from `deploy/scripts/bring-up.sh`.
7. Run `deploy/scripts/bring-up.sh smoke`.

Do not run transfer implicitly from service startup. A backend switch is an
operator migration, not a boot side effect.
