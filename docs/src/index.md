# Postgres.jl

Postgres.jl is a PostgreSQL client that speaks the v3 wire protocol with `DBInterface` and `Tables` integration.

See the [Manual](@ref) for a guided walk through connections, queries, prepared statements, transactions, cancellation, notifications, and type translation.

## Installation

```julia
import Pkg
Pkg.add("Postgres")
```

## Connection options

Postgres.jl accepts DSN strings or PostgreSQL URIs and supports:

- libpq-style keyword strings such as `host=127.0.0.1 port=5432 user=postgres dbname=postgres`.
- Environment defaults from `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGAPPNAME`, `PGCONNECT_TIMEOUT`, and TLS-related `PGSSL*` variables.
- `sslmode` values: `disable`, `prefer`, `require`, `verify-full` (only `verify-full` verifies certificates).
- TLS files: `sslrootcert`, `sslcert`, `sslkey`, `sslcapath`; `sslservername` overrides the TLS SNI hostname when connecting to a pre-resolved address.
- `connect_timeout` (seconds), `statement_timeout` (milliseconds).
- `application_name` and `statement_cache_maxsize`.

```julia
using Postgres, DBInterface
conn = DBInterface.connect(Postgres.Connection, "postgresql://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable")
DBInterface.close!(conn)
```

## Query execution

```julia
using Postgres, DBInterface, Tables
conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres")
rows = Tables.rowtable(DBInterface.execute(conn, raw"SELECT $1::int AS val", (42,)))
@show rows[1].val
DBInterface.close!(conn)
```

## StructUtils results

Postgres.jl integrates with StructUtils.jl, so query results can be materialized directly as Julia structs.

```julia
using Postgres, DBInterface, StructUtils

struct CountRow
    count::Int
end

row = DBInterface.execute(conn, "SELECT count(*)::int AS count FROM users", (), CountRow)
@show row.count
```

When PostgreSQL column names do not match Julia field names, add field tags in the `postgres` namespace. Postgres.jl's StructUtils style uses those tags while deserializing rows.

```julia
using Dates, Postgres, DBInterface, StructUtils

StructUtils.@tags struct ProfileSummary
    profileId::Int &(postgres=(name=:profile_id,),)
    firstName::Union{Missing, String} &(postgres=(name=:first_name,),)
    lastName::Union{Missing, String} &(postgres=(name=:last_name,),)
    createdAt::DateTime &(postgres=(name=:created_at,),)
end

profile = DBInterface.execute(conn, raw"""
    SELECT profile_id, first_name, last_name, created_at
    FROM profiles
    WHERE profile_id = $1
    """, (profile_id,), ProfileSummary)

profiles = DBInterface.execute(conn, """
    SELECT profile_id, first_name, last_name, created_at
    FROM profiles
    ORDER BY created_at DESC
    LIMIT 10
    """, (), Vector{ProfileSummary})
```

Prepared statements are cached with LRU eviction; disable caching via `statement_cache_maxsize=0`.

```julia
using Postgres, DBInterface, Tables
conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres"; statement_cache_maxsize=5)
stmt = DBInterface.prepare(conn, "SELECT $1::int AS val")
rows = Tables.rowtable(DBInterface.execute(stmt, (7,)))
DBInterface.close!(stmt)
DBInterface.close!(conn)
```

`Postgres.command_tag(result)` and `Postgres.rows_affected(result)` expose PostgreSQL command completion metadata.

## Transactions

```julia
using Postgres, DBInterface
conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres")
Postgres.transaction(conn) do tx
    DBInterface.execute(tx, "CREATE TEMP TABLE tx_demo (id int)")
    DBInterface.execute(tx, "INSERT INTO tx_demo VALUES (1)")
end
Postgres.@transaction conn begin
    DBInterface.execute(conn, "INSERT INTO tx_demo VALUES (2)")
end
DBInterface.close!(conn)
```

## COPY protocol

```julia
using Postgres, DBInterface
conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres")
DBInterface.execute(conn, "CREATE TEMP TABLE copy_demo (id int, name text)")
Postgres.copy_from(conn, "COPY copy_demo (id, name) FROM STDIN", "1\talpha\n2\tbeta\n")
bytes = Postgres.copy_to(conn, "COPY copy_demo TO STDOUT (FORMAT BINARY)")
Postgres.copy_from(conn, "COPY copy_demo FROM STDIN (FORMAT BINARY)", bytes)
DBInterface.close!(conn)
```

## LISTEN/NOTIFY

```julia
using Postgres, DBInterface
listener = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres")
notifier = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres")
Postgres.listen!(listener, "events")
Postgres.notify!(notifier, "events", "hello")
notice = Postgres.wait_for_notification(listener; timeout=5.0)
@show notice.channel notice.payload
DBInterface.close!(notifier)
DBInterface.close!(listener)
```

## Cursor streaming

```julia
using Postgres, DBInterface
conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres")
cur = Postgres.cursor(conn, "SELECT generate_series(1, 5) AS n"; fetchsize=2)
for row in cur
    @show row.n
end
DBInterface.close!(cur)
DBInterface.close!(conn)
```

## Type registry

```julia
using Postgres, DBInterface, Tables
conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres")
DBInterface.execute(conn, "CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')")
Postgres.register_enum!(conn, "mood")
row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT 'happy'::mood AS mood")))
@show row.mood
DBInterface.close!(conn)
```

`Numeric` values are represented by `Postgres.Numeric`, `interval` values by `Dates.Period` or `Dates.CompoundPeriod`, and range types by `Postgres.PostgresRange{T}`.

## Query logging

Query logging (and other driver behavior) is customized with a driver style; see the [Manual](@ref) for details.

```julia
using Postgres, DBInterface

struct LoggingStyle <: Postgres.AbstractPostgresStyle end
Postgres.query_logging_enabled(::LoggingStyle) = true
Postgres.query_logger(::LoggingStyle, event::Symbol, info::NamedTuple) = @info "query" event info.success info.duration_ns

conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres"; style=LoggingStyle())
DBInterface.execute(conn, "SELECT 1")
DBInterface.close!(conn)
```

## Connection pooling

```julia
using Postgres, DBInterface
pool = Postgres.ConnectionPool(Postgres.Connection, "127.0.0.1", "postgres", "postgres"; dbname="postgres", limit=5)
Postgres.with_connection(pool) do conn
    DBInterface.execute(conn, "SELECT 1")
end
DBInterface.close!(pool)
```

## Errors and cancellation

`Postgres.Error` includes SQLSTATE information. Use `Postgres.cancel_query!(conn)` to cancel a running query.

## Reference

```@autodocs
Modules = [Postgres]
```

```@docs
Postgres.Error
Postgres.Notification
Postgres.Numeric
Postgres.PostgresRange
Postgres.ConnectionParams
Postgres.parse_dsn
```
