# Manual

Postgres.jl intentionally keeps its export surface small: `using Postgres` re-exports `DBInterface`, while package-specific APIs are accessed through the `Postgres.` namespace.

## Connecting

Use `DBInterface.connect` with either a PostgreSQL URI, a libpq-style keyword string, or explicit host/user/password arguments.

```julia
using Postgres, Tables

conn = DBInterface.connect(
    Postgres.Connection,
    "postgresql://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
)

DBInterface.close!(conn)
```

Keyword DSNs and environment defaults are also supported.

```julia
conn = DBInterface.connect(
    Postgres.Connection,
    "host=127.0.0.1 port=5432 user=postgres password=postgres dbname=postgres",
)
```

## Querying

`DBInterface.execute` returns a Tables.jl-compatible result. For small result sets, `Tables.rowtable` is a convenient way to materialize rows.

```julia
rows = Tables.rowtable(DBInterface.execute(conn, "SELECT 1 AS id, 'hello' AS label"))
row = only(rows)
@show row.id row.label
```

The result object can also be iterated directly.

```julia
for row in DBInterface.execute(conn, "SELECT generate_series(1, 3) AS n")
    @show row.n
end
```

PostgreSQL command completion metadata is available on the result.

```julia
result = DBInterface.execute(conn, "UPDATE items SET seen = true WHERE seen = false")
@show Postgres.command_tag(result)
@show Postgres.rows_affected(result)
```

## Typed Results With StructUtils

Postgres.jl result sets implement the StructUtils.jl interface. That means `DBInterface.execute` can deserialize rows directly into a target type instead of first materializing `Tables.rowtable` rows.

For a single-row query, pass a concrete struct type as the fourth argument. The query should return exactly one row.

```julia
using Postgres, StructUtils

struct CountRow
    count::Int
end

row = DBInterface.execute(conn, "SELECT count(*)::int AS count FROM users", (), CountRow)
@show row.count
```

For multi-row queries, pass a vector type.

```julia
struct UserName
    id::Int
    name::String
end

users = DBInterface.execute(conn, "SELECT id, name FROM users ORDER BY id", (), Vector{UserName})
```

StructUtils field tags let Julia models keep idiomatic field names while SQL keeps idiomatic column names. Tags for Postgres.jl live under the `postgres` namespace.

```julia
using Dates, Postgres, StructUtils

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

The `postgres=(name=:column_name,)` tag is only needed when a column should map to a differently named field. Columns such as `id` or `name` can be left untagged because they already match the Julia field name.

### Driver Styles

Connection behavior such as query logging, server notices, and asynchronous
notifications is selected by a concrete driver style. Subtype
`Postgres.AbstractPostgresStyle`, overload the documented behavior hooks for
that style, and pass an instance with the `style` connection keyword. The
default `Postgres.PostgresStyle` keeps query logging disabled and reports
server notices through Julia's logger.

```julia
struct LoggingStyle <: Postgres.AbstractPostgresStyle end
Postgres.query_logging_enabled(::LoggingStyle) = true
Postgres.query_logger(::LoggingStyle, event::Symbol, info::NamedTuple) = @info "query" event info.success info.duration_ns
Postgres.notice_callback(::LoggingStyle, notice) = @info "notice" notice
Postgres.notification_callback(::LoggingStyle, notification) = @info "notification" notification

conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1 user=postgres dbname=postgres"; style=LoggingStyle())
```

`query_logger`'s `info` includes the SQL and the bound parameter values, so a logger that writes them out records whatever sensitive data those queries carry. Redact or omit `info.params` when the log destination is less trusted than the database itself.

```@docs
Postgres.AbstractPostgresStyle
Postgres.PostgresStyle
Postgres.query_logging_enabled
Postgres.query_logger
Postgres.notice_callback
Postgres.notification_callback
```

## Parameters And Prepared Statements

Use PostgreSQL placeholders (`$1`, `$2`, ...) and pass a tuple or other iterable of parameter values. Note the use of `raw"..."` strings so that `$1` is not treated as Julia string interpolation.

```julia
rows = Tables.rowtable(DBInterface.execute(conn, raw"SELECT $1::int + $2::int AS total", (20, 22)))
@show only(rows).total
```

Prepared statements can be created explicitly. Postgres.jl also caches prepared statements internally with LRU eviction; set `statement_cache_maxsize=0` to disable caching.

```julia
stmt = DBInterface.prepare(conn, raw"SELECT $1::text AS value")
rows = Tables.rowtable(DBInterface.execute(stmt, ("prepared",)))
DBInterface.close!(stmt)
```

Bulk inserts can use `DBInterface.executemany`.

```julia
DBInterface.execute(conn, "CREATE TEMP TABLE demo_many (id int, name text)")
stmt = DBInterface.prepare(conn, raw"INSERT INTO demo_many VALUES ($1, $2)")
DBInterface.executemany(stmt, ([1, 2, 3], ["a", "b", "c"]))
DBInterface.close!(stmt)
```

## Transactions

Postgres.jl supports both its connection-passing helper and the DBInterface transaction API.

```julia
Postgres.transaction(conn) do tx
    DBInterface.execute(tx, "CREATE TEMP TABLE tx_demo (id int)")
    DBInterface.execute(tx, "INSERT INTO tx_demo VALUES (1)")
end
```

```julia
DBInterface.transaction(conn) do
    DBInterface.execute(conn, "INSERT INTO tx_demo VALUES (2)")
end
```

Nested transactions use savepoints.

## Streaming Results

For larger result sets, `Postgres.cursor` fetches rows in batches.

```julia
cur = Postgres.cursor(conn, "SELECT generate_series(1, 1000) AS n"; fetchsize=100)
try
    for row in cur
        @show row.n
    end
finally
    DBInterface.close!(cur)
end
```

## COPY

Use `Postgres.copy_from` and `Postgres.copy_to` for PostgreSQL's COPY protocol.

```julia
DBInterface.execute(conn, "CREATE TEMP TABLE copy_demo (id int, name text)")
Postgres.copy_from(conn, "COPY copy_demo (id, name) FROM STDIN", "1\talpha\n2\tbeta\n")
bytes = Postgres.copy_to(conn, "COPY copy_demo TO STDOUT")
```

## Cancellation

`Postgres.cancel_query!` sends a PostgreSQL CancelRequest for a running query on another task.

```julia
task = Threads.@spawn DBInterface.execute(conn, "SELECT pg_sleep(10)")
sleep(0.5)
Postgres.cancel_query!(conn)
```

The running query raises a `Postgres.Error` with PostgreSQL SQLSTATE `57014`.

## LISTEN And NOTIFY

Use one connection to listen and another to notify.

```julia
listener = DBInterface.connect(Postgres.Connection, "host=127.0.0.1 user=postgres password=postgres dbname=postgres")
notifier = DBInterface.connect(Postgres.Connection, "host=127.0.0.1 user=postgres password=postgres dbname=postgres")

Postgres.listen!(listener, "events")
Postgres.notify!(notifier, "events", "hello")
notification = Postgres.wait_for_notification(listener; timeout=5.0)
@show notification.channel notification.payload

DBInterface.close!(notifier)
DBInterface.close!(listener)
```

## Type Translation

Postgres.jl maps common PostgreSQL types to Julia values:

- integers, floats, booleans, text, UUIDs, dates, times, timestamps, and bytea map to their natural Julia types.
- `json` and `jsonb` are returned as lazy JSON values from JSON.jl.
- `numeric` maps to `Postgres.Numeric` to preserve decimal scale.
- `interval` maps to `Dates.Period` or `Dates.CompoundPeriod`.
- arrays map to Julia arrays, preserving `missing` for SQL `NULL`.
- PostgreSQL range types map to `Postgres.PostgresRange{T}`.

Custom enum, composite, and range types can be registered on a connection.

```julia
DBInterface.execute(conn, "CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')")
Postgres.register_enum!(conn, "mood"; julia_type=Symbol)

row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT 'happy'::mood AS mood")))
@show row.mood
```

Registering composite and range types follows the same pattern.

### Session Formats

Text decoding assumes the server renders dates and timestamps in the `ISO`
`DateStyle` output format and intervals in the `postgres` `IntervalStyle`. The
driver checks the server-reported settings at connect time and issues a `SET`
for any that differ, preserving the configured date field order (`MDY`/`DMY`/
`YMD`) since it decides how ambiguous input literals like `'01/02/2020'` are
read. The alignment is re-applied on reconnect, but not if the session is
changed afterwards: running `SET DateStyle = ...` or `SET IntervalStyle = ...`
mid-session breaks decoding — intervals and unparseable dates raise errors
rather than silently returning wrong values.

### Values Without A Julia Representation

A few PostgreSQL values have no faithful Julia equivalent and raise
`Postgres.PostgresInterfaceError` when decoded rather than silently returning
a wrong value: `infinity`/`-infinity` dates and timestamps, dates in the BC
era, and `numeric` `NaN`/`infinity`. `"char"` columns (the 1-byte internal
catalog type) decode to `Char`, including the zero byte (`'\0'`) and high-bit
bytes; note that a `'\0'` read from such a column cannot be bound back as a
text parameter, because PostgreSQL rejects NUL bytes in text — write it with
an explicit cast such as `0::"char"` instead.
