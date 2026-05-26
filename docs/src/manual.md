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

## Parameters And Prepared Statements

Use PostgreSQL placeholders (`$1`, `$2`, ...) and pass a tuple or other iterable of parameter values.

```julia
rows = Tables.rowtable(DBInterface.execute(conn, "SELECT $1::int + $2::int AS total", (20, 22)))
@show only(rows).total
```

Prepared statements can be created explicitly. Postgres.jl also caches prepared statements internally with LRU eviction; set `statement_cache_maxsize=0` to disable caching.

```julia
stmt = DBInterface.prepare(conn, "SELECT $1::text AS value")
rows = Tables.rowtable(DBInterface.execute(stmt, ("prepared",)))
DBInterface.close!(stmt)
```

Bulk inserts can use `DBInterface.executemany`.

```julia
DBInterface.execute(conn, "CREATE TEMP TABLE demo_many (id int, name text)")
stmt = DBInterface.prepare(conn, "INSERT INTO demo_many VALUES ($1, $2)")
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

