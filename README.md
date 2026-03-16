# Postgres.jl

Postgres.jl is a PostgreSQL client that implements the v3 wire protocol with `DBInterface` and `Tables` integration.

## Installation

```julia
import Pkg
Pkg.add("Postgres")
```

## Quick start

```julia
using Postgres, DBInterface, Tables
DBInterface.connect(Postgres.Connection, "host=127.0.0.1;port=5432;user=postgres;password=postgres;dbname=postgres") do conn
    rows = Tables.rowtable(DBInterface.execute(conn, "SELECT 1 AS a"))
    @show rows[1].a
end
```

## Connections

```julia
using Postgres, DBInterface
conn = DBInterface.connect(Postgres.Connection, "postgresql://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable")
DBInterface.close!(conn)
```

Connection options support:

- `sslmode` values: `disable`, `prefer`, `require`, `verify-full` (only `verify-full` enforces certificate verification).
- TLS files: `sslrootcert`, `sslcert`, `sslkey`, `sslcapath`.
- `connect_timeout` (seconds) and `statement_timeout` (milliseconds).
- `application_name` and `statement_cache_maxsize`.

You can also use `ConnectionParams`:

```julia
using Postgres, DBInterface
params = Postgres.ConnectionParams(host="127.0.0.1", user="postgres", password="postgres", dbname="postgres", sslmode="disable")
conn = DBInterface.connect(Postgres.Connection, params)
DBInterface.close!(conn)
```

## Queries and prepared statements

```julia
using Postgres, DBInterface, Tables
conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres")
rows = Tables.rowtable(DBInterface.execute(conn, "SELECT $1::int AS val", (42,)))
@show rows[1].val
stmt = DBInterface.prepare(conn, "SELECT $1::int AS val")
rows = Tables.rowtable(DBInterface.execute(stmt, (7,)))
DBInterface.close!(stmt)
DBInterface.close!(conn)
```

Statement caching is LRU-based. Set `statement_cache_maxsize=0` to disable caching.

```julia
using Postgres, DBInterface
conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres"; statement_cache_maxsize=10)
Postgres.set_statement_cache_maxsize!(conn, 5)
cached = Postgres.get_cached_statements(conn)
Postgres.clear_statement_cache!(conn)
DBInterface.close!(conn)
```

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

Nested transactions are implemented with savepoints.

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

`Numeric` values are returned as `Postgres.Numeric` and range types as `Postgres.PostgresRange{T}`.

## Query logging

```julia
using Postgres, DBInterface
conn = DBInterface.connect(Postgres.Connection, "host=127.0.0.1;user=postgres;password=postgres;dbname=postgres")
Postgres.set_query_logger!(conn) do event, info
    @show event info.success info.duration_ns
end
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

`Postgres.Error` represents server errors and includes SQLSTATE codes; `Postgres.PostgresInterfaceError` covers client-side failures. Use `cancel_query!(conn)` to send a CancelRequest to the server.
