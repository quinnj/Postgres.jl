using Test
using Dates
using UUIDs
using DBInterface
using Tables
using StructUtils
using JSON
using Harbor
using Postgres
using Sockets

# Integration tests for Postgres.jl protocol and API behavior.
const JSONType = typeof(JSON.lazy("{}"))
const IMAGE_REF = get(ENV, "POSTGRES_IMAGE", "postgres:16")
const DEFAULT_USER = get(ENV, "POSTGRES_USER", "postgres")
const DEFAULT_PASSWORD = get(ENV, "POSTGRES_PASSWORD", "postgres")
const DEFAULT_DB = get(ENV, "POSTGRES_DB", "postgres")
const DEFAULT_AUTH = get(ENV, "POSTGRES_HOST_AUTH_METHOD", "trust")
const DEFAULT_INITDB_ARGS = get(ENV, "POSTGRES_INITDB_ARGS", "--auth-host=trust")

StructUtils.@defaults struct TypeRow
    id::Int = 0
    smallint_col::Int16 = 0
    int_col::Int32 = 0
    bigint_col::Int64 = 0
    oid_col::Cuint = 0
    bool_col::Bool = false
    float4_col::Float32 = 0
    float8_col::Float64 = 0
    numeric_col::Postgres.Numeric = Postgres.Numeric(BigInt(0), 0)
    text_col::String = ""
    varchar_col::String = ""
    bpchar_col::String = ""
    uuid_col::UUID = UUID("00000000-0000-0000-0000-000000000000")
    date_col::Date = Date(0)
    time_col::Time = Time(0)
    ts_col::DateTime = DateTime(0)
    tstz_col::DateTime = DateTime(0)
    json_col::JSONType = JSON.lazy("{}")
    jsonb_col::JSONType = JSON.lazy("{}")
    bytea_col::Vector{UInt8} = UInt8[]
    char_col::Char = '\0'
    bit_col::Bool = false
    nullable_text::Union{Missing, String} = missing
    int_array::Vector{Int32} = Int32[]
end

struct PgConfig
    host::String
    port::Int
    user::String
    password::String
    dbname::String
end

function parse_image_ref(ref::String)
    parts = split(ref, ":"; limit=2)
    length(parts) == 2 && return String(parts[1]), String(parts[2])
    return String(parts[1]), "latest"
end

function docker_available()
    Sys.which("docker") === nothing && return false
    try
        run(pipeline(`docker info`, stdout=devnull, stderr=devnull))
        return true
    catch
        return false
    end
end

function pick_port()
    server = Sockets.listen(Sockets.IPv4(0), 0)
    _, port = Sockets.getsockname(server)
    port = Int(port)
    close(server)
    return port
end

function wait_for_connection(cfg::PgConfig; timeout::Float64=60.0)
    start_time = time()
    last_err = nothing
    while time() - start_time < timeout
        try
            return DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port)
        catch err
            last_err = err
            sleep(0.5)
        end
    end
    last_err === nothing && error("Postgres did not become ready")
    error("Postgres did not become ready: $(sprint(showerror, last_err))")
end

function with_postgres(f::Function)
    image, tag = parse_image_ref(IMAGE_REF)
    host_port = pick_port()
    env = Dict(
        "POSTGRES_USER" => DEFAULT_USER,
        "POSTGRES_PASSWORD" => DEFAULT_PASSWORD,
        "POSTGRES_DB" => DEFAULT_DB,
        "POSTGRES_HOST_AUTH_METHOD" => DEFAULT_AUTH,
        "POSTGRES_INITDB_ARGS" => DEFAULT_INITDB_ARGS,
    )
    Harbor.with_container(image; tag=tag, ports=Dict(5432 => host_port), environment=env) do _
        cfg = PgConfig("127.0.0.1", host_port, DEFAULT_USER, DEFAULT_PASSWORD, DEFAULT_DB)
        return f(cfg)
    end
end

function setup_types(conn::Postgres.Connection)
    DBInterface.execute(conn, "DROP TABLE IF EXISTS types_test")
    DBInterface.execute(conn, """
CREATE TABLE types_test (
    id SERIAL PRIMARY KEY,
    smallint_col SMALLINT,
    int_col INTEGER,
    bigint_col BIGINT,
    oid_col OID,
    bool_col BOOLEAN,
    float4_col REAL,
    float8_col DOUBLE PRECISION,
    numeric_col NUMERIC,
    text_col TEXT,
    varchar_col VARCHAR(10),
    bpchar_col CHAR(3),
    uuid_col UUID,
    date_col DATE,
    time_col TIME,
    ts_col TIMESTAMP,
    tstz_col TIMESTAMPTZ,
    json_col JSON,
    jsonb_col JSONB,
    bytea_col BYTEA,
    char_col "char",
    bit_col BIT(1),
    nullable_text TEXT,
    int_array INT[]
)
""")
    smallint_val = Int16(7)
    int_val = Int32(42)
    bigint_val = Int64(9_000_000_000)
    oid_val = Cuint(1234)
    bool_val = true
    float4_val = Float32(1.25)
    float8_val = 2.5
    numeric_val = Postgres.API.parse_numeric("12345.6789")
    text_val = "hello"
    varchar_val = "world"
    bpchar_val = "abc"
    uuid_val = UUID("12345678-1234-5678-1234-567812345678")
    date_val = Date(2024, 1, 28)
    time_val = Time(12, 34, 56)
    ts_val = DateTime(2024, 1, 28, 21, 30, 15)
    tstz_val = "2024-02-13 05:28:17+02"
    json_val = JSON.json(Dict("a" => 1, "b" => "two"))
    jsonb_val = JSON.json(Dict("x" => true))
    bytea_hex = "DEADBEEF"
    char_val = "Z"
    bit_val = "1"
    nullable_val = missing
    array_val = Int32[1, 2, 3]
    insert_sql = raw"""
INSERT INTO types_test (
    smallint_col,
    int_col,
    bigint_col,
    oid_col,
    bool_col,
    float4_col,
    float8_col,
    numeric_col,
    text_col,
    varchar_col,
    bpchar_col,
    uuid_col,
    date_col,
    time_col,
    ts_col,
    tstz_col,
    json_col,
    jsonb_col,
    bytea_col,
    char_col,
    bit_col,
    nullable_text,
    int_array
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    $10,
    $11,
    $12,
    $13,
    $14,
    $15,
    $16,
    $17::json,
    $18::jsonb,
    decode($19, 'hex'),
    $20::"char",
    $21::bit(1),
    $22,
    $23::int[]
) RETURNING id
"""
    params = (
        smallint_val,
        int_val,
        bigint_val,
        oid_val,
        bool_val,
        float4_val,
        float8_val,
        numeric_val,
        text_val,
        varchar_val,
        bpchar_val,
        uuid_val,
        date_val,
        time_val,
        ts_val,
        tstz_val,
        json_val,
        jsonb_val,
        bytea_hex,
        char_val,
        bit_val,
        nullable_val,
        array_val,
    )
    res = DBInterface.execute(conn, insert_sql, params)
    id = only(Tables.rowtable(res)).id
    expected = (
        smallint_val,
        int_val,
        bigint_val,
        oid_val,
        bool_val,
        float4_val,
        float8_val,
        numeric_val,
        text_val,
        varchar_val,
        bpchar_val,
        uuid_val,
        date_val,
        time_val,
        ts_val,
        DateTime(2024, 2, 13, 3, 28, 17),
        json_val,
        jsonb_val,
        UInt8[0xde, 0xad, 0xbe, 0xef],
        'Z',
        true,
        nullable_val,
        array_val,
    )
    return id, expected
end

@testset "Postgres" begin
    if !docker_available()
        @info "Docker not available; skipping Postgres integration tests."
        @test true
    else
        with_postgres() do cfg
            conn = wait_for_connection(cfg)
            try
                @testset "Auth" begin
                    if occursin("trust", DEFAULT_AUTH) || occursin("trust", DEFAULT_INITDB_ARGS)
                        conn_trust = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, nothing; dbname=cfg.dbname, port=cfg.port)
                        @test isopen(conn_trust)
                        DBInterface.close!(conn_trust)
                    else
                        @test_throws Postgres.API.Error DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, "wrong"; dbname=cfg.dbname, port=cfg.port)
                    end
                    @test isopen(conn)
                end
                @testset "Connection Lifecycle" begin
                    conn2 = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port)
                    @test isopen(conn2)
                    DBInterface.close!(conn2)
                    @test !isopen(conn2)
                    DBInterface.close!(conn2)
                end
                @testset "Reconnect" begin
                    conn3 = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, reconnect=true)
                    close(conn3.socket)
                    rows = Tables.rowtable(DBInterface.execute(conn3, "SELECT 1 AS a"))
                    @test rows[1].a == 1
                    DBInterface.close!(conn3)
                end
                @testset "Reconnect Disabled" begin
                    conn4 = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, reconnect=false)
                    close(conn4.socket)
                    @test_throws Postgres.PostgresInterfaceError DBInterface.execute(conn4, "SELECT 1")
                    DBInterface.close!(conn4)
                end
                @testset "Prepared Statements" begin
                    stmt = DBInterface.prepare(conn, raw"SELECT $1::int AS val")
                    res = Tables.rowtable(DBInterface.execute(stmt, (1,)))
                    @test res[1].val == 1
                    DBInterface.close!(stmt)
                    @test_throws Postgres.PostgresInterfaceError DBInterface.execute(stmt, (1,))
                end
                @testset "Result Handling" begin
                    res = DBInterface.execute(conn, "SELECT 1 AS a, 2 AS b")
                    rows = Tables.rowtable(res)
                    @test length(rows) == 1
                    @test rows[1].a == 1
                    @test rows[1].b == 2
                end
                @testset "Type Parsing" begin
                    id, expected = setup_types(conn)
                    row = only(Tables.rowtable(DBInterface.execute(conn, raw"SELECT * FROM types_test WHERE id = $1", (id,))))
                    @test row.smallint_col == expected[1]
                    @test row.int_col == expected[2]
                    @test row.bigint_col == expected[3]
                    @test row.oid_col == expected[4]
                    @test row.bool_col == expected[5]
                    @test isapprox(row.float4_col, expected[6]; rtol=1e-6)
                    @test isapprox(row.float8_col, expected[7]; rtol=1e-12)
                    @test row.numeric_col == expected[8]
                    @test row.text_col == expected[9]
                    @test row.varchar_col == expected[10]
                    @test strip(row.bpchar_col) == expected[11]
                    @test row.uuid_col == expected[12]
                    @test row.date_col == expected[13]
                    @test row.time_col == expected[14]
                    @test row.ts_col == expected[15]
                    @test row.tstz_col == expected[16]
                    @test JSON.parse(row.json_col)["a"] == 1
                    @test JSON.parse(row.jsonb_col)["x"] == true
                    @test row.bytea_col == expected[19]
                    @test row.char_col == expected[20]
                    @test row.bit_col == expected[21]
                    @test ismissing(row.nullable_text)
                @test row.int_array == expected[23]
                @test eltype(row.int_array) == Int32
                array_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '{1,NULL,3}'::int[] AS arr")))
                @test isequal(array_row.arr, Union{Missing, Int32}[1, missing, 3])
                nested_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '{{1,2},{3,4}}'::int[] AS arr")))
                @test nested_row.arr == [Int32[1, 2], Int32[3, 4]]
                    typed = DBInterface.execute(conn, raw"SELECT * FROM types_test WHERE id = $1", (id,), TypeRow)
                    @test typed isa TypeRow
                    @test typed.uuid_col == expected[12]
                    @test typed.bytea_col == expected[19]
                    @test JSON.parse(typed.json_col)["a"] == 1
                    @test JSON.parse(typed.jsonb_col)["x"] == true
                @test typed.int_array == expected[23]
                end

                @testset "Type Registry" begin
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS custom_types")
                    DBInterface.execute(conn, "DROP TYPE IF EXISTS mood")
                    DBInterface.execute(conn, "DROP TYPE IF EXISTS address")
                    DBInterface.execute(conn, "CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')")
                    DBInterface.execute(conn, "CREATE TYPE address AS (street text, number int)")
                    DBInterface.execute(conn, "CREATE TABLE custom_types (id serial primary key, mood mood, addr address, span int4range)")
                    DBInterface.execute(conn, "INSERT INTO custom_types (mood, addr, span) VALUES ('happy', ROW('Main', 10), '[1,5)')")
                    Postgres.register_enum!(conn, "mood"; schema="public", julia_type=Symbol)
                    Postgres.register_composite!(conn, "address"; schema="public")
                    Postgres.register_range!(conn, "int4range"; schema="pg_catalog")
                    row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT mood, addr, span FROM custom_types")))
                    @test row.mood == :happy
                    @test row.addr.street == "Main"
                    @test row.addr.number == 10
                    @test row.span.lower == 1
                    @test row.span.upper == 5
                    @test row.span.lower_inclusive
                    @test !row.span.upper_inclusive
                end
                @testset "Transactions" begin
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS trans_test")
                    DBInterface.execute(conn, "CREATE TABLE trans_test (id SERIAL PRIMARY KEY, value INTEGER)")
                    DBInterface.execute(conn, "INSERT INTO trans_test (value) VALUES (1)")
                    DBInterface.execute(conn, "INSERT INTO trans_test (value) VALUES (2)")

                    Postgres.start_transaction(conn)
                    DBInterface.execute(conn, "INSERT INTO trans_test (value) VALUES (3)")
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM trans_test"))) == 3
                    Postgres.rollback(conn)
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM trans_test"))) == 2

                    Postgres.start_transaction(conn)
                    DBInterface.execute(conn, "INSERT INTO trans_test (value) VALUES (4)")
                    Postgres.commit(conn)
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM trans_test"))) == 3

                    @test_throws Postgres.PostgresInterfaceError Postgres.commit(conn)
                    @test_throws Postgres.PostgresInterfaceError Postgres.rollback(conn)

                    Postgres.start_transaction(conn)
                    @test_throws Postgres.API.Error DBInterface.execute(conn, "INVALID SQL")
                    Postgres.rollback(conn)
                end

                @testset "Transaction Macro" begin
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS macro_test")
                    DBInterface.execute(conn, "CREATE TABLE macro_test (id SERIAL PRIMARY KEY, value INTEGER)")
                    DBInterface.execute(conn, "INSERT INTO macro_test (value) VALUES (1)")

                    result = Postgres.@transaction conn begin
                        DBInterface.execute(conn, "INSERT INTO macro_test (value) VALUES (2)")
                        length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM macro_test")))
                    end
                    @test result == 2

                    @test_throws Postgres.API.Error Postgres.@transaction conn begin
                        DBInterface.execute(conn, "INSERT INTO macro_test (value) VALUES (3)")
                        DBInterface.execute(conn, "INVALID SQL")
                    end
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM macro_test"))) == 2
                end

                @testset "Nested Transactions" begin
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS nested_test")
                    DBInterface.execute(conn, "CREATE TABLE nested_test (id SERIAL PRIMARY KEY, value INTEGER)")

                    Postgres.start_transaction(conn)
                    DBInterface.execute(conn, "INSERT INTO nested_test (value) VALUES (1)")

                    Postgres.start_transaction(conn)
                    DBInterface.execute(conn, "INSERT INTO nested_test (value) VALUES (2)")
                    Postgres.rollback(conn)
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM nested_test"))) == 1

                    Postgres.start_transaction(conn)
                    DBInterface.execute(conn, "INSERT INTO nested_test (value) VALUES (3)")
                    Postgres.commit(conn)
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM nested_test"))) == 2

                    Postgres.commit(conn)
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM nested_test"))) == 2
                end

                @testset "Connection Ergonomics" begin
                    params = Postgres.ConnectionParams(
                        host=cfg.host,
                        port=cfg.port,
                        user=cfg.user,
                        password=cfg.password,
                        dbname=cfg.dbname
                    )
                    conn2 = DBInterface.connect(Postgres.Connection, params)
                    @test isopen(conn2)
                    DBInterface.close!(conn2)

                    params_with_app = Postgres.ConnectionParams(
                        host=cfg.host,
                        port=cfg.port,
                        user=cfg.user,
                        password=cfg.password,
                        dbname=cfg.dbname,
                        application_name="test_app"
                    )
                    conn3 = DBInterface.connect(Postgres.Connection, params_with_app)
                    @test isopen(conn3)
                    DBInterface.close!(conn3)
                end

                @testset "SSL Modes" begin
                    conn_disable = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, sslmode="disable")
                    @test isopen(conn_disable)
                    DBInterface.close!(conn_disable)
                    @test_throws Postgres.API.Error DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, sslmode="require")
                    @test_throws Postgres.API.Error DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, sslmode="verify-full")
                end

                @testset "Statement Cache Controls" begin
                    conn_cache = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, statement_cache_maxsize=3)
                    @test conn_cache.statement_cache_maxsize == 3
                    stmt1 = DBInterface.prepare(conn_cache, "SELECT 1")
                    stmt2 = DBInterface.prepare(conn_cache, "SELECT 2")
                    stmt3 = DBInterface.prepare(conn_cache, "SELECT 3")
                    DBInterface.execute(stmt1)
                    DBInterface.execute(stmt2)
                    DBInterface.execute(stmt3)
                    @test length(Postgres.get_cached_statements(conn_cache)) == 3
                    DBInterface.execute(stmt1)
                    stmt4 = DBInterface.prepare(conn_cache, "SELECT 4")
                    DBInterface.execute(stmt4)
                    @test length(Postgres.get_cached_statements(conn_cache)) == 3
                    cached = Postgres.get_cached_statements(conn_cache)
                    @test haskey(cached, "SELECT 1")
                    @test !haskey(cached, "SELECT 2")
                    Postgres.set_statement_cache_maxsize!(conn_cache, 5)
                    @test conn_cache.statement_cache_maxsize == 5
                    stmt5 = DBInterface.prepare(conn_cache, "SELECT 5")
                    DBInterface.execute(stmt5)
                    @test length(Postgres.get_cached_statements(conn_cache)) == 4
                    Postgres.set_statement_cache_maxsize!(conn_cache, 0)
                    @test length(Postgres.get_cached_statements(conn_cache)) == 0
                    stmt6 = DBInterface.prepare(conn_cache, "SELECT 6")
                    DBInterface.execute(stmt6)
                    @test length(Postgres.get_cached_statements(conn_cache)) == 0
                    DBInterface.close!(stmt6)
                    Postgres.clear_statement_cache!(conn_cache)
                    @test length(Postgres.get_cached_statements(conn_cache)) == 0
                    DBInterface.close!(conn_cache)
                end

                @testset "Do-Block Helpers" begin
                    saved = Ref{Postgres.Connection}()
                    DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port) do block_conn
                        saved[] = block_conn
                        @test isopen(block_conn)
                        rows = Tables.rowtable(DBInterface.execute(block_conn, "SELECT 1 AS a"))
                        @test rows[1].a == 1
                    end
                    @test saved[] !== nothing
                    @test !isopen(saved[])
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS tx_do")
                    DBInterface.execute(conn, "CREATE TABLE tx_do (id INT)")
                    Postgres.transaction(conn) do tx_conn
                        DBInterface.execute(tx_conn, "INSERT INTO tx_do (id) VALUES (1)")
                    end
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM tx_do"))) == 1
                    @test_throws Postgres.API.Error Postgres.transaction(conn) do tx_conn
                        DBInterface.execute(tx_conn, "INSERT INTO tx_do (id) VALUES (2)")
                        DBInterface.execute(tx_conn, "INVALID SQL")
                    end
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM tx_do"))) == 1
                end

                @testset "Query Logger" begin
                    events = NamedTuple[]
                    previous = Postgres.get_query_logger(conn)
                    Postgres.set_query_logger!(conn, (event, info) -> begin
                        push!(events, (event=event, info=info))
                        return
                    end)
                    rows = Tables.rowtable(DBInterface.execute(conn, "SELECT 1 AS a"))
                    @test rows[1].a == 1
                    @test !isempty(events)
                    @test events[end].event == :execute
                    @test events[end].info.success
                    @test_throws Postgres.API.Error DBInterface.execute(conn, "INVALID SQL")
                    @test !events[end].info.success
                    Postgres.set_query_logger!(conn, previous)
                end

                @testset "Connection Pool" begin
                    pool = Postgres.ConnectionPool(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, limit=1)
                    conn_a = Postgres.acquire(pool)
                    @test isopen(conn_a)
                    Postgres.release(pool, conn_a)
                    conn_b = Postgres.acquire(pool)
                    @test conn_a === conn_b
                    Postgres.release(pool, conn_b)
                    pooled_result = Postgres.with_connection(pool) do pooled_conn
                        rows = Tables.rowtable(DBInterface.execute(pooled_conn, "SELECT 1 AS a"))
                        return rows[1].a
                    end
                    @test pooled_result == 1
                    DBInterface.close!(pool)
                    @test !isopen(conn_a)
                end

                @testset "Transaction Prevents Reconnect" begin
                    tx_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, reconnect=true)
                    Postgres.start_transaction(tx_conn)
                    close(tx_conn.socket)
                    @test_throws Postgres.PostgresInterfaceError DBInterface.execute(tx_conn, "SELECT 1")
                    DBInterface.close!(tx_conn)
                end

                @testset "Reconnect Preserves Application Name" begin
                    app_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, reconnect=true, application_name="reconnect_test")
                    close(app_conn.socket)
                    rows = Tables.rowtable(DBInterface.execute(app_conn, "SELECT current_setting('application_name') AS app_name"))
                    @test rows[1].app_name == "reconnect_test"
                    DBInterface.close!(app_conn)
                end

                @testset "Statement Timeout" begin
                    timeout_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, statement_timeout=200)
                    @test_throws Postgres.API.Error DBInterface.execute(timeout_conn, "SELECT pg_sleep(1)")
                    Postgres.set_statement_timeout!(timeout_conn, 0)
                    rows = Tables.rowtable(DBInterface.execute(timeout_conn, "SELECT 1 AS a"))
                    @test rows[1].a == 1
                    DBInterface.close!(timeout_conn)
                end

                @testset "Listen/Notify" begin
                    listener = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port)
                    notifier = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port)
                    Postgres.listen!(listener, "notify_test")
                    Postgres.notify!(notifier, "notify_test", "payload")
                    notification = Postgres.wait_for_notification(listener; timeout=5.0)
                    @test notification !== nothing
                    @test notification.channel == "notify_test"
                    @test notification.payload == "payload"
                    DBInterface.close!(notifier)
                    DBInterface.close!(listener)
                end

                @testset "Copy Protocol" begin
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS copy_test")
                    DBInterface.execute(conn, "CREATE TABLE copy_test (id INT, name TEXT)")
                    Postgres.copy_from(conn, "COPY copy_test (id, name) FROM STDIN", "1\talpha\n2\tbeta\n")
                    rows = Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM copy_test ORDER BY id"))
                    @test rows[1].id == 1
                    @test rows[1].name == "alpha"
                    @test rows[2].id == 2
                    @test rows[2].name == "beta"
                    text_copy = String(Postgres.copy_to(conn, "COPY copy_test TO STDOUT"))
                    @test occursin("alpha", text_copy)
                    binary_copy = Postgres.copy_to(conn, "COPY copy_test TO STDOUT (FORMAT BINARY)")
                    @test length(binary_copy) > 11
                    @test binary_copy[1:11] == UInt8[0x50, 0x47, 0x43, 0x4f, 0x50, 0x59, 0x0a, 0xff, 0x0d, 0x0a, 0x00]
                    DBInterface.execute(conn, "TRUNCATE copy_test")
                    Postgres.copy_from(conn, "COPY copy_test FROM STDIN (FORMAT BINARY)", binary_copy)
                    rows2 = Tables.rowtable(DBInterface.execute(conn, "SELECT count(*) AS count FROM copy_test"))
                    @test rows2[1].count == 2
                end

                @testset "Cursor Streaming" begin
                    cur = Postgres.cursor(conn, "SELECT generate_series(1, 5) AS n"; fetchsize=2)
                    values = [row.n for row in cur]
                    @test values == [1, 2, 3, 4, 5]
                    DBInterface.close!(cur)
                end

                @testset "Notice Callback" begin
                    notice_seen = Ref(false)
                    previous = Postgres.get_notice_callback(conn)
                    Postgres.set_notice_callback!(conn, notice -> begin
                        notice_seen[] = true
                        return
                    end)
                    DBInterface.execute(conn, raw"DO $$ BEGIN RAISE NOTICE 'hello'; END $$;")
                    Postgres.set_notice_callback!(conn, previous)
                    @test notice_seen[]
                end

                @testset "Cancel Request" begin
                    cancel_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port)
                    task = errormonitor(Threads.@spawn begin
                        try
                            DBInterface.execute(cancel_conn, "SELECT pg_sleep(5)")
                            return :completed
                        catch err
                            return err
                        end
                    end)
                    sleep(0.5)
                    Postgres.cancel_query!(cancel_conn)
                    result = fetch(task)
                    @test result isa Postgres.API.Error
                    @test result.code == "57014"
                    DBInterface.close!(cancel_conn)
                end

                @testset "Unsupported Types" begin
                    interval_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '1 day'::interval AS interval_col")))
                    @test interval_row.interval_col isa String
                    @test_broken interval_row.interval_col isa Dates.Period
                end
            finally
                isopen(conn) && DBInterface.close!(conn)
            end
        end
    end
end
