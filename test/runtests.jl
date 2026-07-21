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
using Random

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

struct Int8Row
    x::Int8
    s::String
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
        os_type = strip(read(`docker info --format "{{.OSType}}"`, String))
        return os_type == "linux"
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

function wait_for_connection(cfg::PgConfig; timeout::Float64=60.0, sslmode::Union{Nothing, String}=nothing, sslrootcert::Union{Nothing, String}=nothing)
    start_time = time()
    last_err = nothing
    while time() - start_time < timeout
        try
            return DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, connect_timeout=2, sslmode=sslmode, sslrootcert=sslrootcert)
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
    Harbor.with_container(
        image;
        tag=tag,
        ports=Dict(5432 => host_port),
        environment=env,
        wait_strategy=(pattern="database system is ready to accept connections",),
    ) do _
        cfg = PgConfig("127.0.0.1", host_port, DEFAULT_USER, DEFAULT_PASSWORD, DEFAULT_DB)
        return f(cfg)
    end
end

function run_openssl(args::String...)
    openssl = Sys.which("openssl")
    openssl === nothing && error("OpenSSL executable not found")
    run(pipeline(Cmd([openssl, args...]); stdout=devnull, stderr=devnull))
end

function ssl_postgres_command()
    setup_script = """
set -eu
certdir=/tmp/postgres-jl-certs
mkdir -p "\$certdir"
cp /certs/server.crt "\$certdir/server.crt"
cp /certs/server.key "\$certdir/server.key"
cp /certs/root.crt "\$certdir/root.crt"
chown postgres:postgres "\$certdir/server.crt" "\$certdir/server.key" "\$certdir/root.crt"
chmod 0644 "\$certdir/server.crt" "\$certdir/root.crt"
chmod 0600 "\$certdir/server.key"
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file="\$certdir/server.crt" -c ssl_key_file="\$certdir/server.key" -c ssl_ca_file="\$certdir/root.crt"
"""
    return ["sh", "-c", setup_script]
end

function generate_ssl_material(dir::AbstractString)
    root_key = joinpath(dir, "root.key")
    root_cert = joinpath(dir, "root.crt")
    wrong_root_key = joinpath(dir, "wrong-root.key")
    wrong_root_cert = joinpath(dir, "wrong-root.crt")
    server_key = joinpath(dir, "server.key")
    server_csr = joinpath(dir, "server.csr")
    server_cert = joinpath(dir, "server.crt")
    server_config = joinpath(dir, "server-openssl.cnf")

    open(server_config, "w") do io
        write(io, """
[req]
distinguished_name = req_distinguished_name
prompt = no
req_extensions = v3_req

[req_distinguished_name]
CN = 127.0.0.1

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
""")
    end

    run_openssl("req", "-x509", "-newkey", "rsa:2048", "-days", "1", "-nodes", "-keyout", root_key, "-out", root_cert, "-subj", "/CN=Postgres.jl Test Root CA")
    run_openssl("req", "-x509", "-newkey", "rsa:2048", "-days", "1", "-nodes", "-keyout", wrong_root_key, "-out", wrong_root_cert, "-subj", "/CN=Postgres.jl Wrong Root CA")
    run_openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", server_key, "-out", server_csr, "-config", server_config)
    run_openssl("x509", "-req", "-in", server_csr, "-CA", root_cert, "-CAkey", root_key, "-CAcreateserial", "-out", server_cert, "-days", "1", "-sha256", "-extensions", "v3_req", "-extfile", server_config)
    chmod(server_key, 0o600)

    return (rootcert=root_cert, wrongrootcert=wrong_root_cert, certdir=dir)
end

function with_ssl_postgres(f::Function)
    image, tag = parse_image_ref(IMAGE_REF)
    host_port = pick_port()
    env = Dict(
        "POSTGRES_USER" => DEFAULT_USER,
        "POSTGRES_PASSWORD" => DEFAULT_PASSWORD,
        "POSTGRES_DB" => DEFAULT_DB,
        "POSTGRES_HOST_AUTH_METHOD" => DEFAULT_AUTH,
        "POSTGRES_INITDB_ARGS" => DEFAULT_INITDB_ARGS,
    )
    mktempdir(@__DIR__) do dir
        tls = generate_ssl_material(dir)
        Harbor.with_container(
            image;
            tag=tag,
            ports=Dict(5432 => host_port),
            volumes=Dict(
                "/certs" => tls.certdir,
            ),
            environment=env,
            command=ssl_postgres_command(),
            wait_strategy=(pattern="database system is ready to accept connections",),
        ) do _
            cfg = PgConfig("127.0.0.1", host_port, DEFAULT_USER, DEFAULT_PASSWORD, DEFAULT_DB)
            return f(cfg, tls)
        end
    end
end

function connection_error(host::AbstractString, cfg::PgConfig; sslmode::Union{Nothing, String}=nothing, sslrootcert::Union{Nothing, String}=nothing)
    try
        conn = DBInterface.connect(Postgres.Connection, host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, connect_timeout=2, sslmode=sslmode, sslrootcert=sslrootcert)
        DBInterface.close!(conn)
        return nothing
    catch err
        return err
    end
end

function connection_uses_ssl(conn::Postgres.Connection)
    row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")))
    return row.ssl
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

function pg_array_token(value::Missing)
    return "NULL"
end

function pg_array_token(value::AbstractString)
    return string('"', replace(String(value), "\\" => "\\\\", "\"" => "\\\""), '"')
end

function pg_array_token(value)
    return string(value)
end

function pg_array_literal(values)
    return string("{", join((pg_array_token(value) for value in values), ","), "}")
end

function random_array_string(rng::AbstractRNG)
    alphabet = vcat(collect('a':'z'), collect('A':'Z'), collect('0':'9'), [' ', ',', '\\', '"', '{', '}', '[', ']', 'N'])
    return String(rand(rng, alphabet, rand(rng, 0:12)))
end

@testset "Postgres" begin
    @testset "Export Surface" begin
        @test Set(names(Postgres)) == Set([:DBInterface, :Postgres])
    end

    @testset "Connection String Parsing" begin
        params = Postgres.parse_dsn("host=127.0.0.1 port=5433 user='post gres' password='pa ss' dbname=mydb application_name='my app' sslmode=disable")
        @test params.host == "127.0.0.1"
        @test params.port == 5433
        @test params.user == "post gres"
        @test params.password == "pa ss"
        @test params.dbname == "mydb"
        @test params.application_name == "my app"
        @test params.sslmode == "disable"

        semicolon_params = Postgres.parse_dsn("host=localhost;port=5434;user=postgres;dbname=postgres;statement_cache_maxsize=7")
        @test semicolon_params.host == "localhost"
        @test semicolon_params.port == 5434
        @test semicolon_params.statement_cache_maxsize == 7

        uri_params = Postgres.parse_dsn("postgresql://postgres:secret@[::1]:5435/postgres?connect_timeout=2&sslmode=require")
        @test uri_params.host == "::1"
        @test uri_params.port == 5435
        @test uri_params.user == "postgres"
        @test uri_params.password == "secret"
        @test uri_params.dbname == "postgres"
        @test uri_params.connect_timeout == 2
        @test uri_params.sslmode == "require"

        default_db_params = Postgres.parse_dsn("postgresql://bob@localhost")
        @test default_db_params.user == "bob"
        @test default_db_params.dbname == "bob"

        unicode_params = Postgres.parse_dsn("postgresql://usér@localhost/café")
        @test unicode_params.user == "usér"
        @test unicode_params.dbname == "café"

        plus_params = Postgres.parse_dsn("postgresql://plus+user:p+ss@localhost/db+name?application_name=my+app")
        @test plus_params.user == "plus+user"
        @test plus_params.password == "p+ss"
        @test plus_params.dbname == "db+name"
        @test plus_params.application_name == "my app"

        encoded_params = Postgres.parse_dsn("postgresql://user%20name:p%40ss@localhost/db%2Fname?application_name=my+app&statement_cache_maxsize=2")
        @test encoded_params.user == "user name"
        @test encoded_params.password == "p@ss"
        @test encoded_params.dbname == "db/name"
        @test encoded_params.statement_cache_maxsize == 2

        query_host_params = Postgres.parse_dsn("postgresql:///postgres?host=%2Fvar%2Frun%2Fpostgresql&port=5436")
        @test query_host_params.host == "/var/run/postgresql"
        @test query_host_params.port == 5436
        @test query_host_params.dbname == "postgres"

        withenv(
            "PGHOST" => "envhost",
            "PGPORT" => "5544",
            "PGUSER" => "envuser",
            "PGPASSWORD" => "envpass",
            "PGDATABASE" => "envdb",
            "PGAPPNAME" => "envapp",
            "PGCONNECT_TIMEOUT" => "3",
        ) do
            env_params = Postgres.parse_dsn(nothing)
            @test env_params.host == "envhost"
            @test env_params.port == 5544
            @test env_params.user == "envuser"
            @test env_params.password == "envpass"
            @test env_params.dbname == "envdb"
            @test env_params.application_name == "envapp"
            @test env_params.connect_timeout == 3

            mixed_params = Postgres.parse_dsn("host=explicit")
            @test mixed_params.host == "explicit"
            @test mixed_params.user == "envuser"
            @test mixed_params.dbname == "envdb"
        end
    end

    @testset "API Type Parsers" begin
        registry = Dict(Postgres.API.DEFAULT_TYPE_REGISTRY)

        @test string(Postgres.API.parse_numeric("123.4500")) == "123.4500"
        @test string(Postgres.API.parse_numeric("-0.00120")) == "-0.00120"
        @test string(Postgres.API.parse_numeric("1.23e3")) == "1230"
        @test Postgres.API.parse_numeric("+42") == Postgres.Numeric(BigInt(42), 0)

        @test Postgres.API.parse_value(1184, "2024-02-13 05:28:17+02", registry) == DateTime(2024, 2, 13, 3, 28, 17)
        @test Postgres.API.parse_value(1184, "2024-02-13 05:28:17+02:30", registry) == DateTime(2024, 2, 13, 2, 58, 17)
        @test Postgres.API.parse_value(1184, "2024-02-13 05:28:17Z", registry) == DateTime(2024, 2, 13, 5, 28, 17)

        @test Postgres.API.parse_interval("1 year 2 mons 3 days 04:05:06.789") == Dates.CompoundPeriod(Dates.Year(1), Dates.Month(2), Dates.Day(3), Dates.Hour(4), Dates.Minute(5), Dates.Second(6), Dates.Millisecond(789))
        @test Postgres.API.parse_interval("-04:05:06.789") == Dates.CompoundPeriod(Dates.Hour(-4), Dates.Minute(-5), Dates.Second(-6), Dates.Millisecond(-789))

        @test Postgres.API.parse_value(17, raw"\xDEADBEEF", registry) == UInt8[0xde, 0xad, 0xbe, 0xef]
        @test Postgres.API.decode_bytea(raw"\141\\") == UInt8['a', '\\']
        @test_throws ArgumentError Postgres.API.decode_bytea(raw"\xabc")
        @test_throws ArgumentError Postgres.API.decode_bytea(raw"\xzz")

        range = Postgres.API.parse_range("[1,5)", 23, registry)
        @test range == Postgres.PostgresRange{Int32}(1, 5, true, false, false)
        unbounded = Postgres.API.parse_range("(,5]", 23, registry)
        @test ismissing(unbounded.lower)
        @test unbounded.upper == 5
        @test !unbounded.lower_inclusive
        @test unbounded.upper_inclusive
        empty_range = Postgres.API.parse_range("empty", 23, registry)
        @test empty_range.empty
        @test Postgres.API.split_range_values("\"a,b\",c") == ("\"a,b\"", "c")
        @test Postgres.API.split_range_values("\"a\\\",b\",c") == ("\"a\\\",b\"", "c")

        fields = Postgres.API.parse_composite_fields("(\"a,b\",,\"a\\\"b\",\"c\\\\d\",plain)")
        @test isequal(fields, Union{String, Missing}["a,b", missing, "a\"b", "c\\d", "plain"])

        rng = MersenneTwister(0x5097)
        for _ in 1:200
            values = [random_array_string(rng) for _ in 1:rand(rng, 0:8)]
            literal = pg_array_literal(values)
            @test Postgres.API.parse_array_by_oid(literal, 25, registry) == values
            @test Postgres.API.parse_value(1009, literal, registry) == values
        end

        for _ in 1:200
            values = Union{Missing, Int32}[rand(rng) < 0.2 ? missing : Int32(rand(rng, -1000:1000)) for _ in 1:rand(rng, 0:8)]
            parsed = Postgres.API.parse_array_by_oid(pg_array_literal(values), 23, registry)
            @test isequal(parsed, values)
        end

        # The bind path builds the same literal syntax the parser consumes:
        # element strings are double-quoted with embedded quotes and
        # backslashes escaped. Round-trip serializer output through the parser
        # so the two sides can never drift apart.
        @test Postgres._param(["a\"b", "c\\d", "plain"]) ==
              "{\"a\\\"b\", \"c\\\\d\", \"plain\"}"
        hostile = ["He said \"hi\"", "C:\\temp\\x", "", "NULL", "{brace, comma}", "\\\""]
        @test Postgres.API.parse_array_by_oid(Postgres._param(hostile), 25, registry) == hostile
        for _ in 1:200
            values = [random_array_string(rng) for _ in 1:rand(rng, 0:8)]
            @test Postgres.API.parse_array_by_oid(Postgres._param(values), 25, registry) == values
        end
    end

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
                        err = try
                            DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, "wrong"; dbname=cfg.dbname, port=cfg.port)
                            nothing
                        catch err
                            err
                        end
                        @test err isa Postgres.API.Error
                        @test err.code == "28P01"
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
                @testset "Protocol Resync On Error Paths" begin
                    connp = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port)

                    # a Describe error (e.g. the statement was discarded server-side)
                    # surfaces the real server error, not an assert, and leaves the
                    # stream at ReadyForQuery so the connection stays usable
                    err = try
                        Postgres.API.describeprepared(connp.socket, "no_such_stmt_xyz", false)
                        nothing
                    catch e
                        e
                    end
                    @test err isa Postgres.API.Error
                    @test occursin("does not exist", err.message)
                    @test isopen(connp.socket)
                    @test Tables.rowtable(DBInterface.execute(connp, "SELECT 1 AS a"))[1].a == 1

                    # a consumer exception mid-result drains the remaining rows so
                    # the connection stays usable
                    stmt = DBInterface.prepare(connp, "SELECT i AS x, repeat('y', 10) AS s FROM generate_series(1, 200) i")
                    ex = Postgres.API.exec(connp.socket, stmt.name, Union{String, Missing}[], stmt.names, stmt.typeIds, connp.type_registry, false)
                    err = try
                        StructUtils.applyeach(Postgres.API.PostgresStyle(), ex) do i, row
                            i == 3 && error("consumer abort")
                            nothing
                        end
                        nothing
                    catch e
                        e
                    end
                    @test err isa ErrorException
                    @test isopen(connp.socket)
                    @test Tables.rowtable(DBInterface.execute(connp, "SELECT 2 AS a"))[1].a == 2

                    # a value-conversion failure during materialization (Int8
                    # overflows at row 128) behaves the same through the
                    # DBInterface.execute typed path
                    err = try
                        DBInterface.execute(connp, "SELECT i AS x, repeat('y', 10) AS s FROM generate_series(1, 300) i", nothing, Vector{Int8Row})
                        nothing
                    catch e
                        e
                    end
                    @test err isa InexactError
                    @test isopen(connp.socket)
                    @test Tables.rowtable(DBInterface.execute(connp, "SELECT 3 AS a"))[1].a == 3

                    # a backend killed mid-query surfaces the server's ErrorResponse
                    # (not a raw EOF) and closes the socket so the dead connection
                    # can never be reused
                    conn_victim = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port)
                    victim_task = @async try
                        DBInterface.execute(conn_victim, "SELECT pg_sleep(30)")
                        nothing
                    catch e
                        e
                    end
                    started = false
                    for _ = 1:100
                        active = Tables.rowtable(DBInterface.execute(connp, "SELECT count(*) AS n FROM pg_stat_activity WHERE pid = $(conn_victim.pid) AND state = 'active'"))[1].n
                        started = active == 1
                        started && break
                        sleep(0.1)
                    end
                    @test started
                    DBInterface.execute(connp, "SELECT pg_terminate_backend($(conn_victim.pid))")
                    err = fetch(victim_task)
                    @test err isa Postgres.API.Error
                    @test occursin("terminat", err.message)
                    @test !isopen(conn_victim.socket)

                    DBInterface.close!(conn_victim)
                    DBInterface.close!(connp)
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
                    @test Postgres.command_tag(res) == "SELECT 1"
                    @test Postgres.rows_affected(res) == 1
                    DBInterface.execute(conn, "CREATE TEMP TABLE command_tag_test (id int)")
                    insert_res = DBInterface.execute(conn, "INSERT INTO command_tag_test VALUES (1), (2)")
                    @test Postgres.command_tag(insert_res) == "INSERT 0 2"
                    @test Postgres.rows_affected(insert_res) == 2
                    update_res = DBInterface.execute(conn, "UPDATE command_tag_test SET id = id + 1")
                    @test Postgres.command_tag(update_res) == "UPDATE 2"
                    @test Postgres.rows_affected(update_res) == 2
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
                    bytea_param = UInt8[0xde, 0xad, 0xbe, 0xef]
                    bytea_row = only(Tables.rowtable(DBInterface.execute(conn, raw"SELECT $1::bytea AS bytea_col", (bytea_param,))))
                    @test bytea_row.bytea_col == bytea_param
                    # String array binds must survive quotes and backslashes in
                    # elements end to end, not just through the client parser.
                    text_array_param = ["He said \"hi\"", "C:\\temp\\x", "", "NULL", "{brace, comma}"]
                    text_array_row = only(Tables.rowtable(DBInterface.execute(conn, raw"SELECT $1::text[] AS text_array", (text_array_param,))))
                    @test text_array_row.text_array == text_array_param
                    array_types_row = only(Tables.rowtable(DBInterface.execute(conn, """
                        SELECT
                            ARRAY['12345678-1234-5678-1234-567812345678']::uuid[] AS uuid_array,
                            ARRAY[DATE '2024-01-28']::date[] AS date_array,
                            ARRAY['123.45'::numeric, NULL]::numeric[] AS numeric_array,
                            ARRAY['{"a":1}'::jsonb]::jsonb[] AS jsonb_array
                    """)))
                    @test array_types_row.uuid_array == UUID[UUID("12345678-1234-5678-1234-567812345678")]
                    @test array_types_row.date_array == Date[Date(2024, 1, 28)]
                    @test isequal(array_types_row.numeric_array, Union{Missing, Postgres.Numeric}[Postgres.API.parse_numeric("123.45"), missing])
                    @test JSON.parse(only(array_types_row.jsonb_array))["a"] == 1
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

                    DBInterface.transaction(conn) do
                        DBInterface.execute(conn, "INSERT INTO tx_do (id) VALUES (3)")
                    end
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM tx_do"))) == 2
                    @test_throws Postgres.API.Error DBInterface.transaction(conn) do
                        DBInterface.execute(conn, "INSERT INTO tx_do (id) VALUES (4)")
                        DBInterface.execute(conn, "INVALID SQL")
                    end
                    @test length(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM tx_do"))) == 2

                    DBInterface.execute(conn, "DROP TABLE IF EXISTS executemany_test")
                    DBInterface.execute(conn, "CREATE TABLE executemany_test (id INT)")
                    many_stmt = DBInterface.prepare(conn, "INSERT INTO executemany_test (id) VALUES (\$1)")
                    DBInterface.executemany(many_stmt, ([1, 2, 3],))
                    DBInterface.close!(many_stmt)
                    count_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT count(*) AS count FROM executemany_test")))
                    @test count_row.count == 3
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
                    @test Postgres.wait_for_notification(listener; timeout=0.05) === nothing
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

                @testset "Interval Types" begin
                    interval_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '1 day'::interval AS interval_col")))
                    @test interval_row.interval_col == Dates.Day(1)
                    complex_interval = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '1 year 2 mons 3 days 04:05:06.789'::interval AS interval_col")))
                    @test complex_interval.interval_col == Dates.CompoundPeriod(Dates.Year(1), Dates.Month(2), Dates.Day(3), Dates.Hour(4), Dates.Minute(5), Dates.Second(6), Dates.Millisecond(789))
                end
            finally
                isopen(conn) && DBInterface.close!(conn)
            end
        end

        @testset "SSL Certificate Fixture" begin
            if Sys.which("openssl") === nothing
                @info "OpenSSL executable not available; skipping certificate-backed SSL tests."
                @test true
            else
                with_ssl_postgres() do ssl_cfg, tls
                    require_conn = wait_for_connection(ssl_cfg; sslmode="require")
                    try
                        @test isopen(require_conn)
                        @test connection_uses_ssl(require_conn)
                    finally
                        isopen(require_conn) && DBInterface.close!(require_conn)
                    end

                    verify_conn = DBInterface.connect(Postgres.Connection, ssl_cfg.host, ssl_cfg.user, ssl_cfg.password; dbname=ssl_cfg.dbname, port=ssl_cfg.port, sslmode="verify-full", sslrootcert=tls.rootcert)
                    try
                        @test isopen(verify_conn)
                        @test connection_uses_ssl(verify_conn)
                    finally
                        isopen(verify_conn) && DBInterface.close!(verify_conn)
                    end

                    @test connection_error(ssl_cfg.host, ssl_cfg; sslmode="verify-full") !== nothing
                    @test connection_error(ssl_cfg.host, ssl_cfg; sslmode="verify-full", sslrootcert=tls.wrongrootcert) !== nothing

                    localhost_require_err = connection_error("localhost", ssl_cfg; sslmode="require")
                    if localhost_require_err === nothing
                        @test connection_error("localhost", ssl_cfg; sslmode="verify-full", sslrootcert=tls.rootcert) !== nothing
                    else
                        @info "localhost did not route to the Docker PostgreSQL port; skipping hostname mismatch check." error=sprint(showerror, localhost_require_err)
                        @test true
                    end
                end
            end
        end
    end
end
