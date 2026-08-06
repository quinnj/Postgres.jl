using Test
using Aqua
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

# Style-based customization (the runtime callback setters are gone): overload the
# behavior interface on a custom AbstractPostgresStyle and pass it at connect time.
const LOGGED_EVENTS = NamedTuple[]
const NOTICE_SEEN = Ref(false)
struct LoggingStyle <: Postgres.API.AbstractPostgresStyle end
Postgres.API.query_logging_enabled(::LoggingStyle) = true
Postgres.API.query_logger(::LoggingStyle, event::Symbol, info::NamedTuple) = (push!(LOGGED_EVENTS, (event=event, info=info)); nothing)
Postgres.API.notice_callback(::LoggingStyle, notice) = (NOTICE_SEEN[] = true; nothing)

const FAILING_LOGGER_CALLS = Ref(0)
struct FailingLoggerStyle <: Postgres.API.AbstractPostgresStyle end
Postgres.API.query_logging_enabled(::FailingLoggerStyle) = true
function Postgres.API.query_logger(::FailingLoggerStyle, event::Symbol, info::NamedTuple)
    FAILING_LOGGER_CALLS[] += 1
    error("logger failed")
end


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

# user-IO failure injection for the COPY hardening tests
struct ThrowingSource <: IO end
Base.eof(::ThrowingSource) = false
Base.readbytes!(::ThrowingSource, ::Vector{UInt8}, n) = error("source failed")

struct FailingDest <: IO end
Base.write(::FailingDest, ::Vector{UInt8}) = error("dest failed")

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
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file="\$certdir/server.crt" -c ssl_key_file="\$certdir/server.key" -c ssl_ca_file="\$certdir/root.crt" -c hba_file=/certs/pg_hba.conf
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
    client_key = joinpath(dir, "client.key")
    client_csr = joinpath(dir, "client.csr")
    client_cert = joinpath(dir, "client.crt")
    client_config = joinpath(dir, "client-openssl.cnf")
    hba_file = joinpath(dir, "pg_hba.conf")

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

    open(client_config, "w") do io
        write(io, """
[req]
distinguished_name = req_distinguished_name
prompt = no
req_extensions = v3_req

[req_distinguished_name]
CN = postgres_mtls

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
""")
    end

    open(hba_file, "w") do io
        write(io, """
local all all trust
hostssl all postgres_mtls 0.0.0.0/0 trust clientcert=verify-full
hostssl all postgres_mtls ::/0 trust clientcert=verify-full
host all all 0.0.0.0/0 trust
host all all ::/0 trust
""")
    end

    run_openssl("req", "-x509", "-newkey", "rsa:2048", "-days", "1", "-nodes", "-keyout", root_key, "-out", root_cert, "-subj", "/CN=Postgres.jl Test Root CA")
    run_openssl("req", "-x509", "-newkey", "rsa:2048", "-days", "1", "-nodes", "-keyout", wrong_root_key, "-out", wrong_root_cert, "-subj", "/CN=Postgres.jl Wrong Root CA")
    run_openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", server_key, "-out", server_csr, "-config", server_config)
    run_openssl("x509", "-req", "-in", server_csr, "-CA", root_cert, "-CAkey", root_key, "-CAcreateserial", "-out", server_cert, "-days", "1", "-sha256", "-extensions", "v3_req", "-extfile", server_config)
    run_openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", client_key, "-out", client_csr, "-config", client_config)
    run_openssl("x509", "-req", "-in", client_csr, "-CA", root_cert, "-CAkey", root_key, "-CAcreateserial", "-out", client_cert, "-days", "1", "-sha256", "-extensions", "v3_req", "-extfile", client_config)
    chmod(server_key, 0o600)
    chmod(client_key, 0o600)

    return (rootcert=root_cert, wrongrootcert=wrong_root_cert,
            clientcert=client_cert, clientkey=client_key, certdir=dir)
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
    Aqua.test_all(Postgres)

    @testset "Export Surface" begin
        exported = Set([:DBInterface, :Postgres])
        @static if VERSION >= v"1.11"
            # names() includes `public` declarations on Julia 1.11+
            public_names = Set([
                :Connection, :ConnectionPool, :ConnectionParams, :PostgresInterfaceError,
                :Error, :Notification, :Numeric, :PostgresRange, :AbstractPostgresStyle, :PostgresStyle,
                :query_logging_enabled, :query_logger, :notice_callback, :notification_callback, :parse_dsn,
                :transaction, Symbol("@transaction"), :start_transaction, :commit, :rollback, :in_transaction,
                :cursor, :copy_from, :copy_to, :listen!, :unlisten!, :notify!, :wait_for_notification,
                :register_type!, :register_enum!, :register_composite!, :register_range!,
                :command_tag, :rows_affected, :cancel_query!, :escape_identifier, :escape_literal,
                :get_cached_statements, :clear_statement_cache!, :set_statement_cache_maxsize!,
                :get_server_parameter, :get_server_parameters, :get_statement_timeout, :set_statement_timeout!,
                :acquire, :release, :with_connection, :describe,
            ])
            @test Set(names(Postgres)) == union(exported, public_names)
        else
            @test Set(names(Postgres)) == exported
        end
        @test Postgres.PostgresInterfaceError <: Exception
        @test Postgres.Error <: Exception
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

        sni_params = Postgres.parse_dsn("host=203.0.113.7 sslmode=require sslservername=db.example.com")
        @test sni_params.sslservername == "db.example.com"
        sni_uri_params = Postgres.parse_dsn("postgresql://postgres@203.0.113.7/postgres?sslservername=db.example.com")
        @test sni_uri_params.sslservername == "db.example.com"

        # IPv6 hosts must be bracketed for the transport address parser;
        # unix socket paths are rejected with a clear error
        @test Postgres.API.hostport_address("::1", 5432) == "[::1]:5432"
        @test Postgres.API.hostport_address("127.0.0.1", 5432) == "127.0.0.1:5432"
        @test Postgres.API.hostport_address("db.example.com", 6432) == "db.example.com:6432"
        @test_throws Postgres.PostgresInterfaceError Postgres.API.hostport_address("/var/run/postgresql", 5432)

        # debug/reconnect are accepted from a DSN and actually applied
        flag_params = Postgres.parse_dsn("host=h debug=true reconnect=on")
        @test flag_params.debug
        @test flag_params.reconnect
        @test !Postgres.parse_dsn("host=h").debug
        @test !Postgres.parse_dsn("host=h").reconnect

        # an unrecognized parameter is a typo, not something to silently drop:
        # "ssl_mode=verify-full" would otherwise leave sslmode unset and
        # quietly fall back to an unverified connection
        @test_throws ArgumentError Postgres.parse_dsn("host=h ssl_mode=verify-full")
        @test_throws ArgumentError Postgres.parse_dsn("postgresql://u@h/db?ssl_mode=require")

        # A libpq option that requests behavior this driver cannot enforce is
        # rejected. Warning and connecting would falsely report a security or
        # routing guarantee to the caller.
        @test_throws ArgumentError Postgres.parse_dsn("postgresql://u:p@h/db?sslmode=require&channel_binding=require")
        @test_throws ArgumentError Postgres.parse_dsn("postgresql://u@h/db?target_session_attrs=read-write")
        @test_throws ArgumentError Postgres.parse_dsn("host=h options=-csearch_path=x")
        @test_throws ArgumentError Postgres.parse_dsn("host=h sslcrl=/tmp/crl.pem")
        @test_throws ArgumentError Postgres.parse_dsn("host=h requiressl=1")
        @test_throws ArgumentError Postgres.parse_dsn("host=h gssencmode=require")
        @test_throws ArgumentError Postgres.parse_dsn("host=h requirepeer=postgres")
        @test_throws ArgumentError Postgres.parse_dsn("host=h hostaddr=203.0.113.1")
        @test_throws ArgumentError Postgres.parse_dsn("host=h client_encoding=LATIN1")
        # the no-op defaults for those keywords stay silent, as do keywords
        # with no security consequence
        @test_logs Postgres.parse_dsn("host=h channel_binding=prefer target_session_attrs=any requiressl=0")
        @test_logs Postgres.parse_dsn("host=h keepalives=1 client_encoding=UTF8")
        @test_logs Postgres.parse_dsn("postgresql://u@h/db?channel_binding=disable")

        # Displaying structured connection options must never reveal a secret.
        shown = repr(Postgres.ConnectionParams(host="h", user="u", password="top-secret", dbname="d"))
        plain_shown = repr(MIME"text/plain"(), Postgres.ConnectionParams(
            host="h", user="u", password="top-secret", dbname="d"))
        @test !occursin("top-secret", shown)
        @test !occursin("top-secret", plain_shown)
        @test occursin("password=***", shown)
        @test occursin("password=***", plain_shown)

        # Malformed keyword DSNs must never degrade to a usable partial
        # configuration. In particular, a discarded security option could
        # change which endpoint or transport is selected.
        @test_throws ArgumentError Postgres.parse_dsn("host=h broken")
        @test_throws ArgumentError Postgres.parse_dsn("host='unterminated")
        @test_throws ArgumentError Postgres.parse_dsn("host=abc\\")
        @test_throws ArgumentError Postgres.parse_dsn("host='h'trailing")

        # invalid values for a recognized parameter are reported against that
        # parameter rather than silently defaulting
        @test_throws ArgumentError Postgres.parse_dsn("host=h reconnect=ture")
        @test_throws ArgumentError Postgres.parse_dsn("host=h port=abc")

        # an empty value (an unset PGPORT expanded by a process manager) falls
        # back to the default instead of failing to parse
        withenv("PGPORT" => "") do
            @test Postgres.parse_dsn("host=h").port == 5432
            @test Postgres.parse_dsn(nothing).port == 5432
        end
        # ... and the same for the boolean and TLS-mode parameters (quoted so
        # the empty value can't swallow the next key: a bare "reconnect=" takes
        # the following token as its value, as libpq does)
        @test !Postgres.parse_dsn("host=h reconnect='' debug=''").reconnect
        @test !Postgres.parse_dsn("host=h reconnect='' debug=''").debug
        # sslmode is deliberately NOT empty-tolerant (libpq rejects it too):
        # an unexpanded ${PGSSLMODE} meant to be verify-full must fail loudly
        # rather than fall back to the unauthenticated default
        withenv("PGSSLMODE" => "") do
            @test Postgres.parse_dsn("host=h").sslmode == ""
        end

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
        # numeric special values can't be represented and must fail clearly
        @test_throws Postgres.PostgresInterfaceError Postgres.API.parse_numeric("NaN")
        @test_throws Postgres.PostgresInterfaceError Postgres.API.parse_numeric("Infinity")
        @test_throws Postgres.PostgresInterfaceError Postgres.API.parse_numeric("-Infinity")
        # an absurd exponent must be rejected, not turned into a huge BigInt
        @test_throws Postgres.PostgresInterfaceError Postgres.API.parse_numeric("1e999999999999")
        @test_throws Postgres.PostgresInterfaceError Postgres.API.parse_numeric("1e99999999999999999999999999")
        # abs(typemin(Int)) wraps to itself, so the bound must not use abs
        @test_throws Postgres.PostgresInterfaceError Postgres.API.parse_numeric("1e-9223372036854775808")
        # ordinary scientific notation still round-trips
        @test string(Postgres.API.parse_numeric("1.5e2")) == "150"
        @test string(Postgres.API.parse_numeric("1.5e-2")) == "0.015"

        # message-field parsing is bounded by the buffer actually received: a
        # truncated or unterminated field must not read past the allocation
        @test Postgres.API.cstring_at(UInt8[], 1) == ("", 1)
        @test Postgres.API.cstring_at(UInt8['a', 'b', 0x00], 1) == ("ab", 4)
        @test Postgres.API.cstring_at(UInt8['a', 'b'], 1) == ("ab", 3)
        @test Postgres.API.cstring_at(UInt8['a', 0x00, 'c', 0x00], 3) == ("c", 5)
        @test Postgres.API.cstring_at(UInt8['a', 0x00], 5) == ("", 3)
        @test_throws EOFError Postgres.API.skipbytes!(IOBuffer(UInt8[0x01]), 2)
        @test Postgres.API.read_ready_status(IOBuffer(UInt8['T']), 1) == UInt8('T')
        @test_throws Postgres.API.Error Postgres.API.read_ready_status(IOBuffer(UInt8[]), 0)
        @test Postgres.API.commandComplete(7, IOBuffer(UInt8[codeunits("SELECT\0")...])) == "SELECT"
        @test_throws Postgres.API.Error Postgres.API.commandComplete(0, IOBuffer())
        @test_throws Postgres.API.Error Postgres.API.commandComplete(4, IOBuffer(UInt8['O', 'K', 0x00, 0x00]))
        let socket = IOBuffer()
            write(socket, UInt8('D'))
            write(socket, hton(Postgres.API.MAX_PREAUTH_MESSAGE_LEN + Int32(5)))
            seekstart(socket)
            @test_throws Postgres.API.Error Postgres.API.readheader(
                socket, false, Postgres.API.MAX_PREAUTH_MESSAGE_LEN)
        end

        # a malformed DataRow must fail with a clear protocol error rather
        # than reading past the buffer or leaving the row partly unfilled
        let nms = Symbol[:a, :b], tids = Int[23, 23],
            mk = b -> Postgres.API.DataRow(b, nms, tids, registry),
            consume = row -> StructUtils.applyeach(Postgres.API.PostgresStyle(), (k, v) -> nothing, row)
            # ncols is signed on the wire: -1 must not pass an upper-bound check
            @test_throws Postgres.API.Error consume(mk(UInt8[0xff, 0xff]))
            # the count must equal the described column count exactly: too few
            # would leave the caller's row partly unfilled
            @test_throws Postgres.API.Error consume(mk(UInt8[0x00, 0x09]))
            @test_throws Postgres.API.Error consume(mk(UInt8[0x00, 0x01, 0x00, 0x00, 0x00, 0x01, UInt8('7')]))
            # truncated header, and a column length running past the body
            @test_throws Postgres.API.Error consume(mk(UInt8[0x00]))
            @test_throws Postgres.API.Error consume(mk(UInt8[0x00, 0x01, 0x00, 0x00, 0x00, 0x7f]))
            # a well-formed row still parses, including a NULL column
            vals = Any[]
            consume_ok = Postgres.API.DataRow(
                UInt8[0x00, 0x02, 0x00, 0x00, 0x00, 0x01, UInt8('5'), 0xff, 0xff, 0xff, 0xff],
                nms, tids, registry)
            StructUtils.applyeach(Postgres.API.PostgresStyle(), (k, v) -> push!(vals, v), consume_ok)
            @test vals == Any[Int32(5), nothing]
        end

        # a cancel connection must never downgrade to cleartext when the
        # connection being cancelled actually negotiated TLS
        @test Postgres.cancel_sslmode(true, nothing) == "require"
        @test Postgres.cancel_sslmode(true, "prefer") == "require"
        @test Postgres.cancel_sslmode(true, "PREFER") == "require"
        @test Postgres.cancel_sslmode(true, "verify-full") == "verify-full"
        @test Postgres.cancel_sslmode(true, "require") == "require"
        # an explicitly plaintext connection is left alone, as are non-TLS ones
        @test Postgres.cancel_sslmode(true, "disable") == "disable"
        @test Postgres.cancel_sslmode(false, nothing) === nothing
        @test Postgres.cancel_sslmode(false, "prefer") == "prefer"

        # escaping helpers reject embedded NULs rather than emitting SQL the
        # server would truncate mid-statement
        @test Postgres.escape_identifier("a\"b") == "\"a\"\"b\""
        @test Postgres.escape_literal("a'b") == "'a''b'"
        @test Postgres.escape_literal("a\\b") == "E'a\\\\b'"
        @test_throws Postgres.PostgresInterfaceError Postgres.escape_identifier("a\0b")
        @test_throws Postgres.PostgresInterfaceError Postgres.escape_literal("a\0b")
        @test_throws Postgres.PostgresInterfaceError Postgres.Connection(host="127.0.0.1", port=1, user="u\0x")

        # severity must come from the non-localized 'V' field when the server
        # sends it: 'S' is translated, so comparing it to "FATAL" would depend
        # on the server's lc_messages
        let socket = IOBuffer(Vector{UInt8}(vcat(
                UInt8('S'), Vector{UInt8}("SCHWERWIEGEND"), 0x00,
                UInt8('V'), Vector{UInt8}("FATAL"), 0x00,
                UInt8('C'), Vector{UInt8}("57P01"), 0x00,
                UInt8('M'), Vector{UInt8}("terminating connection"), 0x00,
                0x00)))
            err = Postgres.API.errorResponse(bytesavailable(socket), socket, false)
            @test err.severity == "FATAL"
            @test err.code == "57P01"
        end
        # without 'V' the localized 'S' is still reported
        let socket = IOBuffer(Vector{UInt8}(vcat(
                UInt8('S'), Vector{UInt8}("ERROR"), 0x00,
                UInt8('C'), Vector{UInt8}("42601"), 0x00,
                0x00)))
            err = Postgres.API.errorResponse(bytesavailable(socket), socket, false)
            @test err.severity == "ERROR"
        end

        @test Postgres.API.parse_value(1184, "2024-02-13 05:28:17+02", registry) == DateTime(2024, 2, 13, 3, 28, 17)
        @test Postgres.API.parse_value(1184, "2024-02-13 05:28:17+02:30", registry) == DateTime(2024, 2, 13, 2, 58, 17)
        @test Postgres.API.parse_value(1184, "2024-02-13 05:28:17Z", registry) == DateTime(2024, 2, 13, 5, 28, 17)
        # LMT-era offsets in named zones carry a seconds field; dropping it
        # silently shifted the decoded value
        @test Postgres.API.parse_value(1184, "1880-01-01 05:21:10+05:21:10", registry) == DateTime(1880, 1, 1, 0, 0, 0)
        @test Postgres.API.parse_value(1184, "1879-12-31 18:38:50-05:21:10", registry) == DateTime(1880, 1, 1, 0, 0, 0)

        @test Postgres.API.parse_interval("1 year 2 mons 3 days 04:05:06.789") == Dates.CompoundPeriod(Dates.Year(1), Dates.Month(2), Dates.Day(3), Dates.Hour(4), Dates.Minute(5), Dates.Second(6), Dates.Millisecond(789))
        @test Postgres.API.parse_interval("-04:05:06.789") == Dates.CompoundPeriod(Dates.Hour(-4), Dates.Minute(-5), Dates.Second(-6), Dates.Millisecond(-789))
        # a genuine zero interval renders as "00:00:00" in the postgres style
        @test Postgres.API.parse_interval("00:00:00") == Dates.Millisecond(0)
        # text in an IntervalStyle this parser can't read (a mid-session SET
        # to sql_standard or iso_8601) must fail loudly, not silently decode
        # to a zero interval
        for foreign in ("+1 +2:00:00", "1 2:00:00", "P1DT2H", "PT0S", "@ 1 day 2 hours", "1-2")
            @test_throws Postgres.PostgresInterfaceError Postgres.API.parse_interval(foreign)
        end

        # the field-order half of DateStyle survives the correction to ISO
        @test Postgres.API.date_order("German, DMY") == "DMY"
        @test Postgres.API.date_order("SQL, MDY") == "MDY"
        @test Postgres.API.date_order("Postgres, YMD") == "YMD"
        @test Postgres.API.date_order("ISO, DMY") == "DMY"
        # unreported or unrecognized styles fall back to the postgres default
        @test Postgres.API.date_order("") == "MDY"
        @test Postgres.API.date_order("German") == "MDY"

        @test Postgres.API.parse_value(17, raw"\xDEADBEEF", registry) == UInt8[0xde, 0xad, 0xbe, 0xef]
        @test Postgres.API.decode_bytea(raw"\141\\") == UInt8['a', '\\']
        @test_throws ArgumentError Postgres.API.decode_bytea(raw"\xabc")
        @test_throws ArgumentError Postgres.API.decode_bytea(raw"\xzz")

        # timestamp range bounds are quoted on the wire; without unquoting them
        # every tsrange/tstzrange value fails to decode
        ts_range = Postgres.API.parse_range("[\"2020-01-01 00:00:00\",\"2020-01-02 00:00:00\")", 1114, registry)
        @test ts_range.lower == DateTime(2020, 1, 1)
        @test ts_range.upper == DateTime(2020, 1, 2)
        @test ts_range.lower_inclusive
        @test !ts_range.upper_inclusive
        @test Postgres.API.unquote_range_bound("\"a\\\"b\"") == "a\"b"
        @test Postgres.API.unquote_range_bound("plain") == "plain"

        # the "char" type renders its zero value as an empty string
        @test Postgres.API.parse_value(18, "", registry) == '\0'
        @test Postgres.API.parse_value(18, "Z", registry) == 'Z'
        # ... and high-bit bytes as backslash-octal escapes
        @test Postgres.API.parse_value(18, "\\200", registry) == Char(0x80)
        @test Postgres.API.parse_value(18, "\\377", registry) == Char(0xff)
        @test Postgres.API.parse_value(18, "\\x80", registry) == Char(0x80)
        @test Postgres.API.parse_value(18, "\\xFF", registry) == Char(0xff)
        # a backslash byte renders as a lone backslash, not an escape
        @test Postgres.API.parse_value(18, "\\", registry) == '\\'
        @test Postgres.API.pg_parse_char("\\310") == Char(0xc8)
        # "char"[] (oid 1002) decodes elements, escapes included; on the wire
        # the escape's backslash is itself array-quoted as "\\200"
        @test isequal(Postgres.API.parse_value(1002, "{a,\"\\\\200\",NULL}", registry), Any['a', Char(0x80), missing])
        @test Postgres.API.ArrayParsing.parse_array("{a,b}", Char) == ['a', 'b']

        # infinite timestamps/dates can't be represented and must say so
        @test_throws Postgres.PostgresInterfaceError Postgres.API.pg_parse_datetime("infinity")
        @test_throws Postgres.PostgresInterfaceError Postgres.API.pg_parse_datetime("-infinity")
        @test_throws Postgres.PostgresInterfaceError Postgres.API.pg_parse_date("infinity")
        # BC dates are a different year numbering than Julia's (no year zero);
        # decoding them as AD would be silent corruption
        @test_throws Postgres.PostgresInterfaceError Postgres.API.pg_parse_date("0044-03-15 BC")
        @test_throws Postgres.PostgresInterfaceError Postgres.API.pg_parse_datetime("0044-03-15 12:00:00 BC")
        # timestamptz puts " BC" after the zone offset, past where the
        # offset-stripped datetime parse can see it
        @test_throws Postgres.PostgresInterfaceError Postgres.API.parse_timestamptz("0044-03-15 12:00:00+00 BC")
        # years beyond 9999 widen the year field rather than misparsing
        @test Postgres.API.pg_parse_date("10000-01-01") == Date(10000, 1, 1)
        @test Postgres.API.pg_parse_datetime("294276-12-31 23:59:59") == DateTime(294276, 12, 31, 23, 59, 59)
        @test Postgres.API.parse_value(1184, "10000-01-02 03:04:05+02", registry) == DateTime(10000, 1, 2, 1, 4, 5)
        # ... but only genuine ISO renderings: an ISO year is zero-padded to
        # at least 4 digits, so "03-04-2020" (Postgres-style for 2020-03-04
        # after a mid-session SET DateStyle) must throw, not decode as year 3
        @test_throws ArgumentError Postgres.API.pg_parse_date("03-04-2020")
        @test_throws ArgumentError Postgres.API.pg_parse_date("123-01-01")
        # adversarial input: bounded digits (no Int overflow), checked layout
        @test_throws ArgumentError Postgres.API.pg_parse_date("99999999999999999999-01-01")
        @test_throws ArgumentError Postgres.API.pg_parse_date("12345678-9")
        @test_throws ArgumentError Postgres.API.pg_parse_datetime("999999999-  03:04:05    ")

        # postgres permits time '24:00:00'; Julia's Time does not
        @test_throws Postgres.PostgresInterfaceError Postgres.API.pg_parse_time("24:00:00")
        @test Postgres.API.pg_parse_time("23:59:59.999") == Time(23, 59, 59, 999)

        # range bounds may end in multibyte text; byte-index slicing threw
        # StringIndexError on every such value
        uni_range = Postgres.API.parse_range_of(String, "[α,ω)", 25, registry)
        @test uni_range.lower == "α"
        @test uni_range.upper == "ω"
        @test uni_range.lower_inclusive
        @test !uni_range.upper_inclusive

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

        # postgres prefixes the literal with explicit dimensions whenever a
        # lower bound isn't 1; without handling it the elements are silently
        # dropped (text) or the parse throws (numeric)
        @test Postgres.API.parse_array_by_oid("[0:2]={x,y,z}", 25, registry) == ["x", "y", "z"]
        @test Postgres.API.parse_array_by_oid("[0:2]={1,2,3}", 23, registry) == [1, 2, 3]
        @test Postgres.API.parse_value(1009, "[0:1]={a,b}", registry) == ["a", "b"]
        @test Postgres.API.ArrayParsing.parse_array("[1:2][1:2]={{1,2},{3,4}}", Int64) == [[1, 2], [3, 4]]
        # ']' is ordinary element data: postgres doesn't quote it, so treating
        # it as a terminator silently truncated the element and dropped every
        # element after it
        @test Postgres.API.parse_array_by_oid("{a]b,x[1],plain}", 25, registry) == ["a]b", "x[1]", "plain"]
        @test Postgres.API.parse_array_by_oid("{]}", 25, registry) == ["]"]
        @test Postgres.API.parse_array_by_oid("{/var/log/x[1].txt,b}", 25, registry) == ["/var/log/x[1].txt", "b"]

        @test Postgres.API.ArrayParsing.parse_array("{1,2}", Int64) isa Vector{Int64}

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
                    ex = Postgres.API.exec(connp.style, connp.socket, stmt.name, Union{String, Missing}[], stmt.names, stmt.typeIds, connp.type_registry, false)
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
                    # 57P01: admin_shutdown — the code, not the localized message
                    @test err.code == "57P01"
                    @test !isopen(conn_victim.socket)

                    DBInterface.close!(conn_victim)
                    DBInterface.close!(connp)
                end
                @testset "Prepared Statements" begin
                    stmt = DBInterface.prepare(conn, raw"SELECT $1::int AS val")
                    res = Tables.rowtable(DBInterface.execute(stmt, (1,)))
                    @test res[1].val == 1
                    @test all(ismissing, stmt.params)

                    failing_stmt = DBInterface.prepare(conn, raw"SELECT 10 / $1::int AS val")
                    @test_throws Postgres.API.Error DBInterface.execute(failing_stmt, (0,))
                    @test all(ismissing, failing_stmt.params)
                    mismatch_stmt = DBInterface.prepare(conn,
                        raw"SELECT $1::text AS a, $2::text AS b")
                    @test_throws Postgres.PostgresInterfaceError DBInterface.execute(
                        mismatch_stmt, ("must-not-remain",))
                    @test all(ismissing, mismatch_stmt.params)

                    # Each prepare call returns an independent caller handle,
                    # even when both handles share one cache-owned server
                    # statement. Closing one must not close the other.
                    held = DBInterface.prepare(conn, "SELECT 42 AS val")
                    alias = DBInterface.prepare(conn, "SELECT 42 AS val")
                    @test held !== alias
                    DBInterface.close!(alias)
                    @test only(DBInterface.execute(held)).val == 42
                    function_value = DBInterface.execute(conn, "SELECT 42 AS val", nothing) do result
                        only(result).val
                    end
                    @test function_value == 42
                    @test only(DBInterface.execute(held)).val == 42

                    DBInterface.close!(held)
                    DBInterface.close!(mismatch_stmt)
                    DBInterface.close!(failing_stmt)
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
                # a column mixing null-free and null-bearing arrays must report
                # a schema type every row satisfies, whatever the row order
                for order in ("'{1,2}'::int[]), ('{1,NULL}'::int[]), ('{3,4}'::int[]",
                              "'{1,NULL}'::int[]), ('{1,2}'::int[]), ('{3,4}'::int[]")
                    mixed = DBInterface.execute(conn, "SELECT a FROM (VALUES ($order)) t(a)")
                    schema_type = Tables.schema(mixed).types[1]
                    @test all(row -> Tables.getcolumn(row, 1) isa schema_type, mixed)
                    @test length(Tables.columntable(mixed).a) == 3
                end
                # a text array element containing ']' must survive the round trip
                bracket_param = ["a]b", "x[1]", "]", "plain"]
                bracket_row = only(Tables.rowtable(DBInterface.execute(conn, raw"SELECT $1::text[] AS arr", (bracket_param,))))
                @test bracket_row.arr == bracket_param
                array_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '{1,NULL,3}'::int[] AS arr")))
                @test isequal(array_row.arr, Union{Missing, Int32}[1, missing, 3])
                nested_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '{{1,2},{3,4}}'::int[] AS arr")))
                @test nested_row.arr == [Int32[1, 2], Int32[3, 4]]
                # arrays whose lower bound isn't 1 come back with an explicit
                # dimension prefix; the elements must survive it
                lb_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT array_fill(7, ARRAY[3], ARRAY[0]) AS arr")))
                @test lb_row.arr == [7, 7, 7]
                lb_text_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT array_fill('x'::text, ARRAY[3], ARRAY[0]) AS arr")))
                @test lb_text_row.arr == ["x", "x", "x"]
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

                    # a range over an element type outside the builtin set must
                    # decode after registration, not throw on every value
                    DBInterface.execute(conn, "DROP TYPE IF EXISTS textrange CASCADE")
                    DBInterface.execute(conn, "CREATE TYPE textrange AS RANGE (subtype = text)")
                    Postgres.register_range!(conn, "textrange"; schema="public")
                    trow = only(Tables.rowtable(DBInterface.execute(conn, "SELECT textrange('a','z') AS r, textrange('x','y','[]') AS s, 'empty'::textrange AS e")))
                    @test trow.r isa Postgres.PostgresRange{String}
                    @test trow.r.lower == "a"
                    @test trow.r.upper == "z"
                    @test trow.r.lower_inclusive
                    @test !trow.r.upper_inclusive
                    @test trow.s.lower == "x"
                    @test trow.s.upper_inclusive
                    @test trow.e.empty
                    # bounds ending in multibyte text arrive unquoted
                    uni_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT textrange('α','ω') AS r")))
                    @test uni_row.r.lower == "α"
                    @test uni_row.r.upper == "ω"

                    # arrays of registered custom types decode as arrays, not
                    # raw literal strings
                    enumarr = only(Tables.rowtable(DBInterface.execute(conn, "SELECT ARRAY['sad','happy']::mood[] AS a, ARRAY['ok',NULL]::mood[] AS b")))
                    @test isequal(collect(enumarr.a), Any[:sad, :happy])
                    @test isequal(collect(enumarr.b), Any[:ok, missing])
                    comparr = only(Tables.rowtable(DBInterface.execute(conn, "SELECT ARRAY[ROW('A',1)::address, ROW('B',2)::address] AS a")))
                    @test comparr.a[1] == (street="A", number=1)
                    @test comparr.a[2] == (street="B", number=2)
                    rangearr = only(Tables.rowtable(DBInterface.execute(conn, "SELECT ARRAY['[1,3)'::int4range, '[5,7)'::int4range] AS a")))
                    @test rangearr.a[1].lower == 1
                    @test rangearr.a[2].upper == 7
                    textrangearr = only(Tables.rowtable(DBInterface.execute(conn, "SELECT ARRAY[textrange('a','c'), textrange('α','ω')] AS a")))
                    @test textrangearr.a[1].upper == "c"
                    @test textrangearr.a[2].lower == "α"

                    # Registry metadata must describe values the parser can
                    # actually produce, including empty and all-NULL results.
                    @test_throws ArgumentError Postgres.register_type!(conn, 900_000, Int)
                    @test_throws ArgumentError Postgres.register_enum!(conn, "mood"; julia_type=Int)
                    Postgres.register_enum!(conn, "mood"; julia_type=String)
                    empty_enum = DBInterface.execute(conn, "SELECT mood FROM custom_types WHERE false")
                    @test Tables.schema(empty_enum).types[1] === String
                    null_enum = DBInterface.execute(conn, "SELECT NULL::mood AS mood")
                    @test Tables.schema(null_enum).types[1] == Union{Missing, String}
                    @test ismissing(only(null_enum).mood)
                    string_enum = only(DBInterface.execute(conn, "SELECT 'happy'::mood AS mood"))
                    @test string_enum.mood == "happy"
                    DBInterface.execute(conn, "DROP TYPE textrange CASCADE")
                end

                @testset "Describe Schema Isolation" begin
                    DBInterface.execute(conn, "DROP SCHEMA IF EXISTS postgres_describe_a CASCADE")
                    DBInterface.execute(conn, "DROP SCHEMA IF EXISTS postgres_describe_b CASCADE")
                    DBInterface.execute(conn, "CREATE SCHEMA postgres_describe_a")
                    DBInterface.execute(conn, "CREATE SCHEMA postgres_describe_b")
                    try
                        DBInterface.execute(conn, "CREATE TABLE postgres_describe_a.parent_a (id int PRIMARY KEY)")
                        DBInterface.execute(conn, "CREATE TABLE postgres_describe_b.parent_b (id int PRIMARY KEY)")
                        DBInterface.execute(conn, """
                            CREATE TABLE postgres_describe_a.child (
                                id int PRIMARY KEY,
                                parent_id int,
                                CONSTRAINT shared_fk FOREIGN KEY (parent_id)
                                    REFERENCES postgres_describe_a.parent_a(id)
                            )
                        """)
                        DBInterface.execute(conn, """
                            CREATE TABLE postgres_describe_b.child (
                                id int PRIMARY KEY,
                                parent_id int,
                                CONSTRAINT shared_fk FOREIGN KEY (parent_id)
                                    REFERENCES postgres_describe_b.parent_b(id)
                            )
                        """)
                        description = Postgres.describe(conn, "child"; schema="postgres_describe_a")
                        rows = Tables.rowtable(description.resultset)
                        @test length(rows) == 2
                        parent_row = only(filter(row -> row.column_name == "parent_id", rows))
                        @test parent_row.foreign_key_reference == "parent_a.id"
                    finally
                        DBInterface.execute(conn, "DROP SCHEMA IF EXISTS postgres_describe_a CASCADE")
                        DBInterface.execute(conn, "DROP SCHEMA IF EXISTS postgres_describe_b CASCADE")
                    end
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

                    # A COMMIT that fails server-side (deferred constraint) must
                    # surface the server's error with its SQLSTATE — a retry
                    # loop keys on that — and must not leave the transaction
                    # open on the client after the server has ended it.
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS deferred_child")
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS deferred_parent")
                    DBInterface.execute(conn, "CREATE TABLE deferred_parent (id int PRIMARY KEY)")
                    DBInterface.execute(conn, """
                        CREATE TABLE deferred_child (
                            id int,
                            parent_id int REFERENCES deferred_parent(id) DEFERRABLE INITIALLY DEFERRED
                        )
                    """)
                    for wrapper in (:plain, :helper, :macro)
                        err = try
                            if wrapper === :plain
                                Postgres.start_transaction(conn)
                                DBInterface.execute(conn, "INSERT INTO deferred_child VALUES (1, 999)")
                                Postgres.commit(conn)
                            elseif wrapper === :helper
                                Postgres.transaction(conn) do tx
                                    DBInterface.execute(tx, "INSERT INTO deferred_child VALUES (1, 999)")
                                end
                            else
                                Postgres.@transaction conn begin
                                    DBInterface.execute(conn, "INSERT INTO deferred_child VALUES (1, 999)")
                                end
                            end
                            nothing
                        catch e
                            e
                        end
                        @test err isa Postgres.API.Error
                        @test err.code == "23503"
                        @test !Postgres.in_transaction(conn)
                        # the failed COMMIT's own ReadyForQuery says the
                        # transaction is over; the tracked server status must
                        # not stay stale-true from the preceding INSERT
                        @test !(@lock conn.lock conn.server_in_transaction)
                        @test isempty(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM deferred_child")))
                    end

                    # PostgreSQL changes COMMIT to ROLLBACK when a statement
                    # error was caught inside the body. The helper must not
                    # return the body value as if the write committed.
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS caught_error_tx")
                    DBInterface.execute(conn, "CREATE TABLE caught_error_tx (id int)")
                    for wrapper in (:plain, :helper, :macro)
                        err = try
                            if wrapper === :plain
                                Postgres.start_transaction(conn)
                                DBInterface.execute(conn, "INSERT INTO caught_error_tx VALUES (1)")
                                try
                                    DBInterface.execute(conn, "SELECT 1/0")
                                catch
                                end
                                Postgres.commit(conn)
                            elseif wrapper === :helper
                                Postgres.transaction(conn) do tx
                                    DBInterface.execute(tx, "INSERT INTO caught_error_tx VALUES (1)")
                                    try
                                        DBInterface.execute(tx, "SELECT 1/0")
                                    catch
                                    end
                                    :body_value
                                end
                            else
                                Postgres.@transaction conn begin
                                    DBInterface.execute(conn, "INSERT INTO caught_error_tx VALUES (1)")
                                    try
                                        DBInterface.execute(conn, "SELECT 1/0")
                                    catch
                                    end
                                    :body_value
                                end
                            end
                            nothing
                        catch e
                            e
                        end
                        @test err isa Postgres.PostgresInterfaceError
                        @test occursin("completed ROLLBACK", sprint(showerror, err))
                        @test !Postgres.in_transaction(conn)
                        @test isempty(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM caught_error_tx")))
                    end

                    # a transaction opened with raw SQL belongs to the caller:
                    # driver helpers must nest inside it (savepoints), never
                    # commit it, and never destroy it on their rollback
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS rawtx_test")
                    DBInterface.execute(conn, "CREATE TABLE rawtx_test (id int)")
                    DBInterface.execute(conn, "BEGIN")
                    DBInterface.execute(conn, "INSERT INTO rawtx_test VALUES (1)")
                    Postgres.transaction(conn) do tx
                        DBInterface.execute(tx, "INSERT INTO rawtx_test VALUES (2)")
                    end
                    # a failing block rolls back only its own level, leaving
                    # the caller's transaction alive and usable
                    raw_err = try
                        Postgres.transaction(conn) do tx
                            DBInterface.execute(tx, "INSERT INTO rawtx_test VALUES (3)")
                            DBInterface.execute(tx, "SELECT 1/0")
                        end
                        nothing
                    catch e
                        e
                    end
                    @test raw_err isa Postgres.API.Error
                    # a cursor sees the open transaction and must not own
                    # (and so commit) it on close — nor start any driver-level
                    # nesting of its own
                    raw_cur = Postgres.cursor(conn, "SELECT id FROM rawtx_test ORDER BY id"; fetchsize=1)
                    @test !Postgres.in_transaction(conn)
                    @test [row.id for row in raw_cur] == [1, 2]
                    DBInterface.close!(raw_cur)
                    @test @lock conn.lock conn.server_in_transaction
                    # the caller's ROLLBACK is still in control of all of it
                    DBInterface.execute(conn, "ROLLBACK")
                    @test isempty(Tables.rowtable(DBInterface.execute(conn, "SELECT id FROM rawtx_test")))

                    # Driver savepoints must not shadow a caller savepoint with
                    # the same name. A failed helper must also release its own
                    # savepoint after rolling back to it.
                    DBInterface.execute(conn, "BEGIN")
                    DBInterface.execute(conn, "SAVEPOINT sp_0")
                    DBInterface.execute(conn, "INSERT INTO rawtx_test VALUES (10)")
                    @test_throws ErrorException Postgres.transaction(conn) do tx
                        DBInterface.execute(tx, "INSERT INTO rawtx_test VALUES (20)")
                        error("fail nested work")
                    end
                    DBInterface.execute(conn, "ROLLBACK TO SAVEPOINT sp_0")
                    @test isempty(Tables.rowtable(DBInterface.execute(conn, "SELECT id FROM rawtx_test")))
                    DBInterface.execute(conn, "ROLLBACK")
                    # ... and after a raw COMMIT, the driver-level work sticks
                    DBInterface.execute(conn, "BEGIN")
                    Postgres.transaction(conn) do tx
                        DBInterface.execute(tx, "INSERT INTO rawtx_test VALUES (4)")
                    end
                    DBInterface.execute(conn, "COMMIT")
                    @test only(Tables.rowtable(DBInterface.execute(conn, "SELECT id FROM rawtx_test"))).id == 4
                    DBInterface.execute(conn, "DROP TABLE rawtx_test")

                    # COMMIT/ROLLBACK end the transaction server-side even when
                    # they fail, so client state must not be left behind
                    fail_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, reconnect=true)
                    Postgres.start_transaction(fail_conn)
                    close(fail_conn.socket)
                    try
                        Postgres.commit(fail_conn)
                    catch
                        # the connection is gone; the COMMIT cannot be delivered
                    end
                    @test !Postgres.in_transaction(fail_conn)
                    @test Tables.rowtable(DBInterface.execute(fail_conn, "SELECT 1 AS a"))[1].a == 1
                    DBInterface.close!(fail_conn)

                    Postgres.start_transaction(conn)
                    @test_throws Postgres.API.Error DBInterface.execute(conn, "INVALID SQL")
                    Postgres.rollback(conn)

                    # Simple-query protocol messages include CommandComplete
                    # before ReadyForQuery. Verify the driver consumes both and
                    # routes asynchronous notices through the connection style.
                    NOTICE_SEEN[] = false
                    simple_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, style=LoggingStyle())
                    Postgres.API.exec(simple_conn.style, simple_conn.socket, raw"DO $$ BEGIN RAISE NOTICE 'simple query'; END $$;", false)
                    @test NOTICE_SEEN[]
                    @test Tables.rowtable(DBInterface.execute(simple_conn, "SELECT 7 AS a"))[1].a == 7
                    close(simple_conn)
                end

                @testset "Transaction Macro" begin
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS macro_test")
                    DBInterface.execute(conn, "CREATE TABLE macro_test (id SERIAL PRIMARY KEY, value INTEGER)")
                    DBInterface.execute(conn, "INSERT INTO macro_test (value) VALUES (1)")

                    # the macro must evaluate its connection expression once
                    conn_evals = Ref(0)
                    eval_conn = () -> (conn_evals[] += 1; conn)
                    Postgres.@transaction eval_conn() begin
                        DBInterface.execute(conn, "SELECT 1")
                    end
                    @test conn_evals[] == 1

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

                    # An early return must commit before it leaves the caller.
                    early_return = function(c)
                        Postgres.@transaction c begin
                            DBInterface.execute(c, "INSERT INTO macro_test (value) VALUES (4)")
                            return :early
                        end
                        return :late
                    end
                    @test early_return(conn) === :early
                    @test !Postgres.in_transaction(conn)
                    @test only(Tables.rowtable(DBInterface.execute(conn, "SELECT count(*)::int AS n FROM macro_test"))).n == 3
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

                    # ConnectionParams debug/reconnect fields are honored (and
                    # overridable via keyword arguments)
                    params_reconnect = Postgres.ConnectionParams(
                        host=cfg.host,
                        port=cfg.port,
                        user=cfg.user,
                        password=cfg.password,
                        dbname=cfg.dbname,
                        reconnect=true
                    )
                    conn4 = DBInterface.connect(Postgres.Connection, params_reconnect)
                    @test conn4.reconnect
                    @test !conn4.debug
                    DBInterface.close!(conn4)
                    conn5 = DBInterface.connect(Postgres.Connection, params_reconnect; reconnect=false)
                    @test !conn5.reconnect
                    DBInterface.close!(conn5)
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

                    # Retained handles survive eviction and cache disablement,
                    # but private re-prepare must never exceed or repopulate
                    # the configured cache.
                    retained_conn = DBInterface.connect(Postgres.Connection,
                        cfg.host, cfg.user, cfg.password; dbname=cfg.dbname,
                        port=cfg.port, statement_cache_maxsize=1)
                    retained_a = DBInterface.prepare(retained_conn, "SELECT 101 AS n")
                    retained_b = DBInterface.prepare(retained_conn, "SELECT 102 AS n")
                    @test length(Postgres.get_cached_statements(retained_conn)) == 1
                    @test only(DBInterface.execute(retained_a)).n == 101
                    retained_cache = Postgres.get_cached_statements(retained_conn)
                    @test length(retained_cache) == 1
                    @test haskey(retained_cache, "SELECT 102 AS n")
                    replacement_a = DBInterface.prepare(retained_conn, "SELECT 101 AS n")
                    @test only(DBInterface.execute(retained_a)).n == 101
                    @test length(Postgres.get_cached_statements(retained_conn)) == 1
                    Postgres.set_statement_cache_maxsize!(retained_conn, 0)
                    @test only(DBInterface.execute(retained_b)).n == 102
                    @test isempty(Postgres.get_cached_statements(retained_conn))
                    for retained in (retained_a, retained_b, replacement_a)
                        DBInterface.close!(retained)
                    end
                    DBInterface.close!(retained_conn)

                    # Connection-form bulk helpers own and close the private
                    # statements they create when caching is disabled.
                    bulk_conn = DBInterface.connect(Postgres.Connection,
                        cfg.host, cfg.user, cfg.password; dbname=cfg.dbname,
                        port=cfg.port, statement_cache_maxsize=0)
                    DBInterface.execute(bulk_conn, "CREATE TEMP TABLE cache_bulk_test (id int)")
                    for i in 1:3
                        DBInterface.executemany(bulk_conn,
                            raw"INSERT INTO cache_bulk_test VALUES ($1)", ([i],))
                        resultsets = DBInterface.executemultiple(
                            bulk_conn, raw"SELECT $1::int AS n", (i,))
                        @test only(only(resultsets)).n == i
                        prepared_count = only(DBInterface.execute(bulk_conn,
                            "SELECT count(*)::int AS n FROM pg_prepared_statements")).n
                        @test prepared_count == 0
                    end
                    DBInterface.close!(bulk_conn)
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

                @testset "Query Logger (style)" begin
                    log_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, style=LoggingStyle())
                    empty!(LOGGED_EVENTS)
                    rows = Tables.rowtable(DBInterface.execute(log_conn, "SELECT 1 AS a"))
                    @test rows[1].a == 1
                    @test !isempty(LOGGED_EVENTS)
                    @test LOGGED_EVENTS[end].event == :execute
                    @test LOGGED_EVENTS[end].info.success
                    @test_throws Postgres.API.Error DBInterface.execute(log_conn, "INVALID SQL")
                    @test !LOGGED_EVENTS[end].info.success
                    close(log_conn)
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

                    # A connection returned to the pool mid-transaction must not
                    # hand that transaction to the next borrower: their BEGIN
                    # would become a SAVEPOINT and their commit would be lost.
                    Postgres.with_connection(pool) do pooled_conn
                        DBInterface.execute(pooled_conn, "DROP TABLE IF EXISTS pool_tx_test")
                        DBInterface.execute(pooled_conn, "CREATE TABLE pool_tx_test (id int)")
                    end
                    try
                        Postgres.with_connection(pool) do pooled_conn
                            Postgres.start_transaction(pooled_conn)
                            DBInterface.execute(pooled_conn, "INSERT INTO pool_tx_test VALUES (1)")
                            error("abandon the block mid-transaction")
                        end
                    catch
                        # the caller's error propagates; the pool must still be clean
                    end
                    Postgres.with_connection(pool) do pooled_conn
                        @test !Postgres.in_transaction(pooled_conn)
                        Postgres.transaction(pooled_conn) do tx
                            DBInterface.execute(tx, "INSERT INTO pool_tx_test VALUES (2)")
                        end
                    end

                    # ... including a transaction opened by raw SQL, which the
                    # client-side flag never sees
                    try
                        Postgres.with_connection(pool) do pooled_conn
                            DBInterface.execute(pooled_conn, "BEGIN")
                            DBInterface.execute(pooled_conn, "INSERT INTO pool_tx_test VALUES (99)")
                            error("abandon a raw-SQL transaction")
                        end
                    catch
                    end
                    Postgres.with_connection(pool) do pooled_conn
                        rows = Tables.rowtable(DBInterface.execute(pooled_conn, "SELECT id FROM pool_tx_test ORDER BY id"))
                        @test [row.id for row in rows] == [2]
                    end
                    # the abandoned insert rolled back; the committed one landed
                    Postgres.with_connection(pool) do pooled_conn
                        ids = [row.id for row in Tables.rowtable(DBInterface.execute(pooled_conn, "SELECT id FROM pool_tx_test ORDER BY id"))]
                        @test ids == [2]
                    end
                    DBInterface.close!(pool)
                    @test !isopen(pool)
                    @test !isopen(conn_a)
                    @test_throws Postgres.PostgresInterfaceError Postgres.acquire(pool)
                    DBInterface.close!(pool)

                    # Closing a pool is terminal even when a connection is
                    # still checked out. Its later release must close it, not
                    # add it back to the closed pool.
                    active_pool = Postgres.ConnectionPool(Postgres.Connection, cfg.host, cfg.user, cfg.password;
                        dbname=cfg.dbname, port=cfg.port, limit=1)
                    active_conn = Postgres.acquire(active_pool)
                    DBInterface.close!(active_pool)
                    @test isopen(active_conn)
                    Postgres.release(active_pool, active_conn)
                    @test !isopen(active_conn)
                    @test_throws Postgres.PostgresInterfaceError Postgres.acquire(active_pool)
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

                    # a raw-SQL transaction open at disconnect died with the
                    # session; the tracked server status must not survive the
                    # reconnect, or the next pool release issues a spurious
                    # ROLLBACK on the fresh session
                    tx_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, reconnect=true)
                    DBInterface.execute(tx_conn, "BEGIN")
                    @test @lock tx_conn.lock tx_conn.server_in_transaction
                    close(tx_conn.socket)
                    # trigger the reconnect via checkconn directly: a full
                    # statement would refresh the flag from its own
                    # ReadyForQuery and mask a missing reset
                    @lock tx_conn.lock Postgres.checkconn(tx_conn)
                    @test !(@lock tx_conn.lock tx_conn.server_in_transaction)
                    @test only(Tables.rowtable(DBInterface.execute(tx_conn, "SELECT 1 AS a"))).a == 1
                    DBInterface.close!(tx_conn)
                end

                @testset "Statement Timeout" begin
                    timeout_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, statement_timeout=200)
                    # applied with a post-connect SET (poolers reject it as a
                    # startup option), so confirm it actually took effect
                    @test only(Tables.rowtable(DBInterface.execute(timeout_conn, "SELECT current_setting('statement_timeout') AS t"))).t == "200ms"
                    @test_throws Postgres.API.Error DBInterface.execute(timeout_conn, "SELECT pg_sleep(1)")
                    Postgres.set_statement_timeout!(timeout_conn, 0)
                    @test Postgres.get_statement_timeout(timeout_conn) == 0
                    Postgres.start_transaction(timeout_conn)
                    @test_throws Postgres.PostgresInterfaceError Postgres.set_statement_timeout!(timeout_conn, 777)
                    @test Postgres.get_statement_timeout(timeout_conn) == 0
                    Postgres.rollback(timeout_conn)
                    rows = Tables.rowtable(DBInterface.execute(timeout_conn, "SELECT 1 AS a"))
                    @test rows[1].a == 1
                    DBInterface.close!(timeout_conn)
                end

                @testset "Server Parameters And UTF8 Startup" begin
                    original_app = only(DBInterface.execute(conn,
                        "SELECT current_setting('application_name') AS value")).value
                    @test Postgres.get_server_parameter(conn, "application_name") == original_app
                    try
                        DBInterface.execute(conn, "SET application_name = 'postgres_jl_changed'")
                        @test Postgres.get_server_parameter(conn, "application_name") == "postgres_jl_changed"
                        Postgres.start_transaction(conn)
                        DBInterface.execute(conn, "SET LOCAL application_name = 'postgres_jl_local'")
                        @test Postgres.get_server_parameter(conn, "application_name") == "postgres_jl_local"
                        Postgres.commit(conn)
                        @test Postgres.get_server_parameter(conn, "application_name") == "postgres_jl_changed"
                    finally
                        Postgres.in_transaction(conn) && Postgres.rollback(conn)
                        DBInterface.execute(conn, "RESET application_name")
                    end
                    @test Postgres.get_server_parameter(conn, "application_name") == original_app

                    dangerous_literal = "\\' OR true --"
                    try
                        DBInterface.execute(conn, "SET standard_conforming_strings = off")
                        @test Postgres.get_server_parameter(conn,
                            "standard_conforming_strings") == "off"
                        literal_row = only(DBInterface.execute(conn,
                            "SELECT $(Postgres.escape_literal(dangerous_literal))::text AS value"))
                        @test literal_row.value == dangerous_literal
                    finally
                        DBInterface.execute(conn, "RESET standard_conforming_strings")
                    end

                    role_name = "postgres_jl_utf8_" * replace(string(uuid4()), "-" => "")
                    role_ident = Postgres.escape_identifier(role_name)
                    role_conn = nothing
                    DBInterface.execute(conn, "CREATE ROLE $role_ident LOGIN PASSWORD 'postgres_jl_test'")
                    try
                        DBInterface.execute(conn,
                            "ALTER ROLE $role_ident SET client_encoding = 'LATIN1'")
                        DBInterface.execute(conn,
                            "ALTER ROLE $role_ident SET statement_timeout = '444ms'")
                        role_conn = DBInterface.connect(Postgres.Connection, cfg.host,
                            role_name, "postgres_jl_test"; dbname=cfg.dbname,
                            port=cfg.port, reconnect=true)
                        settings = only(DBInterface.execute(role_conn, """
                            SELECT current_setting('client_encoding') AS encoding,
                                   current_setting('statement_timeout') AS timeout
                        """))
                        @test settings.encoding == "UTF8"
                        @test settings.timeout == "444ms"
                        @test Postgres.get_server_parameter(role_conn,
                            "client_encoding") == "UTF8"
                        @test only(DBInterface.execute(role_conn,
                            raw"SELECT $1::text AS value", ("雪",))).value == "雪"

                        # An explicit disable must override the role default on
                        # this session and after automatic reconnect.
                        Postgres.set_statement_timeout!(role_conn, nothing)
                        @test Postgres.get_statement_timeout(role_conn) == 0
                        close(role_conn.socket)
                        @test only(DBInterface.execute(role_conn,
                            "SELECT current_setting('statement_timeout') AS value")).value == "0"
                    finally
                        role_conn === nothing || DBInterface.close!(role_conn)
                        DBInterface.execute(conn, "DROP ROLE IF EXISTS $role_ident")
                    end
                end


                @testset "Query Logger Isolation" begin
                    FAILING_LOGGER_CALLS[] = 0
                    log_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password;
                        dbname=cfg.dbname, port=cfg.port, style=FailingLoggerStyle())
                    try
                        @test_logs (:warn, r"query logger failed") DBInterface.execute(log_conn, "CREATE TEMP TABLE logger_test (id int)")
                        calls = FAILING_LOGGER_CALLS[]
                        @test_logs (:warn, r"query logger failed") DBInterface.execute(log_conn, "INSERT INTO logger_test VALUES (1)")
                        @test FAILING_LOGGER_CALLS[] == calls + 1
                        @test_logs (:warn, r"query logger failed") begin
                            @test only(Tables.rowtable(DBInterface.execute(log_conn, "SELECT count(*)::int AS n FROM logger_test"))).n == 1
                        end
                    finally
                        DBInterface.close!(log_conn)
                    end
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
                    # A notification delivered while the same connection runs
                    # queries must not desync the stream: the async message
                    # arrives interleaved with the query's own messages, and
                    # its body has to be consumed rather than read as the next
                    # message header. Repeated so the notification is unlikely
                    # to land after every query and pass vacuously.
                    interleaved_ok = true
                    for i in 1:5
                        Postgres.notify!(notifier, "notify_test", "interleaved $i")
                        sleep(0.1)
                        interleaved_ok &= Tables.rowtable(DBInterface.execute(listener, "SELECT $i AS a"))[1].a == i
                        interleaved_ok &= isopen(listener)
                        interleaved_ok || break
                    end
                    @test interleaved_ok

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

                    # an invalid COPY statement errors (instead of hanging) and
                    # leaves the connection usable
                    @test_throws Postgres.API.Error Postgres.copy_from(conn, "COPY nonexistent_copy_tbl FROM STDIN", "1\n")
                    @test Tables.rowtable(DBInterface.execute(conn, "SELECT 1 AS a"))[1].a == 1

                    # non-COPY, wrong-direction, and multi-statement COPY calls
                    # are rejected cleanly, without desyncing or deadlocking
                    @test_throws Postgres.PostgresInterfaceError Postgres.copy_from(conn, "SELECT 1", "1\n")
                    @test_throws Postgres.PostgresInterfaceError Postgres.copy_to(conn, "SELECT 1")
                    @test_throws Postgres.PostgresInterfaceError Postgres.copy_from(conn, "COPY copy_test TO STDOUT", "1\talpha\n")
                    @test_throws Postgres.PostgresInterfaceError Postgres.copy_to(conn, "COPY copy_test FROM STDIN")
                    @test_throws Postgres.PostgresInterfaceError Postgres.copy_from(conn, "COPY copy_test (id, name) FROM STDIN; COPY copy_test (id, name) FROM STDIN", "9\tomega\n")
                    @test_throws Postgres.PostgresInterfaceError Postgres.copy_from(conn,
                        "COPY copy_test (id, name) FROM STDIN; COPY copy_test TO STDOUT",
                        "10\tmixed\n")
                    @test_throws Postgres.PostgresInterfaceError Postgres.copy_to(conn,
                        "COPY (SELECT 7) TO STDOUT; COPY (SELECT 8) TO STDOUT")
                    @test_throws Postgres.PostgresInterfaceError Postgres.copy_to(conn,
                        "COPY (SELECT 7) TO STDOUT; SELECT 8")
                    @test Tables.rowtable(DBInterface.execute(conn, "SELECT 2 AS a"))[1].a == 2

                    # a genuine mid-stream server error during copy-out wins
                    # over the misuse error and the connection stays usable
                    @test_throws Postgres.API.Error Postgres.copy_to(conn, "COPY (SELECT 1/0) TO STDOUT")

                    # a failing user data source aborts the copy with CopyFail
                    # and the connection stays usable
                    @test_throws ErrorException Postgres.copy_from(conn, "COPY copy_test (id, name) FROM STDIN", ThrowingSource())
                    @test Tables.rowtable(DBInterface.execute(conn, "SELECT 5 AS a"))[1].a == 5

                    # a failing dest IO mid copy-out closes the connection
                    # instead of leaving a desynced socket that looks usable
                    conn_copyfail = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port)
                    DBInterface.execute(conn_copyfail, "CREATE TEMP TABLE copy_out_fail (id int)")
                    DBInterface.execute(conn_copyfail, "INSERT INTO copy_out_fail VALUES (1), (2)")
                    @test_throws ErrorException Postgres.copy_to(conn_copyfail, "COPY copy_out_fail TO STDOUT", FailingDest())
                    @test !isopen(conn_copyfail.socket)
                    DBInterface.close!(conn_copyfail)

                    # COPY via execute throws a clear client error pointing at
                    # copy_from/copy_to and keeps the connection usable
                    err = try
                        DBInterface.execute(conn, "COPY copy_test FROM STDIN")
                        nothing
                    catch e
                        e
                    end
                    @test err isa Postgres.PostgresInterfaceError
                    @test occursin("copy_from", err.msg)
                    err = try
                        DBInterface.execute(conn, "COPY copy_test TO STDOUT")
                        nothing
                    catch e
                        e
                    end
                    @test err isa Postgres.PostgresInterfaceError
                    @test occursin("copy_to", err.msg)
                    @test Tables.rowtable(DBInterface.execute(conn, "SELECT 3 AS a"))[1].a == 3

                    # COPY via cursor errors cleanly, keeps the connection
                    # usable, and doesn't leave its transaction open
                    @test_throws Postgres.PostgresInterfaceError Postgres.cursor(conn, "COPY copy_test TO STDOUT")
                    @test !Postgres.in_transaction(conn)
                    @test_throws Postgres.PostgresInterfaceError Postgres.cursor(conn, "COPY copy_test FROM STDIN")
                    @test !Postgres.in_transaction(conn)
                    @test Tables.rowtable(DBInterface.execute(conn, "SELECT 4 AS a"))[1].a == 4
                end

                @testset "Cursor Streaming" begin
                    cur = Postgres.cursor(conn, "SELECT generate_series(1, 5) AS n"; fetchsize=2)
                    values = [row.n for row in cur]
                    @test values == [1, 2, 3, 4, 5]
                    DBInterface.close!(cur)
                    @test !Postgres.in_transaction(conn)

                    # The documented Statement overload must own a transaction
                    # when called outside one, or the first Sync drops a
                    # suspended multi-batch portal.
                    cursor_stmt = DBInterface.prepare(conn,
                        "SELECT generate_series(1, 5) AS n")
                    statement_cursor = Postgres.cursor(cursor_stmt; fetchsize=2)
                    @test [row.n for row in statement_cursor] == [1, 2, 3, 4, 5]
                    DBInterface.close!(statement_cursor)
                    @test !Postgres.in_transaction(conn)
                    @test first(DBInterface.execute(cursor_stmt)).n == 1
                    DBInterface.close!(cursor_stmt)

                    mismatch_cursor_stmt = DBInterface.prepare(conn,
                        raw"SELECT $1::text AS a, $2::text AS b")
                    @test_throws Postgres.PostgresInterfaceError Postgres.cursor(
                        mismatch_cursor_stmt, ("must-not-remain",); fetchsize=1)
                    @test all(ismissing, mismatch_cursor_stmt.params)
                    @test !Postgres.in_transaction(conn)
                    DBInterface.close!(mismatch_cursor_stmt)

                    # A fully exhausted named portal still exists until Close
                    # or transaction end. Cursor close must release it now,
                    # even inside a caller-owned long transaction.
                    Postgres.start_transaction(conn)
                    portal_stmt = DBInterface.prepare(conn,
                        "SELECT generate_series(1, 5) AS n")
                    portal_cursor = Postgres.cursor(portal_stmt; fetchsize=2)
                    @test length(collect(portal_cursor)) == 5
                    portal_name = portal_cursor.portal
                    @test only(DBInterface.execute(conn,
                        "SELECT count(*)::int AS n FROM pg_cursors WHERE name = \$1",
                        (portal_name,))).n == 1
                    DBInterface.close!(portal_cursor)
                    @test only(DBInterface.execute(conn,
                        "SELECT count(*)::int AS n FROM pg_cursors WHERE name = \$1",
                        (portal_name,))).n == 0
                    DBInterface.close!(portal_stmt)
                    Postgres.rollback(conn)

                    # With caching disabled, the connection-form cursor owns
                    # its private prepared statement and closes it with the
                    # portal.
                    private_cursor_conn = DBInterface.connect(Postgres.Connection,
                        cfg.host, cfg.user, cfg.password; dbname=cfg.dbname,
                        port=cfg.port, statement_cache_maxsize=0)
                    private_cursor = Postgres.cursor(private_cursor_conn,
                        "SELECT generate_series(1, 3) AS n"; fetchsize=1)
                    @test length(collect(private_cursor)) == 3
                    DBInterface.close!(private_cursor)
                    @test only(DBInterface.execute(private_cursor_conn,
                        "SELECT count(*)::int AS n FROM pg_prepared_statements")).n == 0
                    DBInterface.close!(private_cursor_conn)

                    # closing an already-closed cursor must not reach into a
                    # transaction the caller opened afterwards and commit it
                    DBInterface.execute(conn, "DROP TABLE IF EXISTS cursor_reclose")
                    DBInterface.execute(conn, "CREATE TABLE cursor_reclose (id int)")
                    Postgres.start_transaction(conn)
                    DBInterface.execute(conn, "INSERT INTO cursor_reclose VALUES (1)")
                    DBInterface.close!(cur)
                    @test Postgres.in_transaction(conn)
                    Postgres.rollback(conn)
                    @test isempty(Tables.rowtable(DBInterface.execute(conn, "SELECT * FROM cursor_reclose")))

                    # a cursor over a dead connection must not leave transaction
                    # state behind, which would block reconnect forever
                    dead_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, reconnect=true)
                    dead_cur = Postgres.cursor(dead_conn, "SELECT generate_series(1, 100) AS n"; fetchsize=2)
                    close(dead_conn.socket)
                    try
                        DBInterface.close!(dead_cur)
                    catch
                        # closing the portal on a dead socket may throw
                    end
                    @test !Postgres.in_transaction(dead_conn)
                    @test Tables.rowtable(DBInterface.execute(dead_conn, "SELECT 1 AS a"))[1].a == 1
                    DBInterface.close!(dead_conn)
                end

                @testset "Notice Callback (style)" begin
                    NOTICE_SEEN[] = false
                    notice_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port, style=LoggingStyle())
                    DBInterface.execute(notice_conn, raw"DO $$ BEGIN RAISE NOTICE 'hello'; END $$;")
                    close(notice_conn)
                    @test NOTICE_SEEN[]
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

                    # the cancel key must never go out in the clear when the
                    # connection it cancels required TLS; the refusal is a
                    # thrown error, not a silent no-op (this server has no SSL,
                    # so it answers the SSLRequest with 'N')
                    @test_throws Postgres.PostgresInterfaceError Postgres.API.cancel_request(cfg.host, cfg.port, Int32(1), Int32(1), false, "require")
                    @test_throws Postgres.PostgresInterfaceError Postgres.API.cancel_request(cfg.host, cfg.port, Int32(1), Int32(1), false, "verify-full")
                    # a cleartext-allowed cancel still delivers
                    @test Postgres.API.cancel_request(cfg.host, cfg.port, Int32(1), Int32(1), false, "disable")
                end

                @testset "Timestamp Ranges And char" begin
                    ts_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '[2020-01-01 00:00:00,2020-01-02 00:00:00)'::tsrange AS r")))
                    @test ts_row.r.lower == DateTime(2020, 1, 1)
                    @test ts_row.r.upper == DateTime(2020, 1, 2)
                    # "char" columns holding the zero value appear throughout
                    # the system catalogs
                    cat_rows = Tables.rowtable(DBInterface.execute(conn, "SELECT attidentity FROM pg_attribute LIMIT 5"))
                    @test length(cat_rows) == 5
                    # high-bit "char" values arrive as backslash-octal escapes
                    oct_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT (-1)::\"char\" AS c1, (-128)::\"char\" AS c2, 'a'::\"char\" AS c3, 0::\"char\" AS c4")))
                    @test oct_row.c1 == Char(0xff)
                    @test oct_row.c2 == Char(0x80)
                    @test oct_row.c3 == 'a'
                    @test oct_row.c4 == '\0'
                    # "char"[] round-trips too, escapes and zero included
                    chararr_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT ARRAY['a'::\"char\", 0::\"char\", (-1)::\"char\"] AS a")))
                    @test isequal(collect(chararr_row.a), Any['a', '\0', Char(0xff)])

                    # years beyond 9999 and BC dates: wide years decode, BC
                    # fails loudly, and neither poisons the connection
                    big_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '10000-01-01'::date AS d, '10000-01-02 03:04:05'::timestamp AS t")))
                    @test big_row.d == Date(10000, 1, 1)
                    @test big_row.t == DateTime(10000, 1, 2, 3, 4, 5)
                    @test_throws Postgres.PostgresInterfaceError Tables.rowtable(DBInterface.execute(conn, "SELECT '0044-03-15 BC'::date AS d"))
                    @test only(Tables.rowtable(DBInterface.execute(conn, "SELECT 1 AS ok"))).ok == 1
                    # an interval in a foreign IntervalStyle fails loudly too,
                    # at a message boundary the connection can recover from
                    DBInterface.execute(conn, "SET IntervalStyle = 'sql_standard'")
                    try
                        @test_throws Postgres.PostgresInterfaceError Tables.rowtable(DBInterface.execute(conn, "SELECT '1 day 2 hours'::interval AS i"))
                    finally
                        DBInterface.execute(conn, "SET IntervalStyle = 'postgres'")
                    end
                    @test only(Tables.rowtable(DBInterface.execute(conn, "SELECT '1 day'::interval AS i"))).i == Dates.Day(1)

                    # postgres's time '24:00:00' has no Julia representation
                    @test_throws Postgres.PostgresInterfaceError Tables.rowtable(DBInterface.execute(conn, "SELECT '24:00:00'::time AS t"))
                    # LMT-era timestamptz offsets carry seconds ("+05:21:10");
                    # dropping them silently shifted the value
                    DBInterface.execute(conn, "SET TimeZone = 'Asia/Kolkata'")
                    try
                        lmt_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT '1880-01-01 00:00:00+00'::timestamptz AS t")))
                        @test lmt_row.t == DateTime(1880, 1, 1, 0, 0, 0)
                    finally
                        DBInterface.execute(conn, "RESET TimeZone")
                    end
                    # the session uses ISO dates and postgres intervals, which
                    # the text parsers require
                    style_row = only(Tables.rowtable(DBInterface.execute(conn, "SELECT current_setting('DateStyle') AS ds, current_setting('IntervalStyle') AS is")))
                    @test startswith(style_row.ds, "ISO")
                    @test style_row.is == "postgres"

                    # a server whose default is not ISO is corrected at connect
                    # rather than silently producing unparseable dates
                    DBInterface.execute(conn, "ALTER DATABASE $(cfg.dbname) SET DateStyle = 'German, DMY'")
                    DBInterface.execute(conn, "ALTER DATABASE $(cfg.dbname) SET IntervalStyle = 'sql_standard'")
                    try
                        german_conn = DBInterface.connect(Postgres.Connection, cfg.host, cfg.user, cfg.password; dbname=cfg.dbname, port=cfg.port)
                        try
                            row = only(Tables.rowtable(DBInterface.execute(german_conn, "SELECT '2020-03-04 05:06:07'::timestamp AS t, '1 day'::interval AS i")))
                            @test row.t == DateTime(2020, 3, 4, 5, 6, 7)
                            @test row.i == Dates.Day(1)
                            # the correction must keep the configured DMY field
                            # order: reading '01/02/2020' as MDY would silently
                            # turn the user's 1 February into January 2
                            order_row = only(Tables.rowtable(DBInterface.execute(german_conn, "SELECT current_setting('DateStyle') AS ds, '01/02/2020'::date AS d")))
                            @test order_row.ds == "ISO, DMY"
                            @test order_row.d == Date(2020, 2, 1)
                            @test Postgres.get_server_parameter(german_conn, "DateStyle") == "ISO, DMY"
                            @test Postgres.get_server_parameter(german_conn, "IntervalStyle") == "postgres"
                        finally
                            DBInterface.close!(german_conn)
                        end
                    finally
                        DBInterface.execute(conn, "ALTER DATABASE $(cfg.dbname) RESET DateStyle")
                        DBInterface.execute(conn, "ALTER DATABASE $(cfg.dbname) RESET IntervalStyle")
                    end
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

                    ca_dir = joinpath(tls.certdir, "ca-directory")
                    mkpath(ca_dir)
                    cp(tls.rootcert, joinpath(ca_dir, "root.crt"))
                    capath_conn = DBInterface.connect(Postgres.Connection,
                        ssl_cfg.host, ssl_cfg.user, ssl_cfg.password;
                        dbname=ssl_cfg.dbname, port=ssl_cfg.port,
                        sslmode="verify-full", sslcapath=ca_dir)
                    try
                        @test connection_uses_ssl(capath_conn)
                    finally
                        DBInterface.close!(capath_conn)
                    end

                    # Require and verify a client certificate for one role.
                    # This covers the TLS 1.2 mTLS path and the cancel request,
                    # which must present the same client identity.
                    mtls_admin = DBInterface.connect(Postgres.Connection,
                        ssl_cfg.host, ssl_cfg.user, ssl_cfg.password;
                        dbname=ssl_cfg.dbname, port=ssl_cfg.port, sslmode="require")
                    try
                        DBInterface.execute(mtls_admin, "DROP ROLE IF EXISTS postgres_mtls")
                        DBInterface.execute(mtls_admin, "CREATE ROLE postgres_mtls LOGIN")
                        no_cert_error = try
                            no_cert_conn = DBInterface.connect(Postgres.Connection,
                                ssl_cfg.host, "postgres_mtls", nothing;
                                dbname=ssl_cfg.dbname, port=ssl_cfg.port,
                                sslmode="verify-full", sslrootcert=tls.rootcert)
                            DBInterface.close!(no_cert_conn)
                            nothing
                        catch err
                            err
                        end
                        @test no_cert_error !== nothing

                        mtls_conn = DBInterface.connect(Postgres.Connection,
                            ssl_cfg.host, "postgres_mtls", nothing;
                            dbname=ssl_cfg.dbname, port=ssl_cfg.port,
                            sslmode="verify-full", sslrootcert=tls.rootcert,
                            sslcert=tls.clientcert, sslkey=tls.clientkey)
                        try
                            tls_row = only(DBInterface.execute(mtls_conn, """
                                SELECT ssl, version, client_dn
                                FROM pg_stat_ssl
                                WHERE pid = pg_backend_pid()
                            """))
                            @test tls_row.ssl
                            @test tls_row.version == "TLSv1.2"
                            @test occursin("CN=postgres_mtls", tls_row.client_dn)

                            mtls_task = errormonitor(Threads.@spawn begin
                                try
                                    DBInterface.execute(mtls_conn, "SELECT pg_sleep(5)")
                                    :completed
                                catch err
                                    err
                                end
                            end)
                            sleep(0.5)
                            Postgres.cancel_query!(mtls_conn)
                            mtls_result = fetch(mtls_task)
                            @test mtls_result isa Postgres.API.Error
                            @test mtls_result.code == "57014"
                        finally
                            DBInterface.close!(mtls_conn)
                        end
                    finally
                        DBInterface.execute(mtls_admin, "DROP ROLE IF EXISTS postgres_mtls")
                        DBInterface.close!(mtls_admin)
                    end

                    # against a TLS-capable server the cancel key goes over TLS
                    # and the request is delivered. The connection uses the
                    # default sslmode ("prefer") but negotiates TLS, so this
                    # also covers the cancel path upgrading itself to require
                    # TLS — which has to happen while the query being cancelled
                    # holds the connection lock.
                    @test Postgres.API.cancel_request(ssl_cfg.host, ssl_cfg.port, Int32(1), Int32(1), false, "require")
                    # LISTEN/NOTIFY over TLS: the read deadline surfaces as a
                    # wrapped TLSError rather than a bare DeadlineExceededError,
                    # so the poll loop must recognize it — and must not leave an
                    # expired deadline set, which would kill the connection.
                    ssl_listener = wait_for_connection(ssl_cfg; sslmode="require")
                    ssl_notifier = wait_for_connection(ssl_cfg; sslmode="require")
                    try
                        Postgres.listen!(ssl_listener, "tls_notify_test")
                        @test Postgres.wait_for_notification(ssl_listener; timeout=0.3) === nothing
                        # the connection survives an elapsed poll deadline
                        @test Tables.rowtable(DBInterface.execute(ssl_listener, "SELECT 1 AS a"))[1].a == 1
                        Postgres.notify!(ssl_notifier, "tls_notify_test", "over-tls")
                        tls_notification = Postgres.wait_for_notification(ssl_listener; timeout=5.0)
                        @test tls_notification !== nothing
                        @test tls_notification.channel == "tls_notify_test"
                        @test tls_notification.payload == "over-tls"
                        @test Tables.rowtable(DBInterface.execute(ssl_listener, "SELECT 2 AS a"))[1].a == 2
                    finally
                        isopen(ssl_notifier) && DBInterface.close!(ssl_notifier)
                        isopen(ssl_listener) && DBInterface.close!(ssl_listener)
                    end

                    ssl_cancel_conn = DBInterface.connect(Postgres.Connection, ssl_cfg.host, ssl_cfg.user, ssl_cfg.password; dbname=ssl_cfg.dbname, port=ssl_cfg.port)
                    @test ssl_cancel_conn.socket isa Postgres.Reseau.TLS.Conn
                    try
                        ssl_task = errormonitor(Threads.@spawn begin
                            try
                                DBInterface.execute(ssl_cancel_conn, "SELECT pg_sleep(5)")
                                return :completed
                            catch err
                                return err
                            end
                        end)
                        sleep(0.5)
                        Postgres.cancel_query!(ssl_cancel_conn)
                        ssl_result = fetch(ssl_task)
                        @test ssl_result isa Postgres.API.Error
                        @test ssl_result.code == "57014"
                    finally
                        isopen(ssl_cancel_conn) && DBInterface.close!(ssl_cancel_conn)
                    end

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
