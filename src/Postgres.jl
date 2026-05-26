module Postgres

using DBInterface, Dates, UUIDs, Parsers, Tables, StructUtils, JSON, ConcurrentUtilities, Reseau

export DBInterface, PostgresInterfaceError, start_transaction, commit, rollback, in_transaction, transaction, ConnectionParams, parse_dsn, get_cached_statements, clear_statement_cache!, set_statement_cache_maxsize!, get_server_parameter, get_server_parameters, Error, Notification, Numeric, PostgresRange, register_type!, register_enum!, register_composite!, register_range!, set_notice_callback!, get_notice_callback, set_notification_callback!, get_notification_callback, set_query_logger!, get_query_logger, set_statement_timeout!, get_statement_timeout, copy_from, copy_to, listen!, unlisten!, notify!, wait_for_notification, cursor, ConnectionPool, acquire, release, with_connection, command_tag, rows_affected

# For non-api errors that happen in Postgres.jl
struct PostgresInterfaceError
    msg::String
end
Base.showerror(io::IO, e::PostgresInterfaceError) = print(io, e.msg)

include("api/API.jl")
using .API
include("connection_string.jl")
using .ConnectionString

const Pools = ConcurrentUtilities.Pools
const NOOP_QUERY_LOGGER = (event, info) -> nothing
const ReseauConn = Union{Reseau.TCP.Conn, Reseau.TLS.Conn}

# T parameter is always Statement
mutable struct Connection{IO, T} <: DBInterface.Connection
    const lock::ReentrantLock
    socket::IO
    const host::String
    const user::String
    const password::Union{String, Nothing}
    const dbname::String
    const port::Int
    const application_name::Union{String, Nothing}
    const connect_timeout::Union{Int, Nothing}
    const sslmode::Union{String, Nothing}
    const sslrootcert::Union{String, Nothing}
    const sslcert::Union{String, Nothing}
    const sslkey::Union{String, Nothing}
    const sslcapath::Union{String, Nothing}
    statement_timeout::Union{Int, Nothing}
    # pid/skey are used to send cancellation request to backend
    pid::Int32
    skey::Int32
    statements::Dict{String, T} # sql string -> Statement (LRU managed)
    statement_cache_maxsize::Int # max statements to cache
    statement_clock::Int # increments on statement usage for LRU
    server_parameters::Dict{String, String} # server parameters from ParameterStatus messages
    type_registry::Dict{Int, API.TypeInfo} # per-connection type registry
    closed::Bool # if explicitly closed by user; guarded by lock
    const reconnect::Bool
    debug::Bool
    notice_callback::Function # callback for NOTICE messages
    notification_callback::Function # callback for NOTIFY messages
    query_logger::Function # callback for query/copy events
    in_transaction::Bool # track transaction state
    transaction_depth::Int # track nested transactions (SAVEPOINTs)
    generation::Int # increment on reconnect to invalidate statements

    function Connection(; host::AbstractString="", user::AbstractString="", password::Union{AbstractString, Nothing}=nothing, dbname::AbstractString="", port::Integer=5432, debug::Bool=false, reconnect::Bool=false, application_name::Union{AbstractString, Nothing}=nothing, connect_timeout::Union{Integer, Nothing}=nothing, sslmode::Union{AbstractString, Nothing}=nothing, sslrootcert::Union{AbstractString, Nothing}=nothing, sslcert::Union{AbstractString, Nothing}=nothing, sslkey::Union{AbstractString, Nothing}=nothing, sslcapath::Union{AbstractString, Nothing}=nothing, statement_timeout::Union{Integer, Nothing}=nothing, statement_cache_maxsize::Integer=100)
        host = String(host)
        user = String(user)
        dbname = String(dbname)
        port = Int(port)
        password = password === nothing ? nothing : String(password)
        app_name = application_name === nothing ? nothing : String(application_name)
        timeout = connect_timeout === nothing ? nothing : Int(connect_timeout)
        sslmode_val = sslmode === nothing ? nothing : String(sslmode)
        sslrootcert_val = sslrootcert === nothing ? nothing : String(sslrootcert)
        sslcert_val = sslcert === nothing ? nothing : String(sslcert)
        sslkey_val = sslkey === nothing ? nothing : String(sslkey)
        sslcapath_val = sslcapath === nothing ? nothing : String(sslcapath)
        statement_timeout_val = statement_timeout === nothing ? nothing : Int(statement_timeout)
        maxsize = max(0, Int(statement_cache_maxsize))
        #TODO: if values have spaces, need to single-quote them
        # also need to escape single quotes/backslahes then with backslashes
        socket, pid, skey, server_params = API.connect(host, port, dbname, user, password, debug, app_name, timeout, sslmode_val, sslrootcert_val, sslcert_val, sslkey_val, sslcapath_val, statement_timeout_val)
        registry = Dict(API.DEFAULT_TYPE_REGISTRY)
        default_notice_callback = notice -> begin
            msg = get(notice, "M", "")
            !isempty(msg) && @warn msg
            return
        end
        default_notification_callback = notification -> nothing
        default_query_logger = NOOP_QUERY_LOGGER
        return new{typeof(socket), Statement}(ReentrantLock(), socket, host, user, password, dbname, port, app_name, timeout, sslmode_val, sslrootcert_val, sslcert_val, sslkey_val, sslcapath_val, statement_timeout_val, pid, skey, Dict{String, Statement}(), maxsize, 0, server_params, registry, false, reconnect, debug, default_notice_callback, default_notification_callback, default_query_logger, false, 0, 1)
    end
end

Base.isopen(conn::Connection) = @lock conn.lock isopen(conn.socket)

function Base.show(io::IO, conn::Connection)
    println(io, "Postgres.Connection:")
    println(io, "  host = $(conn.host)")
    println(io, "  user = $(conn.user)")
    println(io, "  dbname = $(conn.dbname)")
    println(io, "  port = $(conn.port)")
    isopen(conn) && println(io, "  status = open")
    !isopen(conn) && println(io, "  status = closed")
    println(io, "  in_transaction = $(conn.in_transaction)")
    println(io, "  statement_cache_size = $(length(conn.statements))/$(conn.statement_cache_maxsize)")
    return
end

function next_statement_clock!(conn::Connection)
    conn.statement_clock += 1
    return conn.statement_clock
end

function touch_statement!(conn::Connection, stmt)
    stmt.last_used = next_statement_clock!(conn)
    return
end

function evict_lru_statement!(conn::Connection)
    isempty(conn.statements) && return
    oldest_sql = nothing
    oldest_stamp = typemax(Int)
    for (sql, stmt) in conn.statements
        if stmt.last_used < oldest_stamp
            oldest_stamp = stmt.last_used
            oldest_sql = sql
        end
    end
    oldest_sql === nothing && return
    stmt = pop!(conn.statements, oldest_sql)
    !stmt.closed && API.close_statement(conn.socket, stmt.name, conn.debug)
    return
end

function log_query(logger::Function, event::Symbol, info::NamedTuple)
    logger(event, info)
    return
end

function get_cached_statements(conn::Connection)
    @lock conn.lock copy(conn.statements)
end

function clear_statement_cache!(conn::Connection)
    @lock conn.lock begin
        for (sql, stmt) in conn.statements
            !stmt.closed && API.close_statement(conn.socket, stmt.name, conn.debug)
        end
        empty!(conn.statements)
    end
    return conn
end

function set_statement_cache_maxsize!(conn::Connection, maxsize::Integer)
    @lock conn.lock begin
        conn.statement_cache_maxsize = max(0, Int(maxsize))
        if conn.statement_cache_maxsize == 0
            for (sql, stmt) in conn.statements
                !stmt.closed && API.close_statement(conn.socket, stmt.name, conn.debug)
            end
            empty!(conn.statements)
            return conn
        end
        # Evict if necessary
        while length(conn.statements) > conn.statement_cache_maxsize
            evict_lru_statement!(conn)
        end
    end
    return conn
end

get_server_parameter(conn::Connection, param::String) = @lock conn.lock get(conn.server_parameters, param, nothing)

get_server_parameters(conn::Connection) = @lock conn.lock copy(conn.server_parameters)

set_notice_callback!(conn::Connection, f::Function) = @lock conn.lock begin
    conn.notice_callback = f
    return conn
end

function get_notice_callback(conn::Connection)
    return @lock conn.lock conn.notice_callback
end

set_notification_callback!(conn::Connection, f::Function) = @lock conn.lock begin
    conn.notification_callback = f
    return conn
end

function get_notification_callback(conn::Connection)
    return @lock conn.lock conn.notification_callback
end

set_query_logger!(conn::Connection, f::Function) = @lock conn.lock begin
    conn.query_logger = f
    return conn
end

function get_query_logger(conn::Connection)
    return @lock conn.lock conn.query_logger
end

function get_statement_timeout(conn::Connection)
    return @lock conn.lock conn.statement_timeout
end

function set_statement_timeout!(conn::Connection, timeout::Union{Integer, Nothing})
    timeout_val = timeout === nothing ? 0 : max(0, Int(timeout))
    DBInterface.execute(conn, "SET statement_timeout = $timeout_val")
    @lock conn.lock conn.statement_timeout = timeout === nothing ? nothing : timeout_val
    return conn
end

function escape_identifier(name::AbstractString)
    return string("\"", replace(name, "\"" => "\"\""), "\"")
end

function escape_literal(val::AbstractString)
    return string("'", replace(val, "'" => "''"), "'")
end

function listen!(conn::Connection, channel::AbstractString)
    DBInterface.execute(conn, "LISTEN $(escape_identifier(channel))")
    return conn
end

function unlisten!(conn::Connection, channel::AbstractString)
    DBInterface.execute(conn, "UNLISTEN $(escape_identifier(channel))")
    return conn
end

function notify!(conn::Connection, channel::AbstractString, payload::Union{AbstractString, Nothing}=nothing)
    channel_ident = escape_identifier(channel)
    sql = payload === nothing ? "NOTIFY $channel_ident" : "NOTIFY $channel_ident, $(escape_literal(payload))"
    DBInterface.execute(conn, sql)
    return conn
end

function update_server_parameters!(conn::Connection, buf::Vector{UInt8})
    i = 1
    while i < length(buf)
        j = findnext(isequal(UInt8(0)), buf, i)
        j === nothing && break
        key = unsafe_string(pointer(buf, i), j - i)
        i = j + 1
        j = findnext(isequal(UInt8(0)), buf, i)
        j === nothing && break
        val = unsafe_string(pointer(buf, i), j - i)
        conn.server_parameters[key] = val
        i = j + 1
    end
    return
end

@inline function _set_read_deadline!(socket::Reseau.TCP.Conn, deadline_ns::Int64)
    Reseau.TCP.set_read_deadline!(socket, deadline_ns)
    return nothing
end

@inline function _set_read_deadline!(socket::Reseau.TLS.Conn, deadline_ns::Int64)
    Reseau.TLS.set_read_deadline!(socket, deadline_ns)
    return nothing
end

@inline function _clear_read_deadline!(socket::ReseauConn)
    _set_read_deadline!(socket, Int64(0))
    return nothing
end

const NOTIFICATION_POLL_INTERVAL_NS = Int64(100_000_000)

function wait_for_notification(conn::Connection; timeout::Union{Real, Nothing}=nothing)
    start_time = time()
    @lock conn.lock begin
        checkconn(conn)
        while true
            deadline_ns = if timeout === nothing
                Int64(time_ns()) + NOTIFICATION_POLL_INTERVAL_NS
            else
                remaining_s = timeout - (time() - start_time)
                remaining_s <= 0 && return nothing
                Int64(time_ns()) + min(NOTIFICATION_POLL_INTERVAL_NS, round(Int64, remaining_s * 1_000_000_000))
            end
            _set_read_deadline!(conn.socket, deadline_ns)
            try
                mt, len = API.readheader(conn.socket, conn.debug)
                if mt == UInt8('A')
                    notification = API.notificationResponse(len, conn.socket)
                    conn.notification_callback(notification)
                    return notification
                elseif mt == UInt8('N')
                    notice = API.noticeResponse(len, conn.socket)
                    conn.notice_callback(notice)
                elseif mt == UInt8('S')
                    buf = read(conn.socket, len)
                    update_server_parameters!(conn, buf)
                elseif mt == UInt8('E')
                    err = API.errorResponse(len, conn.socket, conn.debug)
                    throw(err)
                else
                    API.skipbytes!(conn.socket, len)
                end
            catch err
                err isa Reseau.IOPoll.DeadlineExceededError || rethrow()
            finally
                _clear_read_deadline!(conn.socket)
            end
        end
    end
end

function copy_from(conn::Connection, sql::AbstractString, data::IO; debug::Bool=false)
    logger = conn.query_logger
    log_enabled = logger !== NOOP_QUERY_LOGGER
    start_ns = log_enabled ? time_ns() : 0
    sql_str = String(sql)
    try
        @lock conn.lock begin
            checkconn(conn)
            API.copy_in(conn.socket, sql_str, data, debug || conn.debug, conn.notice_callback, conn.notification_callback)
        end
        log_enabled && log_query(logger, :copy_from, (sql=sql_str, duration_ns=time_ns() - start_ns, success=true))
    catch err
        log_enabled && log_query(logger, :copy_from, (sql=sql_str, duration_ns=time_ns() - start_ns, success=false, error=err))
        rethrow()
    end
    return conn
end

function copy_from(conn::Connection, sql::AbstractString, data::AbstractString; debug::Bool=false)
    buffer = IOBuffer(data)
    return copy_from(conn, sql, buffer; debug=debug)
end

function copy_from(conn::Connection, sql::AbstractString, data::AbstractVector{UInt8}; debug::Bool=false)
    buffer = IOBuffer(data)
    return copy_from(conn, sql, buffer; debug=debug)
end

function copy_to(conn::Connection, sql::AbstractString, dest::IO; debug::Bool=false)
    logger = conn.query_logger
    log_enabled = logger !== NOOP_QUERY_LOGGER
    start_ns = log_enabled ? time_ns() : 0
    sql_str = String(sql)
    try
        @lock conn.lock begin
            checkconn(conn)
            API.copy_out(conn.socket, sql_str, dest, debug || conn.debug, conn.notice_callback, conn.notification_callback)
        end
        log_enabled && log_query(logger, :copy_to, (sql=sql_str, duration_ns=time_ns() - start_ns, success=true))
    catch err
        log_enabled && log_query(logger, :copy_to, (sql=sql_str, duration_ns=time_ns() - start_ns, success=false, error=err))
        rethrow()
    end
    return dest
end

function copy_to(conn::Connection, sql::AbstractString; debug::Bool=false)
    buffer = IOBuffer()
    copy_to(conn, sql, buffer; debug=debug)
    return take!(buffer)
end

function register_type!(conn::Connection, oid::Integer, julia_type::Type; parser::Union{Function, Nothing}=nothing)
    @lock conn.lock API.register_type!(conn.type_registry, oid, julia_type; parser=parser)
    return conn
end

function lookup_type_oid(conn::Connection, name::AbstractString, schema::AbstractString)
    rows = Tables.rowtable(DBInterface.execute(conn, """
        SELECT t.oid
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE t.typname = \$1 AND n.nspname = \$2
    """, (name, schema)))
    isempty(rows) && throw(PostgresInterfaceError("type $(schema).$(name) not found"))
    return Int(rows[1].oid)
end

function register_enum!(conn::Connection, name::AbstractString; schema::AbstractString="public", julia_type::Type=Symbol)
    oid = lookup_type_oid(conn, name, schema)
    parser = julia_type === Symbol ? (val, registry) -> Symbol(val) : nothing
    register_type!(conn, oid, julia_type; parser=parser)
    return conn
end

function register_composite!(conn::Connection, name::AbstractString; schema::AbstractString="public")
    rows = Tables.rowtable(DBInterface.execute(conn, """
        SELECT t.oid, a.attname, a.atttypid
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        JOIN pg_class c ON c.oid = t.typrelid
        JOIN pg_attribute a ON a.attrelid = c.oid
        WHERE t.typname = \$1 AND n.nspname = \$2 AND a.attnum > 0 AND NOT a.attisdropped
        ORDER BY a.attnum
    """, (name, schema)))
    isempty(rows) && throw(PostgresInterfaceError("composite type $(schema).$(name) not found"))
    oid = Int(rows[1].oid)
    field_names = [Symbol(row.attname) for row in rows]
    field_oids = Int[row.atttypid for row in rows]
    tuple_type = NamedTuple{Tuple(field_names)}
    parser = (val, registry) -> begin
        fields = API.parse_composite_fields(val)
        length(fields) == length(field_oids) || throw(PostgresInterfaceError("composite value length mismatch for $(schema).$(name)"))
        values = Any[]
        sizehint!(values, length(field_oids))
        for (i, field) in enumerate(fields)
            field === missing && push!(values, missing)
            field !== missing && push!(values, API.parse_value(field_oids[i], field, registry))
        end
        return tuple_type(Tuple(values))
    end
    register_type!(conn, oid, tuple_type; parser=parser)
    return conn
end

function register_range!(conn::Connection, name::AbstractString; schema::AbstractString="public")
    rows = Tables.rowtable(DBInterface.execute(conn, """
        SELECT t.oid, r.rngsubtype
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        JOIN pg_range r ON r.rngtypid = t.oid
        WHERE t.typname = \$1 AND n.nspname = \$2
    """, (name, schema)))
    isempty(rows) && throw(PostgresInterfaceError("range type $(schema).$(name) not found"))
    oid = Int(rows[1].oid)
    subtype_oid = Int(rows[1].rngsubtype)
    subtype_type = API.type_info(conn.type_registry, subtype_oid).julia_type
    parser = (val, registry) -> API.parse_range(val, subtype_oid, registry)
    register_type!(conn, oid, PostgresRange{subtype_type}; parser=parser)
    return conn
end

function cancel_query!(conn::Connection)
    host = conn.host
    port = conn.port
    pid = conn.pid
    skey = conn.skey
    debug = conn.debug
    if trylock(conn.lock)
        try
            !isopen(conn.socket) && throw(PostgresInterfaceError("cannot cancel query: connection not open"))
            pid = conn.pid
            skey = conn.skey
        finally
            unlock(conn.lock)
        end
    end
    API.cancel_request(host, port, pid, skey, debug)
    return conn
end

export cancel_query!

disconnected() = throw(PostgresInterfaceError("postgres connection has been closed or disconnected"))

function checkconn(conn::Connection)
    Base.assert_havelock(conn.lock)
    if !isopen(conn.socket) && !conn.closed
        # connection is closed, but not explicitly, reconnect
        conn.in_transaction && throw(PostgresInterfaceError("postgres connection has been closed or disconnected; reconnect disabled during transaction"))
        conn.reconnect || throw(PostgresInterfaceError("postgres connection has been closed or disconnected; reconnect disabled"))
        conn.socket, conn.pid, conn.skey, server_params = API.connect(conn.host, conn.port, conn.dbname, conn.user, conn.password, conn.debug, conn.application_name, conn.connect_timeout, conn.sslmode, conn.sslrootcert, conn.sslcert, conn.sslkey, conn.sslcapath, conn.statement_timeout)
        empty!(conn.statements)
        conn.in_transaction = false
        conn.transaction_depth = 0
        conn.generation += 1
        conn.server_parameters = server_params
        @warn "postgres connection was closed; reconnected"
    end
    isopen(conn.socket) || disconnected()
    return
end

function DBInterface.connect(::Type{Connection}, host::AbstractString, user::AbstractString, passwd::Union{AbstractString, Nothing}; dbname::AbstractString="", port::Integer=5432, debug::Bool=false, reconnect::Bool=false, application_name::Union{AbstractString, Nothing}=nothing, connect_timeout::Union{Integer, Nothing}=nothing, sslmode::Union{AbstractString, Nothing}=nothing, sslrootcert::Union{AbstractString, Nothing}=nothing, sslcert::Union{AbstractString, Nothing}=nothing, sslkey::Union{AbstractString, Nothing}=nothing, sslcapath::Union{AbstractString, Nothing}=nothing, statement_timeout::Union{Integer, Nothing}=nothing, statement_cache_maxsize::Integer=100)
    Connection(host=host, user=user, password=passwd, dbname=dbname, port=port, debug=debug, reconnect=reconnect, application_name=application_name, connect_timeout=connect_timeout, sslmode=sslmode, sslrootcert=sslrootcert, sslcert=sslcert, sslkey=sslkey, sslcapath=sslcapath, statement_timeout=statement_timeout, statement_cache_maxsize=statement_cache_maxsize)
end

function DBInterface.connect(::Type{Connection}, dsn::String; debug::Bool=false, reconnect::Bool=false, statement_cache_maxsize::Union{Integer, Nothing}=nothing)
    params = parse_dsn(dsn)
    actual_maxsize = isnothing(statement_cache_maxsize) ? params.statement_cache_maxsize : statement_cache_maxsize
    Connection(host=params.host, user=params.user, password=params.password, dbname=params.dbname, port=params.port, debug=debug, reconnect=reconnect, application_name=params.application_name, connect_timeout=params.connect_timeout, sslmode=params.sslmode, sslrootcert=params.sslrootcert, sslcert=params.sslcert, sslkey=params.sslkey, sslcapath=params.sslcapath, statement_timeout=params.statement_timeout, statement_cache_maxsize=actual_maxsize)
end

function DBInterface.connect(::Type{Connection}, params::ConnectionParams; debug::Bool=false, reconnect::Bool=false, statement_cache_maxsize::Union{Integer, Nothing}=nothing)
    actual_maxsize = isnothing(statement_cache_maxsize) ? params.statement_cache_maxsize : statement_cache_maxsize
    Connection(host=params.host, user=params.user, password=params.password, dbname=params.dbname, port=params.port, debug=debug, reconnect=reconnect, application_name=params.application_name, connect_timeout=params.connect_timeout, sslmode=params.sslmode, sslrootcert=params.sslrootcert, sslcert=params.sslcert, sslkey=params.sslkey, sslcapath=params.sslcapath, statement_timeout=params.statement_timeout, statement_cache_maxsize=actual_maxsize)
end

function DBInterface.connect(f::Function, ::Type{Connection}, args...; kwargs...)
    conn = DBInterface.connect(Connection, args...; kwargs...)
    try
        return f(conn)
    finally
        DBInterface.close!(conn)
    end
end

function DBInterface.close!(conn::Connection)
    @lock conn.lock begin
        if !conn.closed
            close(conn.socket)
            conn.closed = true
        end
    end
    return
end
Base.close(conn::Connection) = DBInterface.close!(conn)

struct ConnectionPool
    pool::Pools.Pool
    connector::Function
end

function ConnectionPool(connector::Function; limit::Integer=10)
    pool = Pools.Pool{Connection}(max(1, Int(limit)))
    return ConnectionPool(pool, connector)
end

function ConnectionPool(::Type{Connection}, host::AbstractString, user::AbstractString, passwd::Union{AbstractString, Nothing}; dbname::AbstractString="", port::Integer=5432, debug::Bool=false, reconnect::Bool=false, application_name::Union{AbstractString, Nothing}=nothing, connect_timeout::Union{Integer, Nothing}=nothing, sslmode::Union{AbstractString, Nothing}=nothing, sslrootcert::Union{AbstractString, Nothing}=nothing, sslcert::Union{AbstractString, Nothing}=nothing, sslkey::Union{AbstractString, Nothing}=nothing, sslcapath::Union{AbstractString, Nothing}=nothing, statement_timeout::Union{Integer, Nothing}=nothing, statement_cache_maxsize::Integer=100, limit::Integer=10)
    connector = () -> DBInterface.connect(Connection, host, user, passwd; dbname=dbname, port=port, debug=debug, reconnect=reconnect, application_name=application_name, connect_timeout=connect_timeout, sslmode=sslmode, sslrootcert=sslrootcert, sslcert=sslcert, sslkey=sslkey, sslcapath=sslcapath, statement_timeout=statement_timeout, statement_cache_maxsize=statement_cache_maxsize)
    return ConnectionPool(connector; limit=limit)
end

function ConnectionPool(dsn::String; debug::Bool=false, reconnect::Bool=false, statement_cache_maxsize::Union{Integer, Nothing}=nothing, limit::Integer=10)
    params = parse_dsn(dsn)
    actual_maxsize = isnothing(statement_cache_maxsize) ? params.statement_cache_maxsize : statement_cache_maxsize
    connector = () -> DBInterface.connect(Connection, params; debug=debug, reconnect=reconnect, statement_cache_maxsize=actual_maxsize)
    return ConnectionPool(connector; limit=limit)
end

function ConnectionPool(params::ConnectionParams; debug::Bool=false, reconnect::Bool=false, statement_cache_maxsize::Union{Integer, Nothing}=nothing, limit::Integer=10)
    actual_maxsize = isnothing(statement_cache_maxsize) ? params.statement_cache_maxsize : statement_cache_maxsize
    connector = () -> DBInterface.connect(Connection, params; debug=debug, reconnect=reconnect, statement_cache_maxsize=actual_maxsize)
    return ConnectionPool(connector; limit=limit)
end

function pool_isvalid(conn::Connection)
    valid = @lock conn.lock isopen(conn.socket) && !conn.closed
    return valid
end

function acquire(pool::ConnectionPool; forcenew::Bool=false)
    conn = Pools.acquire(pool.connector, pool.pool; forcenew=forcenew, isvalid=pool_isvalid)
    return conn
end

function release(pool::ConnectionPool, conn::Connection)
    if pool_isvalid(conn)
        Pools.release(pool.pool, conn)
    else
        Pools.release(pool.pool)
    end
    return pool
end

function with_connection(f::Function, pool::ConnectionPool; forcenew::Bool=false)
    conn = acquire(pool; forcenew=forcenew)
    try
        return f(conn)
    finally
        release(pool, conn)
    end
end

function DBInterface.close!(pool::ConnectionPool)
    Base.@lock pool.pool.lock begin
        for conn in pool.pool.values
            try
                DBInterface.close!(conn)
            catch
                # ignore close errors for pooled connections
            end
        end
        empty!(pool.pool.values)
    end
    return pool
end
Base.close(pool::ConnectionPool) = DBInterface.close!(pool)

include("execute.jl")

function start_transaction(conn::Connection)
    @lock conn.lock begin
        checkconn(conn)
        if !conn.in_transaction
            DBInterface.execute(conn, "BEGIN")
            conn.in_transaction = true
            conn.transaction_depth = 1
        else
            # Start a SAVEPOINT for nested transactions
            savepoint = "sp_$(conn.transaction_depth)"
            DBInterface.execute(conn, "SAVEPOINT $savepoint")
            conn.transaction_depth += 1
        end
    end
    return conn
end

in_transaction(conn::Connection) = @lock conn.lock conn.in_transaction

function commit(conn::Connection)
    @lock conn.lock begin
        checkconn(conn)
        !conn.in_transaction && throw(PostgresInterfaceError("no transaction in progress"))
        if conn.transaction_depth == 1
            DBInterface.execute(conn, "COMMIT")
            conn.in_transaction = false
            conn.transaction_depth = 0
        else
            # Release SAVEPOINT for nested transaction
            conn.transaction_depth -= 1
            # Don't need to release SAVEPOINT explicitly, just commit will handle it
        end
    end
    return conn
end

function rollback(conn::Connection)
    @lock conn.lock begin
        checkconn(conn)
        !conn.in_transaction && throw(PostgresInterfaceError("no transaction in progress"))
        if conn.transaction_depth == 1
            DBInterface.execute(conn, "ROLLBACK")
            conn.in_transaction = false
            conn.transaction_depth = 0
        else
            # Rollback to SAVEPOINT for nested transaction
            conn.transaction_depth -= 1
            savepoint = "sp_$(conn.transaction_depth)"
            DBInterface.execute(conn, "ROLLBACK TO SAVEPOINT $savepoint")
        end
    end
    return conn
end

function transaction(f::Function, conn::Connection)
    start_transaction(conn)
    try
        result = f(conn)
        commit(conn)
        return result
    catch
        rollback(conn)
        rethrow()
    end
end

macro transaction(conn, expr)
    quote
        local success = false
        start_transaction($(esc(conn)))
        try
            result = $(esc(expr))
            commit($(esc(conn)))
            success = true
            result
        catch
            !success && rollback($(esc(conn)))
            rethrow()
        end
    end
end

export @transaction

# escape(conn::Connection, s::AbstractString) = API.escape(conn.pg, s)

struct Describe
    resultset::Any
end

function Base.show(io::IO, desc::Describe)
    resultset = desc.resultset
    # columns to print
    columns = [:column_name, :friendly_type, :is_nullable, :column_default, :is_primary_key, :foreign_key_reference]
    # Calculate maximum width for each column
    max_widths = Dict{Symbol, Int}()
    # Initialize with header widths
    for col in columns
        max_widths[col] = max(sizeof(string(col)), 0)  # Start with the sizeof of the header
    end
    # Calculate maximum width for each column based on data
    for row in resultset
        for col in columns
            max_widths[col] = max(max_widths[col], sizeof(string(row[col])))
        end
    end
    # Prepare the header row
    header = join([lpad(string(col), max_widths[col]) for col in columns], " | ")
    println(io, header)
    # Print a separator line
    println(io, "-"^(sizeof(header)))
    # Print each row
    for row in resultset
        row_str = join([lpad(string(row[col]), max_widths[col]) for col in columns], " | ")
        println(io, row_str)
    end
end

function describe(conn::Connection, table::AbstractString; schema::String="public")
    Describe(DBInterface.execute(conn, """
        WITH column_info AS (
            SELECT
                c.column_name,
                c.data_type,
                c.is_nullable,
                c.column_default,
                tc.constraint_type,
                kcu.constraint_name,
                kcu.table_name AS local_table,
                kcu.column_name AS local_column,
                fk.table_name AS foreign_table,
                fk.column_name AS foreign_column,
                CASE
                    WHEN tc.constraint_type = 'PRIMARY KEY' THEN TRUE
                    ELSE FALSE
                END AS is_primary_key,
                CASE
                    WHEN tc.constraint_type = 'FOREIGN KEY' THEN TRUE
                    ELSE FALSE
                END AS is_foreign_key
            FROM
                information_schema.columns c
            LEFT JOIN
                information_schema.key_column_usage kcu ON c.table_name = kcu.table_name AND c.column_name = kcu.column_name
            LEFT JOIN
                information_schema.table_constraints tc ON kcu.constraint_name = tc.constraint_name
            LEFT JOIN
                information_schema.referential_constraints rc ON tc.constraint_name = rc.constraint_name
            LEFT JOIN
                information_schema.key_column_usage fk ON rc.unique_constraint_name = fk.constraint_name AND fk.table_schema = c.table_schema
            WHERE
                c.table_name = \$1 AND c.table_schema = \$2
        )
        SELECT
            column_name,
            data_type AS friendly_type,
            is_nullable,
            column_default,
            is_primary_key,
            CASE
                WHEN is_foreign_key THEN CONCAT(foreign_table, '.', foreign_column)
                ELSE NULL
            END AS foreign_key_reference
        FROM
            column_info;
    """, (table, schema)))
end

end
