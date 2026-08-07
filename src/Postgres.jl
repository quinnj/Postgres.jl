module Postgres

using DBInterface, Dates, UUIDs, Parsers, Tables, StructUtils, JSON, ConcurrentUtilities, Reseau

export DBInterface

"""
    Postgres.PostgresInterfaceError <: Exception

A client-side error raised by Postgres.jl itself (closed connections,
parameter-count mismatches, unsupported features, ...), as opposed to
[`Postgres.Error`](@ref Postgres.API.Error), which represents an error
reported by the server.
"""
struct PostgresInterfaceError <: Exception
    msg::String
end
Base.showerror(io::IO, e::PostgresInterfaceError) = print(io, e.msg)

@noinline _reject_nul(what::String) = throw(PostgresInterfaceError("$what cannot contain a NUL byte"))

include("api/API.jl")
using .API
include("connection_string.jl")
using .ConnectionString

const Pools = ConcurrentUtilities.Pools
const ReseauConn = Union{Reseau.TCP.Conn, Reseau.TLS.Conn}

# Observability must not change whether a database operation succeeds. A
# callback failure is reported, but never replaces the query result or error.
function query_log_safely(style, event::Symbol, info::NamedTuple)
    try
        API.query_logger(style, event, info)
    catch err
        @warn "Postgres query logger failed" event exception=(err, catch_backtrace())
    end
    return nothing
end

"""
    Postgres.Connection

A single connection to a PostgreSQL server, created via
`DBInterface.connect(Postgres.Connection, ...)`:

    DBInterface.connect(Postgres.Connection, host, user, password; dbname, port=5432, kwargs...)
    DBInterface.connect(Postgres.Connection, dsn::String; kwargs...)
    DBInterface.connect(Postgres.Connection, params::ConnectionParams; kwargs...)

`dsn` may be a libpq-style keyword string (`"host=127.0.0.1 user=postgres dbname=postgres"`)
or a PostgreSQL URI (`"postgresql://user:pass@host:5432/dbname?sslmode=require"`).

Supported keyword arguments. All are also available as DSN/URI options except
`style`, which is Julia-only:

- `dbname`, `port`, `application_name`
- `connect_timeout` (seconds), `statement_timeout` (milliseconds)
- `sslmode` (`"disable"`, `"prefer"` (default), `"require"`, `"verify-full"`),
  `sslrootcert`, `sslcert`, `sslkey`, `sslcapath`, and `sslservername`.
  Only `verify-full` verifies the server's certificate; `require` encrypts
  without authenticating the server, and the default `prefer` falls back to an
  unencrypted connection if the server declines TLS. `sslcapath` is a
  fallback CA bundle or directory used only when `sslrootcert` is unset (it is
  ignored otherwise).
  `sslservername` overrides the TLS server
  name when the host is a pre-resolved address — note that under
  `verify-full` this is also the name the certificate is verified against,
  so it must name the server you intend to authenticate.
- `statement_cache_maxsize`: LRU backend cache size for explicit named prepared
  statements (default 100; `0` disables)
- `reconnect`: automatically reconnect and re-prepare statements if the
  connection is found dead (default `false`; never reconnects mid-transaction)
- `style`: a custom [`AbstractPostgresStyle`](@ref Postgres.API.AbstractPostgresStyle)
  for query logging / notice / notification behavior
- `debug`: log wire protocol messages. Authentication messages are redacted,
  but bind parameter values are not — treat a debug log as sensitive as the
  data the connection carries.

Individual operations are serialized on an internal lock. Keep each manual
transaction and streaming cursor on one task and do not run unrelated work on
that connection until the scope ends. Use a [`ConnectionPool`](@ref) for
concurrent work. `cancel_query!` is the intentional cross-task exception.
Close with `DBInterface.close!(conn)` or `close(conn)`; the do-block form
`DBInterface.connect(f, Postgres.Connection, ...)` closes automatically.
"""
mutable struct Connection{T, S <: API.AbstractPostgresStyle} <: DBInterface.Connection
    const lock::ReentrantLock
    socket::ReseauConn
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
    const sslservername::Union{String, Nothing}
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
    # style-dispatched behavior (query_logger / notice_callback / notification_callback
    # overloads on a custom AbstractPostgresStyle) — Function-typed callback fields are
    # dynamic dispatch at every use, unresolvable under `juliac --trim`
    const style::S
    in_transaction::Bool # track transaction state
    transaction_depth::Int # track nested transactions (SAVEPOINTs)
    transaction_savepoints::Vector{String} # driver-owned names, outermost first
    generation::Int # increment on reconnect to invalidate statements
    # the server's own ReadyForQuery transaction status: unlike in_transaction
    # it also sees a transaction opened by raw SQL (`execute(conn, "BEGIN")`)
    server_in_transaction::Bool
    # whether the outermost driver-managed transaction level issued the BEGIN:
    # when start_transaction found a raw-SQL transaction already open, the base
    # level is a savepoint inside the caller's transaction, and the final
    # commit/rollback must not COMMIT/ROLLBACK the caller's work
    owns_base_transaction::Bool

    function Connection(; host::AbstractString="", user::AbstractString="", password::Union{AbstractString, Nothing}=nothing, dbname::AbstractString="", port::Integer=5432, debug::Bool=false, reconnect::Bool=false, application_name::Union{AbstractString, Nothing}=nothing, connect_timeout::Union{Integer, Nothing}=nothing, sslmode::Union{AbstractString, Nothing}=nothing, sslrootcert::Union{AbstractString, Nothing}=nothing, sslcert::Union{AbstractString, Nothing}=nothing, sslkey::Union{AbstractString, Nothing}=nothing, sslcapath::Union{AbstractString, Nothing}=nothing, sslservername::Union{AbstractString, Nothing}=nothing, statement_timeout::Union{Integer, Nothing}=nothing, statement_cache_maxsize::Integer=100, style::API.AbstractPostgresStyle=PostgresStyle())
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
        sslservername_val = sslservername === nothing ? nothing : String(sslservername)
        occursin('\0', host) && _reject_nul("host")
        occursin('\0', user) && _reject_nul("user")
        occursin('\0', dbname) && _reject_nul("dbname")
        password !== nothing && occursin('\0', password) && _reject_nul("password")
        app_name !== nothing && occursin('\0', app_name) && _reject_nul("application_name")
        sslservername_val !== nothing && occursin('\0', sslservername_val) && _reject_nul("sslservername")
        xor(sslcert_val === nothing, sslkey_val === nothing) &&
            throw(PostgresInterfaceError("sslcert and sslkey must be provided together"))
        maxsize = max(0, Int(statement_cache_maxsize))
        socket, pid, skey, server_params = API.connect(host, port, dbname, user, password, debug, app_name, timeout, sslmode_val, sslrootcert_val, sslcert_val, sslkey_val, sslcapath_val, sslservername_val, statement_timeout_val)
        registry = Dict(API.DEFAULT_TYPE_REGISTRY)
        return new{Statement{typeof(style)}, typeof(style)}(ReentrantLock(), socket, host, user, password, dbname, port, app_name, timeout, sslmode_val, sslrootcert_val, sslcert_val, sslkey_val, sslcapath_val, sslservername_val, statement_timeout_val, pid, skey, Dict{String, Statement{typeof(style)}}(), maxsize, 0, server_params, registry, false, reconnect, debug, style, false, 0, String[], 1, false, true)
    end
end

_style_type(::Connection{T, S}) where {T, S} = S

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
    if !stmt.closed
        API.close_statement(conn.socket, stmt.name, conn.debug, conn.server_parameters)
        stmt.closed = true
    end
    return
end

"""
    Postgres.get_cached_statements(conn) -> Dict{String, Statement}

Return a copy of the connection's prepared-statement cache, keyed by SQL text.
"""
function get_cached_statements(conn::Connection)
    @lock conn.lock Dict(sql => statement_handle(stmt) for (sql, stmt) in conn.statements)
end

"""
    Postgres.clear_statement_cache!(conn)

Close all server-side prepared statements in the connection's cache and empty it.
"""
function clear_statement_cache!(conn::Connection)
    @lock conn.lock begin
        for (sql, stmt) in conn.statements
            if !stmt.closed
                API.close_statement(conn.socket, stmt.name, conn.debug, conn.server_parameters)
                stmt.closed = true
            end
        end
        empty!(conn.statements)
    end
    return conn
end

"""
    Postgres.set_statement_cache_maxsize!(conn, maxsize)

Set the maximum number of prepared statements the connection caches (LRU
eviction). `0` disables caching and closes all currently cached statements.
"""
function set_statement_cache_maxsize!(conn::Connection, maxsize::Integer)
    @lock conn.lock begin
        conn.statement_cache_maxsize = max(0, Int(maxsize))
        if conn.statement_cache_maxsize == 0
            for (sql, stmt) in conn.statements
                if !stmt.closed
                    API.close_statement(conn.socket, stmt.name, conn.debug, conn.server_parameters)
                    stmt.closed = true
                end
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

"""
    Postgres.get_server_parameter(conn, name) -> Union{String, Nothing}

Return the server-reported value of runtime parameter `name` (e.g.
`"server_version"`, `"TimeZone"`), or `nothing` if the server has not reported it.
"""
get_server_parameter(conn::Connection, param::String) = @lock conn.lock get(conn.server_parameters, param, nothing)

"""
    Postgres.get_server_parameters(conn) -> Dict{String, String}

Return a copy of all runtime parameters the server has reported on this connection.
"""
get_server_parameters(conn::Connection) = @lock conn.lock copy(conn.server_parameters)

# NOTE: runtime callback setters are gone — customize behavior by passing a custom
# AbstractPostgresStyle to Connection(; style=...) and overloading the style-first
# interface methods (query_logger / notice_callback / notification_callback).

"""
    Postgres.get_statement_timeout(conn) -> Union{Int, Nothing}

Return the statement timeout (milliseconds) configured on the connection, or
`nothing` if none was set.
"""
function get_statement_timeout(conn::Connection)
    return @lock conn.lock conn.statement_timeout
end

"""
    Postgres.set_statement_timeout!(conn, timeout)

Set the server `statement_timeout` for the connection, in milliseconds.
`nothing` or `0` disables the timeout. This setting is session state and cannot
be changed while a transaction is open. An explicit disable is retained across
automatic reconnects as `0`.
"""
function set_statement_timeout!(conn::Connection, timeout::Union{Integer, Nothing})
    timeout_val = timeout === nothing ? 0 : max(0, Int(timeout))
    @lock conn.lock begin
        checkconn(conn)
        (conn.in_transaction || conn.server_in_transaction) &&
            throw(PostgresInterfaceError("statement_timeout cannot be changed while a transaction is open"))
        DBInterface.execute(conn, "SET statement_timeout = $timeout_val")
        conn.statement_timeout = timeout_val
    end
    return conn
end

"""
    Postgres.escape_identifier(name) -> String

Quote a string for use as a SQL identifier (double-quoted, embedded quotes
doubled). Throws if `name` contains a NUL byte.
"""
function escape_identifier(name::AbstractString)
    occursin('\0', name) && _reject_nul("identifier")
    return string("\"", replace(name, "\"" => "\"\""), "\"")
end

"""
    Postgres.escape_literal(val) -> String

Quote a string for use as a SQL literal (single-quoted, embedded quotes
doubled). Throws if `val` contains a NUL byte.

Prefer query parameters (`\$1`, `\$2`, ...) over literal interpolation
whenever possible — parameters are never parsed as SQL. Inputs containing a
backslash use PostgreSQL's explicit escape-string syntax, with backslashes and
quotes escaped so the result is independent of `standard_conforming_strings`.
"""
function escape_literal(val::AbstractString)
    occursin('\0', val) && _reject_nul("literal")
    escaped = replace(val, "'" => "''")
    occursin('\\', escaped) || return string("'", escaped, "'")
    return string("E'", replace(escaped, "\\" => "\\\\"), "'")
end

"""
    Postgres.listen!(conn, channel)

Execute `LISTEN channel` so the connection receives notifications for
`channel`. Use [`wait_for_notification`](@ref Postgres.wait_for_notification)
to block until one arrives.
"""
function listen!(conn::Connection, channel::AbstractString)
    DBInterface.execute(conn, "LISTEN $(escape_identifier(channel))")
    return conn
end

"""
    Postgres.unlisten!(conn, channel)

Execute `UNLISTEN channel` to stop receiving notifications for `channel`.
"""
function unlisten!(conn::Connection, channel::AbstractString)
    DBInterface.execute(conn, "UNLISTEN $(escape_identifier(channel))")
    return conn
end

"""
    Postgres.notify!(conn, channel, payload=nothing)

Execute `NOTIFY channel` (with optional `payload`), delivering a
[`Notification`](@ref Postgres.API.Notification) to all connections listening
on `channel`.
"""
function notify!(conn::Connection, channel::AbstractString, payload::Union{AbstractString, Nothing}=nothing)
    channel_ident = escape_identifier(channel)
    sql = payload === nothing ? "NOTIFY $channel_ident" : "NOTIFY $channel_ident, $(escape_literal(payload))"
    DBInterface.execute(conn, sql)
    return conn
end

function update_server_parameters!(conn::Connection, buf::Vector{UInt8})
    i = 1
    GC.@preserve buf while i < length(buf)
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

@inline function _set_read_deadline!(socket::ReseauConn, deadline_ns::Int64)
    if socket isa Reseau.TCP.Conn
        Reseau.TCP.set_read_deadline!(socket, deadline_ns)
    else
        Reseau.TLS.set_read_deadline!(socket, deadline_ns)
    end
    return nothing
end

@inline function _clear_read_deadline!(socket::ReseauConn)
    _set_read_deadline!(socket, Int64(0))
    return nothing
end

const NOTIFICATION_POLL_INTERVAL_NS = Int64(100_000_000)

# A read deadline surfaces directly as DeadlineExceededError on a plain TCP
# connection, but the TLS layer wraps transport failures, so over TLS the same
# expiry arrives as a TLSError carrying it as the cause.
function _is_read_deadline_error(err)
    err isa Reseau.IOPoll.DeadlineExceededError && return true
    err isa Reseau.TLS.TLSError && return err.cause isa Reseau.IOPoll.DeadlineExceededError
    return false
end

"""
    Postgres.wait_for_notification(conn; timeout=nothing) -> Union{Notification, Nothing}

Block until a `NOTIFY` message arrives on the connection (see
[`listen!`](@ref Postgres.listen!)) and return it as a
[`Notification`](@ref Postgres.API.Notification). With a `timeout` (seconds),
return `nothing` if no message begins arriving in that window; once a message
starts, it is always read to completion so the connection is never left parked
mid-message. The connection lock is held while waiting, so use a dedicated
connection for listening — that is also the only way to receive every
notification, since notifications that arrive while the connection is busy
with a query are delivered to
[`notification_callback`](@ref Postgres.API.notification_callback) only during
the phases of a query that read result data.

Over TLS the poll interval bounds a read on the underlying transport rather
than on the TLS record layer, so a record that arrives split across a poll
boundary cannot be resumed. That is detected on the following poll and closes
the connection with an error rather than returning corrupt data; a blocking
wait (no `timeout`) is not affected.
"""
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
                # clamp before converting: an Inf or very large timeout would
                # overflow the nanosecond conversion
                remaining_ns = remaining_s >= 10.0 ? NOTIFICATION_POLL_INTERVAL_NS : round(Int64, remaining_s * 1_000_000_000)
                Int64(time_ns()) + min(NOTIFICATION_POLL_INTERVAL_NS, remaining_ns)
            end
            # The deadline covers only the first byte: if it expires there,
            # nothing of a message has been consumed and polling again is safe.
            # Once a byte arrives the rest of the message is read without a
            # deadline, so a message straddling the poll boundary can never
            # leave the stream parked mid-message.
            _set_read_deadline!(conn.socket, deadline_ns)
            mt = try
                read(conn.socket, UInt8)
            catch err
                if !_is_read_deadline_error(err)
                    # the stream position is unknowable, so the connection
                    # must never be reused (see the TLS caveat in the
                    # docstring: a deadline that expires partway through a TLS
                    # record surfaces here on the following poll)
                    close(conn.socket)
                    rethrow()
                end
                nothing
            finally
                # the deadline must be cleared on every path, including a
                # rethrow: an expired deadline left set on the socket makes
                # every later read on this connection fail
                isopen(conn.socket) && _clear_read_deadline!(conn.socket)
            end
            # nothing arrived within this poll interval; nothing of a message
            # has been consumed, so it is safe to loop and re-check the timeout
            mt === nothing && continue
            # A byte of a message has been consumed, so from here any failure
            # leaves the stream at an unknowable position: close the connection
            # rather than hand back one that still looks healthy. No deadline is
            # in effect, so the message is read to completion.
            # Read the message off the socket. Only the reading is guarded:
            # once a message is fully consumed the stream is back at a clean
            # boundary, so user callbacks and server errors are surfaced
            # without destroying the connection.
            message = try
                len = ntoh(read(conn.socket, Int32)) - 4
                (len < 0 || len > API.MAX_MESSAGE_LEN) &&
                    throw(API.Error("invalid message length $len from server; connection protocol state is corrupted"))
                conn.debug && @info "readheader: $(Char(mt)), $len"
                if mt == UInt8('A')
                    API.notificationResponse(len, conn.socket)
                elseif mt == UInt8('N')
                    API.noticeResponse(len, conn.socket)
                elseif mt == UInt8('S')
                    update_server_parameters!(conn, read(conn.socket, len))
                    nothing
                elseif mt == UInt8('E')
                    API.errorResponse(len, conn.socket, conn.debug)
                else
                    API.skipbytes!(conn.socket, len)
                    nothing
                end
            catch
                close(conn.socket)
                rethrow()
            end
            if message isa API.Notification
                API.notification_callback(conn.style, message)
                return message
            elseif message isa API.Error
                # FATAL and PANIC both terminate the session; close now so the
                # next use reports the error rather than a bare EOF from a
                # socket the server has already dropped
                (message.severity == "FATAL" || message.severity == "PANIC") && close(conn.socket)
                throw(message)
            elseif message !== nothing
                API.notice_callback(conn.style, message)
            end
        end
    end
end

"""
    Postgres.copy_from(conn, sql, data)

Execute a `COPY ... FROM STDIN` statement, streaming `data` (an `IO`, string,
or byte vector) to the server. Supports all COPY formats, including
`(FORMAT BINARY)`. Returns `conn`.
"""
function copy_from(conn::Connection, sql::AbstractString, data::IO; debug::Bool=false)
    log_enabled = API.query_logging_enabled(conn.style)
    start_ns = log_enabled ? time_ns() : 0
    sql_str = String(sql)
    try
        @lock conn.lock begin
            checkconn(conn)
            API.copy_in(conn.style, conn.socket, sql_str, data, debug || conn.debug)
        end
        log_enabled && query_log_safely(conn.style, :copy_from, (sql=sql_str, duration_ns=time_ns() - start_ns, success=true))
    catch err
        log_enabled && query_log_safely(conn.style, :copy_from, (sql=sql_str, duration_ns=time_ns() - start_ns, success=false, error=err))
        rethrow()
    end
    return conn
end

function copy_from(conn::Connection, sql::AbstractString, data; debug::Bool=false)
    buffer = IOBuffer(data)
    return copy_from(conn, sql, buffer; debug=debug)
end

"""
    Postgres.copy_to(conn, sql, [dest::IO])

Execute a `COPY ... TO STDOUT` statement. With a `dest` IO, the copy stream is
written to it and `dest` is returned; without one, the raw bytes are returned
as a `Vector{UInt8}`.
"""
function copy_to(conn::Connection, sql::AbstractString, dest::IO; debug::Bool=false)
    log_enabled = API.query_logging_enabled(conn.style)
    start_ns = log_enabled ? time_ns() : 0
    sql_str = String(sql)
    try
        @lock conn.lock begin
            checkconn(conn)
            API.copy_out(conn.style, conn.socket, sql_str, dest, debug || conn.debug)
        end
        log_enabled && query_log_safely(conn.style, :copy_to, (sql=sql_str, duration_ns=time_ns() - start_ns, success=true))
    catch err
        log_enabled && query_log_safely(conn.style, :copy_to, (sql=sql_str, duration_ns=time_ns() - start_ns, success=false, error=err))
        rethrow()
    end
    return dest
end

function copy_to(conn::Connection, sql::AbstractString; debug::Bool=false)
    buffer = IOBuffer()
    copy_to(conn, sql, buffer; debug=debug)
    return take!(buffer)
end

"""
    Postgres.register_type!(conn, oid, julia_type; parser=nothing)

Register a mapping from PostgreSQL type `oid` to `julia_type` in the
connection's type registry. `parser` is a `(val::String, registry) -> value`
function that converts the wire text. If `parser` is omitted, `julia_type`
must be `String`. See also [`register_enum!`](@ref Postgres.register_enum!),
[`register_composite!`](@ref Postgres.register_composite!), and
[`register_range!`](@ref Postgres.register_range!).
"""
function register_type!(conn::Connection, oid::Integer, julia_type::Type; parser::Union{Function, Nothing}=nothing)
    parser === nothing && julia_type !== String &&
        throw(ArgumentError("parser is required when julia_type is not String"))
    @lock conn.lock API.register_type!(conn.type_registry, oid, julia_type; parser=parser)
    return conn
end

function lookup_type_oid(conn::Connection, name::AbstractString, schema::AbstractString)
    rows = Tables.rowtable(DBInterface.execute(conn, """
        SELECT t.oid, t.typarray
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE t.typname = \$1 AND n.nspname = \$2
    """, (name, schema)))
    isempty(rows) && throw(PostgresInterfaceError("type $(schema).$(name) not found"))
    return Int(rows[1].oid), Int(rows[1].typarray)
end

# Register the type's array OID alongside it, so `ARRAY[...]::name[]` values
# decode as arrays of the registered type instead of the raw literal string.
function register_array_type!(conn::Connection, arrayoid::Int, oid::Int, @nospecialize(julia_type::Type))
    arrayoid == 0 && return conn
    register_type!(conn, arrayoid, Vector{julia_type};
                   parser=(val, registry) -> API.parse_array_by_oid(val, oid, registry))
    return conn
end

"""
    Postgres.register_enum!(conn, name; schema="public", julia_type=Symbol)

Look up the enum type `schema.name` on the server and register it so values
are returned as `julia_type` (by default `Symbol`). The supported types are
`Symbol` and `String`.
"""
function register_enum!(conn::Connection, name::AbstractString; schema::AbstractString="public", julia_type::Type=Symbol)
    (julia_type === Symbol || julia_type === String) ||
        throw(ArgumentError("julia_type for register_enum! must be Symbol or String"))
    oid, arrayoid = lookup_type_oid(conn, name, schema)
    parser = julia_type === Symbol ? (val, registry) -> Symbol(val) : nothing
    register_type!(conn, oid, julia_type; parser=parser)
    register_array_type!(conn, arrayoid, oid, julia_type)
    return conn
end

"""
    Postgres.register_composite!(conn, name; schema="public")

Look up the composite type `schema.name` on the server and register it so
values are returned as `NamedTuple`s with the composite's field names.
"""
function register_composite!(conn::Connection, name::AbstractString; schema::AbstractString="public")
    rows = Tables.rowtable(DBInterface.execute(conn, """
        SELECT t.oid, t.typarray, a.attname, a.atttypid
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        JOIN pg_class c ON c.oid = t.typrelid
        JOIN pg_attribute a ON a.attrelid = c.oid
        WHERE t.typname = \$1 AND n.nspname = \$2 AND a.attnum > 0 AND NOT a.attisdropped
        ORDER BY a.attnum
    """, (name, schema)))
    isempty(rows) && throw(PostgresInterfaceError("composite type $(schema).$(name) not found"))
    oid = Int(rows[1].oid)
    arrayoid = Int(rows[1].typarray)
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
    register_array_type!(conn, arrayoid, oid, tuple_type)
    return conn
end

"""
    Postgres.register_range!(conn, name; schema="public")

Look up the range type `schema.name` on the server and register it so values
are returned as [`PostgresRange`](@ref Postgres.API.PostgresRange) of the
range's element type.

The element type is captured when the range is registered, so register it
first: a range over a custom enum or composite must come after the
corresponding [`register_enum!`](@ref Postgres.register_enum!) /
[`register_composite!`](@ref Postgres.register_composite!) call.
"""
function register_range!(conn::Connection, name::AbstractString; schema::AbstractString="public")
    rows = Tables.rowtable(DBInterface.execute(conn, """
        SELECT t.oid, t.typarray, r.rngsubtype
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        JOIN pg_range r ON r.rngtypid = t.oid
        WHERE t.typname = \$1 AND n.nspname = \$2
    """, (name, schema)))
    isempty(rows) && throw(PostgresInterfaceError("range type $(schema).$(name) not found"))
    oid = Int(rows[1].oid)
    arrayoid = Int(rows[1].typarray)
    subtype_oid = Int(rows[1].rngsubtype)
    subtype_type = API.type_info(conn.type_registry, subtype_oid).julia_type
    # bind the element type here rather than rediscovering it per value: the
    # builtin parse_range only knows a fixed set of element types, so a range
    # over anything else would register successfully and then fail on every value
    parser = (val, registry) -> API.parse_range_of(subtype_type, val, subtype_oid, registry)
    register_type!(conn, oid, PostgresRange{subtype_type}; parser=parser)
    register_array_type!(conn, arrayoid, oid, PostgresRange{subtype_type})
    return conn
end

# If the connection actually negotiated TLS, the cancel connection must
# require it too, even under the permissive default — otherwise a server
# answering 'N' to the cancel connection's SSLRequest downgrades the cancel
# key to cleartext.
function cancel_sslmode(socket_is_tls::Bool, sslmode::Union{String, Nothing})
    socket_is_tls || return sslmode
    (sslmode === nothing || lowercase(sslmode) == "prefer") && return "require"
    return sslmode
end

"""
    Postgres.cancel_query!(conn)

Send a PostgreSQL CancelRequest for the query currently running on `conn`
(over a separate, short-lived connection, so it works while `conn` is busy).
The cancelled query fails with a [`Postgres.Error`](@ref Postgres.API.Error)
with SQLSTATE `57014`.

The cancel connection uses the same TLS settings as `conn`, since the cancel
key it carries is a credential: if `conn` itself is on TLS, the cancel
connection requires TLS too. Throws a `PostgresInterfaceError` if the cancel
request could not be delivered (rather than failing silently, which would
leave the query running).
"""
function cancel_query!(conn::Connection)
    host = conn.host
    port = conn.port
    pid = conn.pid
    skey = conn.skey
    debug = conn.debug
    # Checked outside the lock deliberately: cancel_query! is called precisely
    # when another task holds it running the query being cancelled, so a
    # trylock-guarded check would be skipped in the case that matters. Reading
    # the socket field unlocked matches how host/pid/skey are read below.
    sslmode = cancel_sslmode(conn.socket isa Reseau.TLS.Conn, conn.sslmode)
    if trylock(conn.lock)
        try
            !isopen(conn.socket) && throw(PostgresInterfaceError("cannot cancel query: connection not open"))
            pid = conn.pid
            skey = conn.skey
        finally
            unlock(conn.lock)
        end
    end
    ok = API.cancel_request(host, port, pid, skey, debug, sslmode, conn.sslrootcert, conn.sslcert, conn.sslkey, conn.sslcapath, conn.sslservername, conn.connect_timeout)
    ok || throw(PostgresInterfaceError("failed to deliver the cancel request to $(host):$(port)"))
    return conn
end

disconnected() = throw(PostgresInterfaceError("postgres connection has been closed or disconnected"))

function checkconn(conn::Connection)
    Base.assert_havelock(conn.lock)
    if !isopen(conn.socket) && !conn.closed
        # connection is closed, but not explicitly, reconnect
        conn.in_transaction && throw(PostgresInterfaceError("postgres connection has been closed or disconnected; reconnect disabled during transaction"))
        conn.reconnect || throw(PostgresInterfaceError("postgres connection has been closed or disconnected; reconnect disabled"))
        conn.socket, conn.pid, conn.skey, server_params = API.connect(conn.host, conn.port, conn.dbname, conn.user, conn.password, conn.debug, conn.application_name, conn.connect_timeout, conn.sslmode, conn.sslrootcert, conn.sslcert, conn.sslkey, conn.sslcapath, conn.sslservername, conn.statement_timeout)
        empty!(conn.statements)
        conn.in_transaction = false
        conn.transaction_depth = 0
        empty!(conn.transaction_savepoints)
        # the server-side transaction died with the old socket; a stale flag
        # would trigger a spurious ROLLBACK on the fresh session
        conn.server_in_transaction = false
        conn.generation += 1
        conn.server_parameters = server_params
        @warn "postgres connection was closed; reconnected"
    end
    isopen(conn.socket) || disconnected()
    return
end

function DBInterface.connect(::Type{Connection}, host::AbstractString, user::AbstractString, passwd::Union{AbstractString, Nothing}; dbname::AbstractString="", port::Integer=5432, debug::Bool=false, reconnect::Bool=false, application_name::Union{AbstractString, Nothing}=nothing, connect_timeout::Union{Integer, Nothing}=nothing, sslmode::Union{AbstractString, Nothing}=nothing, sslrootcert::Union{AbstractString, Nothing}=nothing, sslcert::Union{AbstractString, Nothing}=nothing, sslkey::Union{AbstractString, Nothing}=nothing, sslcapath::Union{AbstractString, Nothing}=nothing, sslservername::Union{AbstractString, Nothing}=nothing, statement_timeout::Union{Integer, Nothing}=nothing, statement_cache_maxsize::Integer=100, style::API.AbstractPostgresStyle=PostgresStyle())
    Connection(host=host, user=user, password=passwd, dbname=dbname, port=port, debug=debug, reconnect=reconnect, application_name=application_name, connect_timeout=connect_timeout, sslmode=sslmode, sslrootcert=sslrootcert, sslcert=sslcert, sslkey=sslkey, sslcapath=sslcapath, sslservername=sslservername, statement_timeout=statement_timeout, statement_cache_maxsize=statement_cache_maxsize, style=style)
end

function DBInterface.connect(::Type{Connection}, dsn::String; debug::Union{Bool, Nothing}=nothing, reconnect::Union{Bool, Nothing}=nothing, statement_cache_maxsize::Union{Integer, Nothing}=nothing, style::API.AbstractPostgresStyle=PostgresStyle())
    return DBInterface.connect(Connection, parse_dsn(dsn); debug=debug, reconnect=reconnect, statement_cache_maxsize=statement_cache_maxsize, style=style)
end

function DBInterface.connect(::Type{Connection}, params::ConnectionParams; debug::Union{Bool, Nothing}=nothing, reconnect::Union{Bool, Nothing}=nothing, statement_cache_maxsize::Union{Integer, Nothing}=nothing, style::API.AbstractPostgresStyle=PostgresStyle())
    actual_maxsize = isnothing(statement_cache_maxsize) ? params.statement_cache_maxsize : statement_cache_maxsize
    Connection(host=params.host, user=params.user, password=params.password, dbname=params.dbname, port=params.port, debug=something(debug, params.debug), reconnect=something(reconnect, params.reconnect), application_name=params.application_name, connect_timeout=params.connect_timeout, sslmode=params.sslmode, sslrootcert=params.sslrootcert, sslcert=params.sslcert, sslkey=params.sslkey, sslcapath=params.sslcapath, sslservername=params.sslservername, statement_timeout=params.statement_timeout, statement_cache_maxsize=actual_maxsize, style=style)
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

"""
    Postgres.ConnectionPool

A pool of [`Connection`](@ref Postgres.Connection)s, created lazily up to
`limit` and reused across [`acquire`](@ref Postgres.acquire)/[`release`](@ref
Postgres.release) cycles. Locally closed connections are replaced. A peer close
that the local socket has not observed can surface on the borrower's first
operation; an ambiguous failed operation is never retried automatically.

    ConnectionPool(Postgres.Connection, host, user, password; limit=10, kwargs...)
    ConnectionPool(dsn::String; limit=10, kwargs...)
    ConnectionPool(params::ConnectionParams; limit=10, kwargs...)
    ConnectionPool(connector::Function; limit=10)

Prefer [`with_connection`](@ref Postgres.with_connection) over manual
acquire/release. Close all pooled connections with `DBInterface.close!(pool)`.
"""
struct ConnectionPool
    pool::Pools.Pool
    connector::Function
    closed::Threads.Atomic{Bool}
    lifecycle_lock::ReentrantLock
end

function ConnectionPool(connector::Function; limit::Integer=10)
    pool = Pools.Pool{Connection}(max(1, Int(limit)))
    return ConnectionPool(pool, connector, Threads.Atomic{Bool}(false), ReentrantLock())
end

Base.isopen(pool::ConnectionPool) = !pool.closed[]

function ConnectionPool(::Type{Connection}, host::AbstractString, user::AbstractString, passwd::Union{AbstractString, Nothing}; dbname::AbstractString="", port::Integer=5432, debug::Bool=false, reconnect::Bool=false, application_name::Union{AbstractString, Nothing}=nothing, connect_timeout::Union{Integer, Nothing}=nothing, sslmode::Union{AbstractString, Nothing}=nothing, sslrootcert::Union{AbstractString, Nothing}=nothing, sslcert::Union{AbstractString, Nothing}=nothing, sslkey::Union{AbstractString, Nothing}=nothing, sslcapath::Union{AbstractString, Nothing}=nothing, sslservername::Union{AbstractString, Nothing}=nothing, statement_timeout::Union{Integer, Nothing}=nothing, statement_cache_maxsize::Integer=100, limit::Integer=10, style::API.AbstractPostgresStyle=PostgresStyle())
    connector = () -> DBInterface.connect(Connection, host, user, passwd; dbname=dbname, port=port, debug=debug, reconnect=reconnect, application_name=application_name, connect_timeout=connect_timeout, sslmode=sslmode, sslrootcert=sslrootcert, sslcert=sslcert, sslkey=sslkey, sslcapath=sslcapath, sslservername=sslservername, statement_timeout=statement_timeout, statement_cache_maxsize=statement_cache_maxsize, style=style)
    return ConnectionPool(connector; limit=limit)
end

function ConnectionPool(dsn::String; debug::Union{Bool, Nothing}=nothing, reconnect::Union{Bool, Nothing}=nothing, statement_cache_maxsize::Union{Integer, Nothing}=nothing, limit::Integer=10, style::API.AbstractPostgresStyle=PostgresStyle())
    return ConnectionPool(parse_dsn(dsn); debug=debug, reconnect=reconnect, statement_cache_maxsize=statement_cache_maxsize, limit=limit, style=style)
end

function ConnectionPool(params::ConnectionParams; debug::Union{Bool, Nothing}=nothing, reconnect::Union{Bool, Nothing}=nothing, statement_cache_maxsize::Union{Integer, Nothing}=nothing, limit::Integer=10, style::API.AbstractPostgresStyle=PostgresStyle())
    connector = () -> DBInterface.connect(Connection, params; debug=debug, reconnect=reconnect, statement_cache_maxsize=statement_cache_maxsize, style=style)
    return ConnectionPool(connector; limit=limit)
end

function pool_isvalid(conn::Connection)
    valid = @lock conn.lock isopen(conn.socket) && !conn.closed
    return valid
end

"""
    Postgres.acquire(pool; forcenew=false) -> Connection

Take a connection from the pool, creating one if none is available (blocking
if the pool is at its limit). Return it with [`release`](@ref Postgres.release).
"""
function acquire(pool::ConnectionPool; forcenew::Bool=false)
    pool.closed[] && throw(PostgresInterfaceError("connection pool is closed"))
    conn = Pools.acquire(pool.connector, pool.pool; forcenew=forcenew, isvalid=pool_isvalid)
    closed = @lock pool.lifecycle_lock pool.closed[]
    if closed
        try
            DBInterface.close!(conn)
        finally
            Pools.release(pool.pool)
        end
        throw(PostgresInterfaceError("connection pool is closed"))
    end
    return conn
end

# A connection going back into the pool must not carry a transaction with it:
# the next borrower's `start_transaction` would issue a SAVEPOINT instead of
# BEGIN, and their commit would only decrement the depth — their writes would
# be silently discarded when the connection is later reset. Roll it back; if
# that can't be done, drop the connection instead of handing it on.
function reset_pooled_connection!(conn::Connection)
    # the client flag misses a transaction opened by raw SQL, so trust the
    # server's ReadyForQuery status too
    (in_transaction(conn) || (@lock conn.lock conn.server_in_transaction)) || return true
    try
        @lock conn.lock begin
            checkconn(conn)
            try
                execute_simple(conn, "ROLLBACK")
            finally
                conn.in_transaction = false
                conn.transaction_depth = 0
                empty!(conn.transaction_savepoints)
            end
        end
        return true
    catch
        try
            DBInterface.close!(conn)
        catch
            # already unusable; nothing more to do
        end
        return false
    end
end

"""
    Postgres.release(pool, conn)

Return a connection previously taken with [`acquire`](@ref Postgres.acquire)
to the pool. A connection still inside a transaction is rolled back first, so
the next borrower starts from a clean session; if it can't be rolled back it
is closed rather than reused.
"""
function release(pool::ConnectionPool, conn::Connection)
    reusable = !pool.closed[] && pool_isvalid(conn) && reset_pooled_connection!(conn)
    if reusable
        returned = @lock pool.lifecycle_lock begin
            if pool.closed[]
                false
            else
                Pools.release(pool.pool, conn)
                true
            end
        end
        returned && return pool
    end
    try
        DBInterface.close!(conn)
    catch
        # already unusable; the permit still has to be returned
    finally
        Pools.release(pool.pool)
    end
    return pool
end

"""
    Postgres.with_connection(f, pool; forcenew=false)

Acquire a connection from the pool, call `f(conn)`, and release the connection
back to the pool afterwards. Returns `f`'s result.
"""
function with_connection(f::Function, pool::ConnectionPool; forcenew::Bool=false)
    conn = acquire(pool; forcenew=forcenew)
    try
        return f(conn)
    finally
        release(pool, conn)
    end
end

function DBInterface.close!(pool::ConnectionPool)
    Base.@lock pool.lifecycle_lock begin
        pool.closed[] = true
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
    end
    return pool
end
Base.close(pool::ConnectionPool) = DBInterface.close!(pool)

include("execute.jl")

# Transaction control statements run over the simple-query protocol: one
# atomic message with a single ReadyForQuery, instead of the unnamed
# Parse/Describe/Bind/Execute sequence whose per-step Syncs let a
# transaction-mode pooler (pgbouncer, Neon) reassign the server connection
# mid-sequence and drop the unnamed statement ("unnamed prepared statement
# does not exist"). Also one network round trip instead of three. Callers
# must hold conn.lock.
function execute_simple(conn::Connection, sql::String; expected_tag::Union{Nothing, String}=nothing)
    # capture the ReadyForQuery status through a Ref so a failed statement
    # (a COMMIT hitting a deferred constraint) still refreshes the tracking:
    # the server ended the transaction either way, and a stale flag draws a
    # spurious ROLLBACK on the next pool release
    status_ref = Ref{UInt8}(UInt8('I'))
    command_tag_ref = Ref{Union{Nothing, String}}(nothing)
    try
        API.exec(conn.style, conn.socket, sql, conn.debug, status_ref,
                 command_tag_ref, conn.server_parameters)
    finally
        conn.server_in_transaction = API.in_transaction_status(status_ref[])
    end
    if expected_tag !== nothing && command_tag_ref[] != expected_tag
        actual = something(command_tag_ref[], "no command tag")
        throw(PostgresInterfaceError("expected $expected_tag but PostgreSQL completed $actual"))
    end
    return conn
end

function new_transaction_savepoint!()
    return string("postgres_jl_", replace(string(UUIDs.uuid4()), "-" => ""))
end

"""
    Postgres.start_transaction(conn)

Begin a transaction (`BEGIN`). If a transaction is already open, create a
savepoint instead, so transactions nest. Pair with [`commit`](@ref
Postgres.commit) or [`rollback`](@ref Postgres.rollback); prefer
[`transaction`](@ref Postgres.transaction) or
[`@transaction`](@ref Postgres.@transaction) for automatic handling.
"""
function start_transaction(conn::Connection)
    @lock conn.lock begin
        checkconn(conn)
        if !conn.in_transaction
            if conn.server_in_transaction
                # a transaction opened with raw SQL (execute(conn, "BEGIN"))
                # belongs to the caller: nest inside it with a savepoint, as
                # for driver-owned nesting, so our commit can't commit — and
                # our rollback can't destroy — their work
                savepoint = new_transaction_savepoint!()
                execute_simple(conn, "SAVEPOINT $savepoint"; expected_tag="SAVEPOINT")
                push!(conn.transaction_savepoints, savepoint)
                conn.owns_base_transaction = false
            else
                execute_simple(conn, "BEGIN"; expected_tag="BEGIN")
                conn.owns_base_transaction = true
            end
            conn.in_transaction = true
            conn.transaction_depth = 1
        else
            # Start a SAVEPOINT for nested transactions
            savepoint = new_transaction_savepoint!()
            execute_simple(conn, "SAVEPOINT $savepoint"; expected_tag="SAVEPOINT")
            push!(conn.transaction_savepoints, savepoint)
            conn.transaction_depth += 1
        end
    end
    return conn
end

"""
    Postgres.in_transaction(conn) -> Bool

Whether the connection currently has an open transaction.
"""
in_transaction(conn::Connection) = @lock conn.lock conn.in_transaction

# Forget a transaction whose session is already gone. Nothing can be sent to
# end it, and leaving the flags set makes checkconn refuse to reconnect.
function clear_transaction_state!(conn::Connection)
    @lock conn.lock begin
        conn.in_transaction = false
        conn.transaction_depth = 0
        empty!(conn.transaction_savepoints)
        conn.server_in_transaction = false
    end
    return
end

"""
    Postgres.commit(conn)

Commit the current transaction (or release one level of transaction nesting).
"""
function commit(conn::Connection)
    @lock conn.lock begin
        !conn.in_transaction && throw(PostgresInterfaceError("no transaction in progress"))
        # a dead socket took the transaction with it: clear the bookkeeping
        # before reporting, or checkconn will refuse to reconnect forever
        # ("reconnect disabled during transaction")
        if !isopen(conn.socket)
            conn.in_transaction = false
            conn.transaction_depth = 0
            empty!(conn.transaction_savepoints)
            disconnected()
        end
        checkconn(conn)
        if conn.transaction_depth == 1
            # COMMIT ends the transaction server-side whether it succeeds or
            # fails (and a dead connection ends it too), so the client's
            # transaction state must be cleared either way — leaving it set
            # would block reconnects and make the next cursor skip its BEGIN
            try
                if conn.owns_base_transaction
                    execute_simple(conn, "COMMIT"; expected_tag="COMMIT")
                else
                    # the base transaction is the caller's raw-SQL one: keep
                    # this level's work pending inside it and leave it open
                    savepoint = only(conn.transaction_savepoints)
                    execute_simple(conn, "RELEASE SAVEPOINT $savepoint"; expected_tag="RELEASE")
                end
            finally
                conn.in_transaction = false
                conn.transaction_depth = 0
                empty!(conn.transaction_savepoints)
            end
        else
            # Release SAVEPOINT for nested transaction
            savepoint = last(conn.transaction_savepoints)
            execute_simple(conn, "RELEASE SAVEPOINT $savepoint"; expected_tag="RELEASE")
            pop!(conn.transaction_savepoints)
            conn.transaction_depth -= 1
        end
    end
    return conn
end

"""
    Postgres.rollback(conn)

Roll back the current transaction (or, in a nested transaction, roll back to
the enclosing savepoint).
"""
function rollback(conn::Connection)
    @lock conn.lock begin
        !conn.in_transaction && throw(PostgresInterfaceError("no transaction in progress"))
        # as in commit: a dead session already ended the transaction
        if !isopen(conn.socket)
            conn.in_transaction = false
            conn.transaction_depth = 0
            empty!(conn.transaction_savepoints)
            disconnected()
        end
        checkconn(conn)
        if conn.transaction_depth == 1
            # as in commit: the transaction is over server-side regardless of
            # how ROLLBACK fares, so don't leave client state describing it
            try
                if conn.owns_base_transaction
                    execute_simple(conn, "ROLLBACK"; expected_tag="ROLLBACK")
                else
                    # undo only this level; a plain ROLLBACK would destroy the
                    # caller's raw-SQL transaction along with it
                    savepoint = only(conn.transaction_savepoints)
                    execute_simple(conn, "ROLLBACK TO SAVEPOINT $savepoint"; expected_tag="ROLLBACK")
                    execute_simple(conn, "RELEASE SAVEPOINT $savepoint"; expected_tag="RELEASE")
                end
            finally
                conn.in_transaction = false
                conn.transaction_depth = 0
                empty!(conn.transaction_savepoints)
            end
        else
            # Rollback to SAVEPOINT for nested transaction
            savepoint = last(conn.transaction_savepoints)
            execute_simple(conn, "ROLLBACK TO SAVEPOINT $savepoint"; expected_tag="ROLLBACK")
            execute_simple(conn, "RELEASE SAVEPOINT $savepoint"; expected_tag="RELEASE")
            pop!(conn.transaction_savepoints)
            conn.transaction_depth -= 1
        end
    end
    return conn
end

# Roll back after the body (or the COMMIT) failed. Only acts if a transaction
# is still open — a failed COMMIT has already ended it — and never lets its own
# failure replace the original error, which is what the caller needs to see.
function rollback_for_failed_transaction!(conn::Connection)
    in_transaction(conn) || return
    try
        rollback(conn)
    catch
        # the connection is already failing; the original error is the useful one
    end
    return
end

"""
    Postgres.transaction(f, conn)

Run `f(conn)` inside a transaction: committed if `f` returns normally, rolled
back if it throws. Nested calls use savepoints. Returns `f`'s result.

A transaction already opened with raw SQL (`execute(conn, "BEGIN")`) is
treated as the enclosing level: the block nests inside it with a savepoint
and leaves it open, so the caller's own `COMMIT`/`ROLLBACK` stays in control
of their transaction.

    Postgres.transaction(conn) do conn
        DBInterface.execute(conn, "INSERT INTO t VALUES (1)")
    end
"""
function transaction(f::F, conn::Connection) where {F}
    start_transaction(conn)
    try
        result = f(conn)
        commit(conn)
        return result
    catch
        rollback_for_failed_transaction!(conn)
        rethrow()
    end
end

function DBInterface.transaction(f::F, conn::Connection) where {F}
    start_transaction(conn)
    try
        result = f()
        commit(conn)
        return result
    catch
        rollback_for_failed_transaction!(conn)
        rethrow()
    end
end

# `token` identifies the @transaction expansion that rewrote the `return`.
# Without it, a lexically nested @transaction intercepts the outer expansion's
# marker, commits only its own savepoint, and its plain `return` then skips
# every enclosing commit — silently rolling back all levels.
struct TransactionReturn{T} <: Exception
    token::Symbol
    value::T
end

# Macros that wrap their body in a closure or task: a `return` inside them
# belongs to that closure (it becomes the task's result), so it must not be
# rewritten into a transaction-return marker.
const _TASK_MACROS = (Symbol("@spawn"), Symbol("@async"), Symbol("@task"),
                      Symbol("@threads"), Symbol("@distributed"), Symbol("@spawnat"))

_macro_name(x) = x isa Symbol ? x :
    x isa GlobalRef ? x.name :
    (x isa Expr && x.head === :. && x.args[2] isa QuoteNode) ? x.args[2].value :
    nothing

# Short-form function definitions — `h(x) = ...`, `h(x)::T = ...`,
# `h(x) where {T} = ...` — parse as `:(=)` with a call-shaped left-hand side.
# A return inside one belongs to that function, exactly like the long
# `function` form the rewrite already skips.
_is_callish_lhs(x) = x isa Expr && (x.head === :call ||
    ((x.head === :where || x.head === :(::)) && !isempty(x.args) && _is_callish_lhs(x.args[1])))

function rewrite_transaction_returns(expr, token::Symbol)
    expr isa Expr || return expr
    if expr.head === :return
        value = (isempty(expr.args) || expr.args[1] === nothing) ? nothing :
            rewrite_transaction_returns(expr.args[1], token)
        marker = GlobalRef(@__MODULE__, :TransactionReturn)
        return Expr(:call, GlobalRef(Core, :throw), Expr(:call, marker, QuoteNode(token), value))
    elseif expr.head === :function || expr.head === :(->) || expr.head === :quote ||
           (expr.head === :(=) && _is_callish_lhs(expr.args[1]))
        # A return in a nested function (long form, arrow, or short form)
        # belongs to that function, not to the scope that contains this
        # transaction macro.
        return expr
    elseif expr.head === :macrocall && _macro_name(expr.args[1]) in _TASK_MACROS
        return expr
    elseif expr.head === :try
        return _rewrite_transaction_try(expr, token)
    end
    return Expr(expr.head, map(a -> rewrite_transaction_returns(a, token), expr.args)...)
end

# A user `catch` inside the body would intercept the transaction-return marker
# (it is thrown as an exception) and silently produce the catch's value instead
# of returning. The marker is a private type no user handler can mean to catch,
# so re-throwing it at the top of every user catch is always correct.
function _rewrite_transaction_try(expr::Expr, token::Symbol)
    args = Any[rewrite_transaction_returns(a, token) for a in expr.args]
    if length(args) >= 3 && args[3] !== false
        var = args[2]
        if var === false
            var = gensym(:transaction_err)
            args[2] = var
        end
        marker = GlobalRef(@__MODULE__, :TransactionReturn)
        guard = Expr(:&&, Expr(:call, GlobalRef(Core, :isa), var, marker),
                     Expr(:call, GlobalRef(Base, :rethrow)))
        args[3] = Expr(:block, guard, args[3])
    end
    return Expr(:try, args...)
end

"""
    Postgres.@transaction conn expr

Run `expr` inside a transaction. Any non-exceptional exit commits: normal
completion, `return` (which then returns from the enclosing function),
`break`, or `continue`. Only a thrown exception rolls back. Evaluates to
`expr`'s value. Nested `@transaction` blocks use savepoints, and an early
`return` commits every enclosing level.
"""
macro transaction(conn, expr)
    token = gensym(:transaction_return)
    body = rewrite_transaction_returns(expr, token)
    quote
        # bind once: the connection expression may have side effects
        # (`@transaction acquire(pool) ...` would otherwise take a different
        # connection for the BEGIN, the COMMIT and the ROLLBACK)
        local c = $(esc(conn))
        local success = false
        local completed = false
        start_transaction(c)
        try
            local result
            try
                result = $(esc(body))
            catch err
                if err isa TransactionReturn
                    # an early return is the success path for every enclosing
                    # transaction level: commit this level either way, then
                    # return here only if this expansion owns the marker —
                    # otherwise keep unwinding to the owning expansion
                    commit(c)
                    success = true
                    completed = true
                    err.token === $(QuoteNode(token)) && return err.value
                end
                rethrow()
            end
            commit(c)
            success = true
            completed = true
            result
        catch
            if !success
                rollback_for_failed_transaction!(c)
            end
            completed = true
            rethrow()
        finally
            # break/continue exit the block without passing the commit above,
            # any catch, or a return: a deliberate non-exceptional exit, so it
            # commits like the others
            completed || commit(c)
        end
    end
end

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

"""
    Postgres.describe(conn, table; schema="public")

Return a printable summary of a table's columns: name, type, nullability,
default, primary-key flag, and foreign-key reference.
"""
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
                information_schema.key_column_usage kcu ON
                    c.table_catalog = kcu.table_catalog AND
                    c.table_schema = kcu.table_schema AND
                    c.table_name = kcu.table_name AND
                    c.column_name = kcu.column_name
            LEFT JOIN
                information_schema.table_constraints tc ON
                    kcu.constraint_catalog = tc.constraint_catalog AND
                    kcu.constraint_schema = tc.constraint_schema AND
                    kcu.constraint_name = tc.constraint_name AND
                    kcu.table_schema = tc.table_schema AND
                    kcu.table_name = tc.table_name
            LEFT JOIN
                information_schema.referential_constraints rc ON
                    tc.constraint_catalog = rc.constraint_catalog AND
                    tc.constraint_schema = rc.constraint_schema AND
                    tc.constraint_name = rc.constraint_name
            LEFT JOIN
                information_schema.key_column_usage fk ON
                    rc.unique_constraint_catalog = fk.constraint_catalog AND
                    rc.unique_constraint_schema = fk.constraint_schema AND
                    rc.unique_constraint_name = fk.constraint_name AND
                    kcu.position_in_unique_constraint = fk.ordinal_position
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

# the supported API surface (`public` requires Julia 1.11+; the names are
# parsed from a string so the file still loads on 1.10)
@static if VERSION >= v"1.11"
    eval(Meta.parse(
        "public Connection, ConnectionPool, ConnectionParams, PostgresInterfaceError, " *
        "Error, Notification, Numeric, PostgresRange, AbstractPostgresStyle, PostgresStyle, " *
        "query_logging_enabled, query_logger, notice_callback, notification_callback, parse_dsn, " *
        "transaction, @transaction, start_transaction, commit, rollback, in_transaction, " *
        "cursor, copy_from, copy_to, listen!, unlisten!, notify!, wait_for_notification, " *
        "register_type!, register_enum!, register_composite!, register_range!, " *
        "command_tag, rows_affected, cancel_query!, escape_identifier, escape_literal, " *
        "get_cached_statements, clear_statement_cache!, set_statement_cache_maxsize!, " *
        "get_server_parameter, get_server_parameters, get_statement_timeout, set_statement_timeout!, " *
        "acquire, release, with_connection, describe"))
end

end
