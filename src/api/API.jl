module API

using UUIDs, Dates, Reseau, SASLAuth, MD5, Parsers, StructUtils, JSON, Random
import ..PostgresInterfaceError

export PostgresStyle, AbstractPostgresStyle, query_logging_enabled, query_logger, notice_callback, notification_callback, Error, Notification, Numeric, PostgresRange, cancel_request

const ReseauConn = Union{Reseau.TCP.Conn, Reseau.TLS.Conn}
const SKIP_BUFFER_SIZE = 8192

"""
    Postgres.Error <: Exception

A PostgreSQL server error (an `ErrorResponse` message). Carries the fields the
server reported: `severity` (non-localized when the server supplies it, so it
can be compared against `"FATAL"`, `"ERROR"`, ... regardless of the server's
`lc_messages`), `code` (the SQLSTATE, e.g. `"23505"`), `message`,
and optional context such as `detail`, `hint`, `position`, `schema`, `table`,
`column`, and `constraint`. A small number of protocol-level failures detected
client-side (unsupported authentication methods, protocol desync) also use
this type, with an empty `code`; other client-side failures throw
`Postgres.PostgresInterfaceError`.
"""
struct Error <: Exception
    severity::String
    code::String
    message::String
    detail::Union{String, Nothing}
    hint::Union{String, Nothing}
    position::Union{String, Nothing}
    internal_position::Union{String, Nothing}
    internal_query::Union{String, Nothing}
    where::Union{String, Nothing}
    schema::Union{String, Nothing}
    table::Union{String, Nothing}
    column::Union{String, Nothing}
    datatype::Union{String, Nothing}
    constraint::Union{String, Nothing}
    file::Union{String, Nothing}
    line::Union{String, Nothing}
    routine::Union{String, Nothing}
end

"""
    Postgres.Notification

An asynchronous `NOTIFY` message received from the server, with the notifying
backend's `pid`, the `channel` name, and the `payload` string (empty when the
notification had no payload). See `Postgres.listen!` and
`Postgres.wait_for_notification`.
"""
struct Notification
    pid::Int32
    channel::String
    payload::String
end

Error(message::String) = Error("ERROR", "", message, nothing, nothing, nothing, nothing, nothing, nothing, nothing, nothing, nothing, nothing, nothing, nothing, nothing, nothing)

function Base.showerror(io::IO, e::Error)
    println(io, "Postgres.Error:")
    println(io, "  Severity: $(e.severity)")
    println(io, "  Code: $(e.code)")
    println(io, "  Message: $(e.message)")
    !isnothing(e.detail) && println(io, "  Detail: $(e.detail)")
    !isnothing(e.hint) && println(io, "  Hint: $(e.hint)")
    !isnothing(e.position) && println(io, "  Position: $(e.position)")
    !isnothing(e.where) && println(io, "  Where: $(e.where)")
    !isnothing(e.schema) && println(io, "  Schema: $(e.schema)")
    !isnothing(e.table) && println(io, "  Table: $(e.table)")
    !isnothing(e.column) && println(io, "  Column: $(e.column)")
    return
end

# Read a NUL-terminated string from `buf` starting at `pos`, bounded by the
# buffer's actual length: `read` returns a short buffer at EOF, and a hostile
# or failing server can send an unterminated or truncated field, so an
# unbounded scan (plain `unsafe_string(pointer(buf, pos))`) would read past
# the allocation. Returns (string, next_pos).
function cstring_at(buf::Vector{UInt8}, pos::Int)
    n = length(buf)
    pos > n && return "", n + 1
    stop = findnext(isequal(UInt8(0)), buf, pos)
    if stop === nothing
        return GC.@preserve(buf, unsafe_string(pointer(buf, pos), n - pos + 1)), n + 1
    end
    return GC.@preserve(buf, unsafe_string(pointer(buf, pos), stop - pos)), stop + 1
end

function errorResponse(len, socket, debug)
    buf = read(socket, len)
    # parse error fields
    i = 1
    severity = ""
    # 'V' is the non-localized severity (PostgreSQL 9.6+); 'S' is translated
    # per the server's lc_messages, so it can't be compared against literals
    severity_nonlocalized = ""
    code = ""
    message = ""
    detail = nothing
    hint = nothing
    position = nothing
    internal_position = nothing
    internal_query = nothing
    where = nothing
    schema = nothing
    table = nothing
    column = nothing
    datatype = nothing
    constraint = nothing
    file = nothing
    line = nothing
    routine = nothing
    while i <= length(buf)
        ccode = Char(buf[i])
        # the field list is terminated by a zero byte
        ccode == '\0' && break
        i += 1
        val, i = cstring_at(buf, i)
        if ccode == 'S'
            severity = val
        elseif ccode == 'V'
            severity_nonlocalized = val
        elseif ccode == 'C'
            code = val
        elseif ccode == 'M'
            message = val
        elseif ccode == 'D'
            detail = val
        elseif ccode == 'H'
            hint = val
        elseif ccode == 'P'
            position = val
        elseif ccode == 'p'
            internal_position = val
        elseif ccode == 'q'
            internal_query = val
        elseif ccode == 'W'
            where = val
        elseif ccode == 's'
            schema = val
        elseif ccode == 't'
            table = val
        elseif ccode == 'c'
            column = val
        elseif ccode == 'd'
            datatype = val
        elseif ccode == 'n'
            constraint = val
        elseif ccode == 'F'
            file = val
        elseif ccode == 'L'
            line = val
        elseif ccode == 'R'
            routine = val
        end
    end
    # prefer the non-localized severity so callers can compare it to "FATAL"
    # and friends regardless of the server's locale
    isempty(severity_nonlocalized) || (severity = severity_nonlocalized)
    err = Error(severity, code, message, detail, hint, position, internal_position, internal_query, where, schema, table, column, datatype, constraint, file, line, routine)
    debug && @error err
    return err
end

function noticeResponse(len, socket)
    buf = read(socket, len)
    i = 1
    notice = Dict{String, String}()
    while i <= length(buf)
        ccode = Char(buf[i])
        ccode == '\0' && break
        i += 1
        val, i = cstring_at(buf, i)
        notice[string(ccode)] = val
    end
    return notice
end

function notificationResponse(len, socket)
    # the body is at least the 4-byte pid; a shorter one would make the
    # channel/payload read consume the next message
    len < 4 && throw(Error("truncated NotificationResponse from server"))
    pid = ntoh(read(socket, Int32))
    buf = read(socket, len - 4)
    i = 1
    channel = ""
    payload = ""
    if !isempty(buf)
        channel, i = cstring_at(buf, i)
        i <= length(buf) && ((payload, i) = cstring_at(buf, i))
    end
    return Notification(pid, channel, payload)
end

include("types.jl")

struct Params
    params::Vector{Union{String, Missing}}
end

msgsizeof(x::String) = sizeof(x) + 1
msgsizeof(x::AbstractVector{UInt8}) = length(x)
msgsizeof(x) = sizeof(x)
msgsizeof(x::Tuple{String, String}) = sizeof(x[1]) + 1 + sizeof(x[2]) + 1
msgsizeof(x::Params) = sum(4 + (ismissing(p) ? 0 : sizeof(p)) for p in x.params; init=0)

_msgsizeof_parts(::Tuple{}) = 0
_msgsizeof_parts(parts::Tuple) = msgsizeof(first(parts)) + _msgsizeof_parts(Base.tail(parts))

writepart(io, x) = write(io, x)
function writepart(io, x::String)
    write(io, x)
    write(io, UInt8(0))
end
writepart(io, x::Integer) = write(io, hton(x))
function writepart(io, x::Tuple{String, String})
    write(io, x[1])
    write(io, UInt8(0))
    write(io, x[2])
    write(io, UInt8(0))
end
writepart(io, x::UInt8) = write(io, x)
function writepart(io, x::Params)
    for p in x.params
        if ismissing(p)
            writepart(io, Int32(-1))
        else
            writepart(io, Int32(sizeof(p)))
            write(io, p) # p must be String, but we only want to write bytes, not the null terminator
        end
    end
end

_writeparts(io, ::Tuple{}) = nothing
function _writeparts(io, parts::Tuple)
    writepart(io, first(parts))
    _writeparts(io, Base.tail(parts))
    return nothing
end

function _write_message_to_buffer(buf::IOBuffer, debug::Bool, msg::Tuple)
    code = first(msg)::Char
    parts = Base.tail(msg)
    debug && @info "sending message: $code, $parts"
    len = Int32(4 + _msgsizeof_parts(parts))
    code != '\0' && write(buf, UInt8(code))
    write(buf, hton(len))
    _writeparts(buf, parts)
    return nothing
end

function _writemessage_parts(socket, debug::Bool, code::Char, parts::Tuple)::Nothing
    debug && @info "sending message: $code, $parts"
    len = Int32(4 + _msgsizeof_parts(parts))
    buf = IOBuffer(Vector{UInt8}(undef, len + 1); write=true)
    code != '\0' && write(buf, UInt8(code))
    write(buf, hton(len))
    _writeparts(buf, parts)
    write(socket, take!(buf))
    flush(socket)
    return nothing
end

writemessage(socket, debug::Bool, code::Char) = _writemessage_parts(socket, debug, code, ())
writemessage(socket, debug::Bool, code::Char, part1) = _writemessage_parts(socket, debug, code, (part1,))
writemessage(socket, debug::Bool, code::Char, part1, part2) = _writemessage_parts(socket, debug, code, (part1, part2))
writemessage(socket, debug::Bool, code::Char, part1, part2, part3) = _writemessage_parts(socket, debug, code, (part1, part2, part3))
writemessage(socket, debug::Bool, code::Char, parts...) = _writemessage_parts(socket, debug, code, parts)

function _write_startup_param(buf::IOBuffer, key::String, value::String)::Nothing
    writepart(buf, (key, value))
    return nothing
end

function writestartupmessage(
    socket,
    debug::Bool,
    user::String,
    dbname::String,
    application_name::Union{Nothing, String},
    statement_timeout::Union{Nothing, Int},
)::Nothing
    timeout_options = statement_timeout === nothing ? nothing : string("-c statement_timeout=", statement_timeout)
    len = 8 + msgsizeof(("user", user)) + msgsizeof(("database", dbname)) + 1
    application_name !== nothing && (len += msgsizeof(("application_name", application_name)))
    timeout_options !== nothing && (len += msgsizeof(("options", timeout_options)))
    debug && @info "sending startup message"
    buf = IOBuffer(Vector{UInt8}(undef, len); write=true)
    write(buf, hton(Int32(len)))
    write(buf, hton(Int32(196608)))
    _write_startup_param(buf, "user", user)
    _write_startup_param(buf, "database", dbname)
    application_name !== nothing && _write_startup_param(buf, "application_name", application_name)
    timeout_options !== nothing && _write_startup_param(buf, "options", timeout_options)
    write(buf, UInt8(0))
    write(socket, take!(buf))
    flush(socket)
    return nothing
end

function writemessages(socket, debug::Bool, msgs::Vararg{Tuple, N}) where {N}
    buf = IOBuffer()
    for msg in msgs
        _write_message_to_buffer(buf, debug, msg)
    end
    write(socket, take!(buf))
    flush(socket)
    return
end

_sum_codes(::Tuple{}) = 0
_sum_codes(codes::Tuple) = UInt8(first(codes)) + _sum_codes(Base.tail(codes))

_contains_code(::UInt8, ::Tuple{}) = false
function _contains_code(mt::UInt8, codes::Tuple)
    return mt == UInt8(first(codes)) || _contains_code(mt, Base.tail(codes))
end

function skipbytes!(io::IO, n::Integer)
    remaining = Int(n)
    remaining <= 0 && return nothing
    buf = Vector{UInt8}(undef, min(SKIP_BUFFER_SIZE, remaining))
    while remaining > 0
        nb = min(length(buf), remaining)
        readbytes!(io, buf, nb)
        remaining -= nb
    end
    return nothing
end

# PostgreSQL's own protocol maximum (PQ_LARGE_MESSAGE_LIMIT): no valid message
# body exceeds 1 GiB. The length is server-supplied and the transport allocates
# it up front, so bound it here — the single point every message passes through
# — rather than letting a bogus header commit gigabytes. This is reachable
# before authentication (an ErrorResponse to the SSLRequest), so it must not
# depend on a trusted peer.
const MAX_MESSAGE_LEN = Int32(1) << 30

# A bogus length means the stream is desynchronized, so the socket must be
# closed before throwing — callers such as describeprepared treat a surviving
# `Error` as "the stream is clean, at ReadyForQuery" and would otherwise keep
# using a connection whose position is unknowable.
@noinline function _bad_message_length(socket, len)
    close(socket)
    throw(Error("invalid message length $len from server; connection protocol state is corrupted"))
end

function readheader(socket, debug=false)
    mt = read(socket, UInt8)
    len = ntoh(read(socket, Int32)) - 4
    debug && @info "readheader: $(Char(mt)), $len"
    (len < 0 || len > MAX_MESSAGE_LEN) && _bad_message_length(socket, len)
    return mt, len
end

function close_and_throw_error_response(socket, len, debug)
    err = errorResponse(len, socket, debug)
    close(socket)
    throw(err)
end

function close_and_throw(socket, err)
    close(socket)
    throw(err)
end

# Read and discard messages through ReadyForQuery so a connection whose result
# stream was abandoned mid-way stays usable. Must be called at a message
# boundary. If the connection fails while draining, close it: the stream
# position is unknowable and the socket must never be reused.
function drain_to_ready!(socket, debug)
    try
        while true
            mt, len = readheader(socket, debug)
            skipbytes!(socket, len)
            mt == UInt8('Z') && break
        end
    catch
        close(socket)
    end
    return
end

# Read the next message header, expecting one of `expected`. Asynchronous
# messages (parameter status, notices, notifications) are skipped. An
# ErrorResponse is read fully, the stream drained through ReadyForQuery (the
# connection stays usable), and thrown as a Postgres.Error. Any other message
# type means the stream is desynchronized: close the connection and throw.
function read_expected(socket, debug, expected::Char...)
    while true
        mt, len = readheader(socket, debug)
        if any(c -> mt == UInt8(c), expected)
            return mt, len
        elseif mt == UInt8('E')
            err = errorResponse(len, socket, debug)
            drain_to_ready!(socket, debug)
            throw(err)
        elseif mt == UInt8('S') || mt == UInt8('N') || mt == UInt8('A')
            skipbytes!(socket, len)
        else
            close_and_throw(socket, Error("unexpected message type '$(Char(mt))' from server; connection protocol state is corrupted"))
        end
    end
end

function expect_auth_message(socket, debug, mt, len)
    mt == UInt8('R') && return
    mt == UInt8('E') && close_and_throw_error_response(socket, len, debug)
    close_and_throw(socket, Error("unexpected message type: $(Char(mt))"))
end

# wait for code, then ready
function waitfor(socket, debug::Bool, codes::Vararg{Char, N}) where {N}
    error = false
    error_msg = nothing
    found = _sum_codes(codes)
    pid = skey = Int32(0)
    server_params = Dict{String, String}()
    debug && @info "waitfor: $codes"
    try
        while true
            mt, len = readheader(socket, debug)
            if mt == UInt8('E')
                # error
                error = true
                error_msg = errorResponse(len, socket, debug)
            elseif error && mt == UInt8('Z')
                # error followed by ready
                skipbytes!(socket, len)
                break
            elseif mt == UInt8('S')
                # parameter status
                buf = read(socket, len)
                i = 1
                GC.@preserve buf while i <= length(buf)
                    j = findnext(isequal(UInt8(0)), buf, i)
                    j === nothing && break
                    key = unsafe_string(pointer(buf, i), j - i)
                    i = j + 1
                    j = findnext(isequal(UInt8(0)), buf, i)
                    j === nothing && break
                    val = unsafe_string(pointer(buf, i), j - i)
                    server_params[key] = val
                    i = j + 1
                end
            elseif _contains_code(mt, codes)
                # found
                found -= mt
                if mt == UInt8('K')
                    pid = ntoh(read(socket, Int32))
                    skey = ntoh(read(socket, Int32))
                else
                    # read off message
                    skipbytes!(socket, len)
                end
                found == 0 && break
            else
                # any other message (notices, notifications, ...): discard the
                # body. Without this the body is read as the next header and
                # the stream desynchronizes — e.g. a NOTIFY delivered on a
                # connection that is also running queries.
                skipbytes!(socket, len)
            end
        end
    catch
        # the connection failed mid-response: the stream position is
        # unknowable, so the socket must never be reused
        close(socket)
        # if the server sent an ErrorResponse before the connection died
        # (e.g. the backend was terminated), surface it over the raw IO error
        error_msg === nothing || throw(error_msg)
        rethrow()
    end
    error_msg === nothing && error && throw(Error("unexpected error response"))
    error && throw(error_msg)
    return pid, skey, server_params
end

# password material must never reach the debug log: password-bearing messages
# are written with debug=false and a redacted line is logged instead
function write_password_message(socket, debug::Bool, password::String)
    debug && @info "sending message: p, (password redacted)"
    writemessage(socket, false, 'p', password)
    return
end

function authRequest(debug, len, socket, user, password, client::Union{Nothing, SASLAuth.SCRAMSHA256Client}=nothing)
    auth_code = ntoh(read(socket, Int32))
    debug && @info "auth code: $auth_code"
    if auth_code == 0
        # authentication ok
        return socket
    elseif auth_code == 2
        # kerberos v5
        close(socket)
        throw(Error("kerberos v5 authentication not supported"))
    elseif auth_code == 3
        # send cleartext password message
        write_password_message(socket, debug, password)
        mt, len = readheader(socket, debug)
        if mt == UInt8('E')
            # error
            close_and_throw_error_response(socket, len, debug)
        elseif mt == UInt8('R')
            auth_code = ntoh(read(socket, Int32))
            if auth_code == 0
                # authentication ok
                return socket
            else
                close_and_throw(socket, Error("cleartext password authentication failed: $auth_code"))
            end
        else
            close_and_throw(socket, Error("unexpected message type: $(Char(mt))"))
        end
    elseif auth_code == 5
        # md5 salt
        salt = read(socket, 4)
        debug && @info "md5 salt: $salt"
        # concat('md5', md5(concat(md5(concat(password, username)), random-salt)))
        # Calculate the MD5 password
        pass = string("md5", bytes2hex(md5(vcat(Vector{UInt8}(bytes2hex(md5(string(password, user)))), salt))))
        # Send password message
        write_password_message(socket, debug, pass)
        mt, len = readheader(socket, debug)
        if mt == UInt8('E')
            # error
            close_and_throw_error_response(socket, len, debug)
        elseif mt == UInt8('R')
            auth_code = ntoh(read(socket, Int32))
            if auth_code == 0
                # authentication ok
                return socket
            else
                close_and_throw(socket, Error("MD5 password authentication failed: $auth_code"))
            end
        else
            close_and_throw(socket, Error("unexpected message type: $(Char(mt))"))
        end
    elseif auth_code == 7
        # GSSAPI
        close_and_throw(socket, Error("GSSAPI authentication not supported"))

    elseif auth_code == 8
        # Specifies that this message contains GSSAPI or SSPI data.
        close_and_throw(socket, Error("GSSAPI/SSPI continuation not supported"))

    elseif auth_code == 9
        # Specifies that SSPI authentication is required.
        close_and_throw(socket, Error("SSPI authentication not supported"))

    elseif auth_code == 10
        # SASL Authentication Required
        data = String(read(socket, len - 4))
        mechanisms = split(data, '\0'; keepempty=false)

        if "SCRAM-SHA-256" ∉ mechanisms
            close_and_throw(socket, Error("no supported SASL mechanisms"))
        end
        client = SASLAuth.SCRAMSHA256Client(user, password)
        msg, _ = SASLAuth.step!(client, nothing)
        bytes = Vector{UInt8}(msg)
        # SASL messages carry the client nonce and (in the client-final message)
        # the client proof, from which the password is brute-forcible offline:
        # write them with debug=false and log a redacted line instead
        debug && @info "sending message: p, (SASL initial response redacted)"
        writemessage(socket, false, 'p', "SCRAM-SHA-256", Int32(length(bytes)), bytes)
        mt, len = readheader(socket, debug)
        expect_auth_message(socket, debug, mt, len)
        return authRequest(debug, len, socket, user, password, client)
    elseif auth_code == 11
        # SASL Challenge
        challenge = String(read(socket, len - 4))
        msg, _ = SASLAuth.step!(client, challenge)
        debug && @info "sending message: p, (SASL response redacted)"
        writemessage(socket, false, 'p', Vector{UInt8}(msg))
        mt, len = readheader(socket, debug)
        expect_auth_message(socket, debug, mt, len)
        return authRequest(debug, len, socket, user, password, client)
    elseif auth_code == 12
        # SASL Final Message
        final_msg = String(read(socket, len - 4))
        _, done = SASLAuth.step!(client, final_msg)
        done || close_and_throw(socket, Error("SASL authentication did not complete"))
        mt, len = readheader(socket, debug)
        expect_auth_message(socket, debug, mt, len)
        auth_code = ntoh(read(socket, Int32))
        auth_code == 0 || close_and_throw(socket, Error("SASL authentication failed: $auth_code"))
        return socket
    else
        close_and_throw(socket, Error("unknown authentication code: $auth_code"))
    end
end

function authRequest(debug, len, socket, user, ::Nothing, client::Nothing=nothing)
    auth_code = ntoh(read(socket, Int32))
    debug && @info "auth code: $auth_code"
    if auth_code == 0
        return socket
    elseif auth_code == 2
        close_and_throw(socket, Error("kerberos v5 authentication not supported"))
    elseif auth_code == 3 || auth_code == 5 || auth_code == 10 || auth_code == 11 || auth_code == 12
        close_and_throw(socket, Error("server requested password authentication but no password was provided"))
    elseif auth_code == 7
        close_and_throw(socket, Error("GSSAPI authentication not supported"))
    elseif auth_code == 8
        close_and_throw(socket, Error("GSSAPI/SSPI continuation not supported"))
    elseif auth_code == 9
        close_and_throw(socket, Error("SSPI authentication not supported"))
    else
        close_and_throw(socket, Error("unknown authentication code: $auth_code"))
    end
end

connectsocket(host::AbstractString, port::Integer; connect_timeout::Union{Int, Nothing}=nothing) =
    connectsocket(host, port, connect_timeout)

# `host:port` for Reseau, with IPv6 literals bracketed (`[::1]:5432`) so the
# address parser doesn't reject the extra colons
function hostport_address(host::AbstractString, port::Integer)
    startswith(host, '/') && throw(PostgresInterfaceError("unix socket connections are not supported; provide a TCP host"))
    h = String(host)
    (startswith(h, '[') && endswith(h, ']')) && return string(h, ":", Int(port))
    return occursin(':', h) ? string("[", h, "]:", Int(port)) : string(h, ":", Int(port))
end

function connectsocket(host::AbstractString, port::Integer, @nospecialize(connect_timeout::Union{Int, Nothing}))
    address = hostport_address(host, port)
    return if connect_timeout === nothing
        Reseau.TCP.connect(address)
    else
        timeout_ns = Int64(connect_timeout) * 1_000_000_000
        Reseau.TCP.connect(address; timeout_ns)
    end
end

function tlsupgrade(
        socket::Reseau.TCP.Conn;
        connect_timeout::Union{Int, Nothing}=nothing,
        server_name::Union{String, Nothing}=nothing,
        verify_peer::Bool=true,
        ssl_cert::Union{String, Nothing}=nothing,
        ssl_key::Union{String, Nothing}=nothing,
        ssl_cacert::Union{String, Nothing}=nothing,
        ssl_capath::Union{String, Nothing}=nothing,
    )
    return tlsupgrade(socket, connect_timeout, server_name, verify_peer,
                      ssl_cert, ssl_key, ssl_cacert, ssl_capath)
end

function tlsupgrade(socket::Reseau.TCP.Conn, @nospecialize(connect_timeout::Union{Int, Nothing}),
                    @nospecialize(server_name::Union{String, Nothing}), verify_peer::Bool,
                    @nospecialize(ssl_cert::Union{String, Nothing}), @nospecialize(ssl_key::Union{String, Nothing}),
                    @nospecialize(ssl_cacert::Union{String, Nothing}), @nospecialize(ssl_capath::Union{String, Nothing}))
    ca_file = ssl_cacert === nothing ? ssl_capath : ssl_cacert
    handshake_timeout_ns = connect_timeout === nothing ? Int64(0) : Int64(connect_timeout) * 1_000_000_000
    sni = server_name isa String ? server_name : nothing

    # positional Config, split on the cert/key pair: the kwargs form (and >2
    # Union-valued args at once) is unresolvable dynamic dispatch under --trim
    config = if ssl_cert === nothing && ssl_key === nothing
        Reseau.TLS.Config(sni, verify_peer, verify_peer, Reseau.TLS.ClientAuthMode.NoClientCert,
                          nothing, nothing, ca_file, nothing, String[], UInt16[],
                          handshake_timeout_ns, Reseau.TLS.TLS1_2_VERSION, nothing, false)
    else
        Reseau.TLS.Config(sni, verify_peer, verify_peer, Reseau.TLS.ClientAuthMode.NoClientCert,
                          ssl_cert::String, ssl_key::String, ca_file, nothing, String[], UInt16[],
                          handshake_timeout_ns, Reseau.TLS.TLS1_2_VERSION, nothing, false)
    end
    tls_conn = Reseau.TLS.client(socket, config)
    try
        Reseau.TLS.handshake!(tls_conn)
        return tls_conn
    catch
        close(tls_conn)
        rethrow()
    end
end

# sslservername: TLS SNI override for when `host` is a pre-resolved address —
# SNI-routed servers (e.g. Neon) need the hostname on the TLS handshake even
# when the TCP dial goes to an IP.
function connect(host::String, port::Integer, dbname::String, user::String, @nospecialize(password::Union{String, Nothing}), debug::Bool, @nospecialize(application_name::Union{String, Nothing}), @nospecialize(connect_timeout::Union{Int, Nothing}), @nospecialize(sslmode::Union{String, Nothing}), @nospecialize(sslrootcert::Union{String, Nothing}), @nospecialize(sslcert::Union{String, Nothing}), @nospecialize(sslkey::Union{String, Nothing}), @nospecialize(sslcapath::Union{String, Nothing}), @nospecialize(sslservername::Union{String, Nothing}), @nospecialize(statement_timeout::Union{Int, Nothing}))
    # re-assert the @nospecialize'd params to their declared unions: the asserts give
    # inference the (static) union types without re-introducing per-argument
    # specialization, so the kwarg NamedTuples below have static types instead of
    # runtime apply_type — which `juliac --trim` can't resolve
    password_v = password::Union{String, Nothing}
    application_name_v = application_name::Union{String, Nothing}
    connect_timeout_v = connect_timeout::Union{Int, Nothing}
    sslmode_v = sslmode::Union{String, Nothing}
    sslrootcert_v = sslrootcert::Union{String, Nothing}
    sslcert_v = sslcert::Union{String, Nothing}
    sslkey_v = sslkey::Union{String, Nothing}
    sslcapath_v = sslcapath::Union{String, Nothing}
    sslservername_v = sslservername::Union{String, Nothing}
    statement_timeout_v = statement_timeout::Union{Int, Nothing}
    socket = connectsocket(host, port, connect_timeout_v)
    # Any failure from here on must close the socket: nothing else holds a
    # reference to it, and the transport has no finalizer, so an escaping
    # exception would leak the descriptor for the life of the process —
    # a pool or reconnect loop against a flapping server would hit EMFILE.
    try
    sslmode_str = sslmode_v === nothing ? "prefer" : lowercase(String(sslmode_v))
    sslmode_str == "disable" || sslmode_str == "prefer" || sslmode_str == "require" || sslmode_str == "verify-full" || throw(Error("invalid sslmode: $sslmode_str"))
    if sslmode_str != "disable"
        # send SSLRequest
        writemessage(socket, debug, '\0', Int32(80877103))
        mt = read(socket, UInt8)
        if mt == UInt8('S')
            # upgrade socket to tls and do handshake
            socket = tlsupgrade(socket, connect_timeout_v,
                                sslservername_v isa String ? sslservername_v : host,
                                sslmode_str == "verify-full",
                                sslcert_v, sslkey_v, sslrootcert_v, sslcapath_v)
        elseif mt == UInt8('N')
            (sslmode_str == "require" || sslmode_str == "verify-full") && throw(Error("server does not support SSL"))
        elseif mt == UInt8('E')
            # server may answer SSLRequest with a full ErrorResponse. This is
            # pre-TLS and pre-auth, so bound the length like readheader does
            # before handing it to the allocating read.
            len = ntoh(read(socket, Int32)) - 4
            (len < 0 || len > MAX_MESSAGE_LEN) && close_and_throw(socket, Error("invalid message length $len from server"))
            close_and_throw_error_response(socket, len, debug)
        else
            close_and_throw(socket, Error("unexpected response to SSLRequest: $(Char(mt))"))
        end
    end
    # socket-union isa split (post-TLS-upgrade φ) so the call resolves under --trim
    if socket isa Reseau.TCP.Conn
        writestartupmessage(socket::Reseau.TCP.Conn, debug, user, dbname, application_name_v, statement_timeout_v)
    else
        writestartupmessage(socket::Reseau.TLS.Conn, debug, user, dbname, application_name_v, statement_timeout_v)
    end
    # read initial response
    mt, len = readheader(socket, debug)
    if mt == UInt8('E')
        # error
        close_and_throw_error_response(socket, len, debug)
    elseif mt == UInt8('R')
        authRequest(debug, len, socket, user, password_v)
    elseif mt == UInt8('v')
        # server version too old
        close_and_throw(socket, Error("server version too old"))
    end
    pid, skey, server_params = waitfor(socket, debug, 'K', 'Z')
    # socket-union isa split so the call resolves under --trim, as above
    if socket isa Reseau.TCP.Conn
        align_session_formats!(socket::Reseau.TCP.Conn, server_params, debug)
    else
        align_session_formats!(socket::Reseau.TLS.Conn, server_params, debug)
    end
    return socket, pid, skey, server_params
    catch
        close(socket)
        rethrow()
    end
end

# The text-format parsers only understand ISO dates and postgres-style
# intervals; against any other setting values decode into silently wrong dates
# or fail with an error that points nowhere near the cause. The server reports
# both in its startup ParameterStatus, so correct them only when they actually
# differ: a default server pays nothing, and no extra startup parameters are
# sent (poolers such as pgbouncer reject `options` unless it is allowlisted).
function align_session_formats!(socket, server_params::Dict{String, String}, debug::Bool)
    datestyle = get(server_params, "DateStyle", "")
    startswith(datestyle, "ISO") || exec(PostgresStyle(), socket, "SET DateStyle = 'ISO, MDY'", debug)
    intervalstyle = get(server_params, "IntervalStyle", "")
    (isempty(intervalstyle) || intervalstyle == "postgres") ||
        exec(PostgresStyle(), socket, "SET IntervalStyle = 'postgres'", debug)
    return
end

function prepare(socket, sql::String, debug::Bool; name::Union{Nothing, String}=nothing)
    stmtname = name === nothing ? randstring(Random.RandomDevice(), 36) : String(name)
    writemessages(socket, debug, ('P', stmtname, sql, Int16(0)), ('S',))
    waitfor(socket, debug, '1', 'Z')
    return stmtname
end

_symbol(ptr, len) = ccall(:jl_symbol_n, Ref{Symbol}, (Ptr{UInt8}, Int), ptr, len)

function describeprepared(socket, name::String, debug::Bool)
    writemessages(socket, debug, ('D', UInt8('S'), name), ('S',))
    nparams = 0
    ncols = 0
    cols = Symbol[]
    types = Int[]
    try
        mt, len = read_expected(socket, debug, 't')
        nparams = Int(ntoh(read(socket, Int16)))
        skipbytes!(socket, len - 2)
        mt, len = read_expected(socket, debug, 'T', 'n')
        if mt == UInt8('n')
            # no data
            waitfor(socket, debug, 'Z')
            return nparams, cols, types
        end
        ncols = Int(ntoh(read(socket, Int16)))
        buf = read(socket, len - 2)
        i = 1
        # each field: name (cstring), table oid (4), column number (2),
        # type oid (4), type length (2), type modifier (4), format code (2).
        # All offsets are bounds-checked against the buffer actually received:
        # a short read or a malformed RowDescription must not read past it.
        GC.@preserve buf while i <= length(buf)
            stop = findnext(isequal(UInt8(0)), buf, i)
            stop === nothing && break
            name = _symbol(pointer(buf, i), stop - i)
            i = stop + 1
            i + 17 <= length(buf) || break
            typeId = Int(ntoh(unsafe_load(Ptr{Int32}(pointer(buf, i + 6)))))
            i += 18
            push!(types, typeId)
            push!(cols, name)
        end
        waitfor(socket, debug, 'Z')
        return nparams, cols, types
    catch err
        # a deliberately-thrown Error leaves the stream at ReadyForQuery (or
        # already closed the socket); anything else means we bailed
        # mid-message and the connection must not be reused
        err isa Error || close(socket)
        rethrow()
    end
end

# One DataRow message, with its body fully read off the socket. Parsing from a
# buffer (instead of incrementally from the socket) means a failure while
# converting values — a bad cast, a user lift throwing — aborts at a message
# boundary, so the caller can drain the rest of the result and keep the
# connection usable.
struct DataRow
    buf::Vector{UInt8}
    names::Vector{Symbol}
    typeIds::Vector{Int}
    type_registry::Dict{Int, TypeInfo}
end

# (style types + behavior interface live in types.jl, included before this point)

function StructUtils.applyeach(::AbstractPostgresStyle, f, dr::DataRow)
    buf = dr.buf
    nbuf = length(buf)
    GC.@preserve buf begin
        nbuf >= 2 || throw(Error("truncated DataRow message from server"))
        ncols = Int(ntoh(unsafe_load(Ptr{Int16}(pointer(buf)))))
        # the protocol mandates one value per described column; anything else
        # (including a negative count, which is signed on the wire) would leave
        # the caller's row partly unfilled — an UndefRefError downstream
        (ncols == length(dr.names) && ncols == length(dr.typeIds)) ||
            throw(Error("DataRow column count does not match the row description"))
        pos = 3
        for i = 1:ncols
            # column lengths come off the wire: validate each against the
            # message actually received before reading the value
            pos + 3 <= nbuf || throw(Error("truncated DataRow message from server"))
            len = Int(ntoh(unsafe_load(Ptr{Int32}(pointer(buf, pos)))))
            pos += 4
            if len == -1
                # null
                f(dr.names[i], nothing)
            else
                (len >= 0 && pos + len - 1 <= nbuf) || throw(Error("truncated DataRow message from server"))
                str = unsafe_string(pointer(buf, pos), len)
                pos += len
                @inbounds applycast(f, dr.names[i], dr.typeIds[i], str, dr.type_registry)
            end
        end
    end
    return
end

struct Exec{S <: AbstractPostgresStyle}
    style::S
    socket::ReseauConn
    names::Vector{Symbol}
    typeIds::Vector{Int}
    type_registry::Dict{Int, TypeInfo}
    debug::Bool
    command_tag::Base.RefValue{Union{Nothing, String}}
    rows_affected::Base.RefValue{Union{Nothing, Int}}
end

function commandComplete(len, socket)
    buf = read(socket, len)
    isempty(buf) && return ""
    tag, _ = cstring_at(buf, 1)
    return tag
end

function rows_affected_from_command_tag(tag::String)
    isempty(tag) && return nothing
    last_token = split(tag)[end]
    try
        return parse(Int, last_token)
    catch
        return nothing
    end
end

function StructUtils.applyeach(::AbstractPostgresStyle, f, e::Exec)
    nrows = 0
    server_error = nothing
    consumer_error = nothing
    copy_in_statement = false
    copy_out_statement = false
    try
        while true
            mt, len = readheader(e.socket, e.debug)
            if mt == UInt8('E')
                # error; keep reading until ready-for-query, thrown below
                server_error = errorResponse(len, e.socket, e.debug)
            elseif mt == UInt8('Z')
                skipbytes!(e.socket, len)
                break
            elseif mt == UInt8('D')
                nrows += 1
                if consumer_error === nothing
                    row = DataRow(read(e.socket, len), e.names, e.typeIds, e.type_registry)
                    try
                        f(nrows, row)
                    catch err
                        # the consumer failed mid-result (value conversion,
                        # etc.); keep reading through ReadyForQuery so the
                        # connection stays usable, then rethrow below
                        consumer_error = err
                    end
                else
                    skipbytes!(e.socket, len)
                end
            elseif mt == UInt8('C')
                # command complete
                tag = commandComplete(len, e.socket)
                e.command_tag[] = tag
                e.rows_affected[] = rows_affected_from_command_tag(tag)
            elseif mt == UInt8('T') || mt == UInt8('n') || mt == UInt8('I') || mt == UInt8('S')
                # row description / no data / empty query response / parameter status
                skipbytes!(e.socket, len)
            elseif mt == UInt8('G')
                # CopyInResponse: the statement was a COPY ... FROM STDIN, which
                # execute doesn't support. Abort the copy with CopyFail so the
                # server returns to ready and the connection stays usable; a
                # clear client error is thrown below. A fresh Sync must follow:
                # the one sent with Bind/Execute was ignored during copy-in
                # mode, and the aborted extended-query sequence only reaches
                # ReadyForQuery once a Sync arrives after the error.
                skipbytes!(e.socket, len)
                copy_in_statement = true
                writemessages(e.socket, e.debug, ('f', "COPY FROM STDIN is not supported via execute"), ('S',))
            elseif mt == UInt8('H') || mt == UInt8('d') || mt == UInt8('c')
                # CopyOutResponse/CopyData/CopyDone: drain the copy-out stream
                # through ReadyForQuery; a clear client error is thrown below
                mt == UInt8('H') && (copy_out_statement = true)
                skipbytes!(e.socket, len)
            elseif mt == UInt8('A')
                # notification response
                notification = notificationResponse(len, e.socket)
                notification_callback(e.style, notification)
            elseif mt == UInt8('N')
                # notice response
                notice = noticeResponse(len, e.socket)
                notice_callback(e.style, notice)
            else
                throw(Error("unexpected message type '$(Char(mt))' from server; connection protocol state is corrupted"))
            end
        end
    catch
        # we bailed mid-stream (connection died, desynchronized stream, or a
        # callback threw): the stream position is unknowable, so the
        # connection must never be reused
        close(e.socket)
        # if the server sent an ErrorResponse before the connection died
        # (e.g. the backend was terminated), surface it over the raw IO error
        server_error === nothing || throw(server_error)
        rethrow()
    end
    # COPY misuse throws a clear client error; the stream was drained above,
    # so the connection stays usable. For copy-in the server error is just the
    # CopyFail artifact, so the client error wins; for copy-out a server error
    # is a genuine mid-stream failure (e.g. inside COPY (SELECT ...) TO
    # STDOUT) and is more informative than the misuse error.
    copy_in_statement && throw(PostgresInterfaceError("COPY ... FROM STDIN is not supported via execute; use Postgres.copy_from"))
    if copy_out_statement
        server_error === nothing || throw(server_error)
        throw(PostgresInterfaceError("COPY ... TO STDOUT is not supported via execute; use Postgres.copy_to"))
    end
    # server errors take precedence; otherwise surface a consumer error that
    # aborted materialization (the stream was still drained above)
    server_error === nothing || throw(server_error)
    consumer_error === nothing || throw(consumer_error)
    return
end

function exec(style::S, socket::ReseauConn, stmtname::String, params::Vector{Union{String, Missing}}, names, typeIds, type_registry::Dict{Int, TypeInfo}, debug::Bool, rowlimit::Int=0) where {S <: AbstractPostgresStyle}
    #TODO: support binary format: here and in applycast
    npformats = Int16(0) # all params use text format
    nparams = Int16(length(params))
    # bind, then execute, then sync
    writemessages(socket, debug, ('B', "", stmtname, npformats, nparams, Params(params), Int16(0)), ('E', "", Int32(rowlimit)), ('S',))
    waitfor(socket, debug, '2')
    return Exec{S}(style, socket, names, typeIds, type_registry, debug, Ref{Union{Nothing, String}}(nothing), Ref{Union{Nothing, Int}}(nothing))
end

function exec(style::S, socket::ReseauConn, query::String, debug::Bool) where {S <: AbstractPostgresStyle}
    writemessages(socket, debug, ('Q', query))
    server_error = nothing
    try
        while true
            mt, len = readheader(socket, debug)
            if mt == UInt8('E')
                # Keep draining through ReadyForQuery before surfacing the
                # server error so the connection remains reusable.
                server_error = errorResponse(len, socket, debug)
            elseif mt == UInt8('Z')
                skipbytes!(socket, len)
                break
            elseif mt == UInt8('N')
                notice_callback(style, noticeResponse(len, socket))
            elseif mt == UInt8('A')
                notification_callback(style, notificationResponse(len, socket))
            elseif mt == UInt8('C') || mt == UInt8('T') || mt == UInt8('D') ||
                   mt == UInt8('I') || mt == UInt8('S')
                # CommandComplete and any incidental simple-query result data.
                skipbytes!(socket, len)
            else
                close_and_throw(socket, Error("unexpected message type '$(Char(mt))' from server; connection protocol state is corrupted"))
            end
        end
    catch
        close(socket)
        server_error === nothing || throw(server_error)
        rethrow()
    end
    server_error === nothing || throw(server_error)
    return
end

exec(socket::ReseauConn, query::String, debug::Bool) = exec(PostgresStyle(), socket, query, debug)

function copy_in(style::S, socket, query::String, source::IO, debug::Bool) where {S <: AbstractPostgresStyle}
    writemessage(socket, debug, 'Q', query)
    error_msg = nothing
    copy_started = false
    try
        while true
            mt, len = readheader(socket, debug)
            if mt == UInt8('G')
                skipbytes!(socket, len)
                copy_started = true
                break
            elseif mt == UInt8('E')
                error_msg = errorResponse(len, socket, debug)
            elseif mt == UInt8('Z')
                # ReadyForQuery without CopyInResponse: the statement errored or
                # wasn't a COPY ... FROM STDIN; the stream is back at ready
                skipbytes!(socket, len)
                break
            elseif mt == UInt8('N')
                notice = noticeResponse(len, socket)
                notice_callback(style, notice)
            elseif mt == UInt8('A')
                notification = notificationResponse(len, socket)
                notification_callback(style, notification)
            else
                skipbytes!(socket, len)
            end
        end
    catch
        # bailed mid-stream: the position is unknowable, never reuse the socket
        close(socket)
        # if the server reported an error before the connection died, surface
        # it over the raw IO error — it explains what actually went wrong
        error_msg === nothing || throw(error_msg)
        rethrow()
    end
    error_msg === nothing || throw(error_msg)
    copy_started || throw(PostgresInterfaceError("statement did not initiate COPY ... FROM STDIN"))
    try
        buf = Vector{UInt8}(undef, 16384)
        while !eof(source)
            n = readbytes!(source, buf, length(buf))
            n == 0 && break
            writemessage(socket, debug, 'd', view(buf, 1:n))
        end
        writemessage(socket, debug, 'c')
    catch
        # the user's data source failed mid-copy: abort the copy so the
        # connection returns to ready, then rethrow the source error
        try
            writemessage(socket, debug, 'f', "client-side data source failed")
            drain_to_ready!(socket, debug)
        catch
            close(socket)
        end
        rethrow()
    end
    error_msg = nothing
    second_copy = false
    try
        while true
            mt, len = readheader(socket, debug)
            if mt == UInt8('E')
                error_msg = errorResponse(len, socket, debug)
            elseif mt == UInt8('C')
                skipbytes!(socket, len)
            elseif mt == UInt8('G')
                # a second CopyInResponse (multi-statement query string): the
                # server is waiting for more copy data, so abort with CopyFail
                # instead of deadlocking; a clear error is thrown below
                skipbytes!(socket, len)
                second_copy = true
                writemessage(socket, debug, 'f', "copy_from supports a single COPY FROM STDIN statement")
            elseif mt == UInt8('N')
                notice = noticeResponse(len, socket)
                notice_callback(style, notice)
            elseif mt == UInt8('A')
                notification = notificationResponse(len, socket)
                notification_callback(style, notification)
            elseif mt == UInt8('Z')
                skipbytes!(socket, len)
                break
            else
                skipbytes!(socket, len)
            end
        end
    catch
        # bailed mid-stream: the position is unknowable, never reuse the socket
        close(socket)
        error_msg === nothing || throw(error_msg)
        rethrow()
    end
    second_copy && throw(PostgresInterfaceError("copy_from supports a single COPY ... FROM STDIN statement per call"))
    error_msg === nothing || throw(error_msg)
    return
end

function copy_out(style::S, socket, query::String, dest::IO, debug::Bool) where {S <: AbstractPostgresStyle}
    writemessage(socket, debug, 'Q', query)
    error_msg = nothing
    copy_started = false
    wrong_direction = false
    try
        while true
            mt, len = readheader(socket, debug)
            if mt == UInt8('H')
                skipbytes!(socket, len)
                copy_started = true
            elseif mt == UInt8('d')
                write(dest, read(socket, len))
            elseif mt == UInt8('c')
                skipbytes!(socket, len)
            elseif mt == UInt8('C')
                skipbytes!(socket, len)
            elseif mt == UInt8('G')
                # CopyInResponse: the statement was COPY ... FROM STDIN. The server
                # is now waiting on us for data, so abort the copy with CopyFail to
                # return the stream to ready instead of deadlocking.
                skipbytes!(socket, len)
                wrong_direction = true
                writemessage(socket, debug, 'f', "COPY FROM STDIN is not supported via copy_to")
            elseif mt == UInt8('E')
                error_msg = errorResponse(len, socket, debug)
            elseif mt == UInt8('N')
                notice = noticeResponse(len, socket)
                notice_callback(style, notice)
            elseif mt == UInt8('A')
                notification = notificationResponse(len, socket)
                notification_callback(style, notification)
            elseif mt == UInt8('Z')
                skipbytes!(socket, len)
                break
            else
                skipbytes!(socket, len)
            end
        end
    catch
        # bailed mid-stream (socket failure, or the user's dest IO threw):
        # the position is unknowable, never reuse the socket
        close(socket)
        error_msg === nothing || throw(error_msg)
        rethrow()
    end
    wrong_direction && throw(PostgresInterfaceError("statement initiated COPY ... FROM STDIN; use Postgres.copy_from"))
    error_msg === nothing || throw(error_msg)
    copy_started || throw(PostgresInterfaceError("statement did not initiate COPY ... TO STDOUT"))
    return dest
end

function close_statement(socket, name::String, debug::Bool)
    writemessages(socket, debug, ('C', UInt8('S'), name), ('S',))
    waitfor(socket, debug, '3', 'Z')
    return
end

# The cancel key is a credential: anyone holding it can cancel that backend's
# queries for the life of the connection, so the CancelRequest goes over TLS
# whenever the connection it cancels uses TLS.
function cancel_request(host::String, port::Int, pid::Int32, skey::Int32, debug::Bool=false,
                        @nospecialize(sslmode::Union{String, Nothing}=nothing),
                        @nospecialize(sslrootcert::Union{String, Nothing}=nothing),
                        @nospecialize(sslcert::Union{String, Nothing}=nothing),
                        @nospecialize(sslkey::Union{String, Nothing}=nothing),
                        @nospecialize(sslcapath::Union{String, Nothing}=nothing),
                        @nospecialize(sslservername::Union{String, Nothing}=nothing),
                        @nospecialize(connect_timeout::Union{Int, Nothing}=nothing))
    sslmode_v = sslmode::Union{String, Nothing}
    connect_timeout_v = connect_timeout::Union{Int, Nothing}
    sslmode_str = sslmode_v === nothing ? "prefer" : lowercase(String(sslmode_v))
    tls_required = sslmode_str == "require" || sslmode_str == "verify-full"
    socket = connectsocket(host, port, connect_timeout_v)
    refused_cleartext = false
    sent = false
    try
        send_key = true
        if sslmode_str != "disable"
            writemessage(socket, debug, '\0', Int32(80877103))
            mt = read(socket, UInt8)
            if mt == UInt8('S')
                socket = tlsupgrade(socket, connect_timeout_v,
                                    sslservername isa String ? sslservername::String : host,
                                    sslmode_str == "verify-full",
                                    sslcert::Union{String, Nothing}, sslkey::Union{String, Nothing},
                                    sslrootcert::Union{String, Nothing}, sslcapath::Union{String, Nothing})
            elseif tls_required
                # never send the cancel key in the clear when TLS was required
                refused_cleartext = true
                send_key = false
            end
        end
        if send_key
            buf = IOBuffer(Vector{UInt8}(undef, 16); write=true)
            write(buf, hton(Int32(16)))
            write(buf, hton(Int32(80877102)))  # CancelRequest code
            write(buf, hton(pid))
            write(buf, hton(skey))
            write(socket, take!(buf))
            flush(socket)
            sent = true
        end
    catch
        sent = false
    finally
        close(socket)
    end
    # refusing to send is a hard failure the caller must hear about, not a
    # silent no-op: the query they asked to cancel is still running
    refused_cleartext && throw(PostgresInterfaceError("server refused TLS on the cancel connection; not sending the cancel key in cleartext under sslmode=$sslmode_str"))
    return sent
end

include("../array_parsing.jl")
using .ArrayParsing

function __init__()
    _populate_default_type_registry!()
    return nothing
end

end
