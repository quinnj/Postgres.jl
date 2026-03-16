module API

using UUIDs, Dates, Reseau, SASLAuth, MD5, Parsers, StructUtils, Logging, JSON, Random
include("reseau_io.jl")

export PostgresStyle, Error, Notification, Numeric, PostgresRange

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

# error code => (name, should_be_shown)
const ERROR_CODE = Dict{Char, Tuple{String, Bool}}(
    'S' => ("Severity", true),
    'V' => ("Severity", false),
    'C' => ("Code", false),
    'M' => ("Message", true),
    'D' => ("Detail", true),
    'H' => ("Hint", true),
    'P' => ("Position", false),
    'p' => ("Internal Position", false),
    'q' => ("Internal Query", false),
    'W' => ("Where", true),
    's' => ("Schema Name", true),
    't' => ("Table Name", true),
    'c' => ("Column Name", true),
    'd' => ("Data Type Name", true),
    'n' => ("Constraint Name", true),
    'F' => ("File", false),
    'L' => ("Line", false),
    'R' => ("Routine", false),
)

function errorResponse(len, socket, debug)
    buf = read(socket, len)
    # parse error fields
    i = 1
    severity = ""
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
    while i < len
        ccode = Char(buf[i])
        i += 1
        val = unsafe_string(pointer(buf, i))
        i += sizeof(val) + 1
        if ccode == 'S'
            severity = val
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
    err = Error(severity, code, message, detail, hint, position, internal_position, internal_query, where, schema, table, column, datatype, constraint, file, line, routine)
    debug && @error err
    return err
end

function noticeResponse(len, socket)
    buf = read(socket, len)
    i = 1
    notice = Dict{String, String}()
    while i < length(buf)
        ccode = Char(buf[i])
        i += 1
        val = unsafe_string(pointer(buf, i))
        i += sizeof(val) + 1
        notice[string(ccode)] = val
    end
    return notice
end

function notificationResponse(len, socket)
    pid = ntoh(read(socket, Int32))
    buf = read(socket, len - 4)
    i = 1
    channel = ""
    payload = ""
    if !isempty(buf)
        channel = unsafe_string(pointer(buf, i))
        i += sizeof(channel) + 1
        i <= length(buf) && (payload = unsafe_string(pointer(buf, i)))
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

function writemessage(socket, debug, code::Char, parts...)
    debug && @info "sending message: $code, $parts"
    len = Int32(4 + sum(msgsizeof(x) for x in parts; init=0))
    buf = IOBuffer(Vector{UInt8}(undef, len + 1); write=true)
    code != '\0' && write(buf, UInt8(code))
    write(buf, hton(len))
    for part in parts
        writepart(buf, part)
    end
    write(socket, take!(buf))
    flush(socket)
    return
end

function writemessages(socket, debug, msgs...)
    buf = IOBuffer()
    for (code, parts...) in msgs
        debug && @info "sending message: $code, $parts"
        len = Int32(4 + sum(msgsizeof(x) for x in parts; init=0))
        code != '\0' && write(buf, UInt8(code))
        write(buf, hton(len))
        for part in parts
            writepart(buf, part)
        end
    end
    write(socket, take!(buf))
    flush(socket)
    return
end

function readheader(socket, debug=false)
    mt = read(socket, UInt8)
    len = ntoh(read(socket, Int32)) - 4
    debug && @info "readheader: $(Char(mt)), $len"
    return mt, len
end

# wait for code, then ready
function waitfor(socket, debug, codes...)
    error = false
    error_msg = nothing
    found = sum(UInt8, codes)
    pid = skey = Int32(0)
    server_params = Dict{String, String}()
    debug && @info "waitfor: $codes"
    while true
        mt, len = readheader(socket, debug)
        if mt == UInt8('E')
            # error
            error = true
            error_msg = errorResponse(len, socket, debug)
        elseif error && mt == UInt8('Z')
            # error followed by ready
            skip(socket, len)
            break
        elseif mt == UInt8('S')
            # parameter status
            buf = read(socket, len)
            i = 1
            while i < len
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
        elseif Char(mt) in codes
            # found
            found -= mt
            if mt == UInt8('K')
                pid = ntoh(read(socket, Int32))
                skey = ntoh(read(socket, Int32))
            else
                skip(socket, len)
            end
            found == 0 && break
        else
            # read off message
            skip(socket, len)
        end
    end
    error_msg === nothing && error && throw(Error("unexpected error response"))
    error && throw(error_msg)
    return pid, skey, server_params
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
        writemessage(socket, debug, 'p', password)
        mt, len = readheader(socket, debug)
        if mt == UInt8('E')
            # error
            close(socket)
            throw(errorResponse(len, socket, debug))
        elseif mt == UInt8('R')
            auth_code = ntoh(read(socket, Int32))
            if auth_code == 0
                # authentication ok
                return socket
            else
                close(socket)
                throw(Error("cleartext password authentication failed: $auth_code"))
            end
        else
            close(socket)
            throw(Error("unexpected message type: $(Char(mt))"))
        end
    elseif auth_code == 5
        # md5 salt
        salt = read(socket, 4)
        debug && @info "md5 salt: $salt"
        # concat('md5', md5(concat(md5(concat(password, username)), random-salt)))
        # Calculate the MD5 password
        pass = string("md5", bytes2hex(md5(vcat(Vector{UInt8}(bytes2hex(md5(string(password, user)))), salt))))
        # Send password message
        writemessage(socket, debug, 'p', pass)
        mt, len = readheader(socket, debug)
        if mt == UInt8('E')
            # error
            close(socket)
            throw(errorResponse(len, socket, debug))
        elseif mt == UInt8('R')
            auth_code = ntoh(read(socket, Int32))
            if auth_code == 0
                # authentication ok
                return socket
            else
                close(socket)
                throw(Error("MD5 password authentication failed: $auth_code"))
            end
        else
            close(socket)
            throw(Error("unexpected message type: $(Char(mt))"))
        end
    elseif auth_code == 7
        # GSSAPI

    elseif auth_code == 8
        # Specifies that this message contains GSSAPI or SSPI data.

    elseif auth_code == 9
        # Specifies that SSPI authentication is required.

    elseif auth_code == 10
        # SASL Authentication Required
        data = String(read(socket, len - 4))
        mechanisms = split(data, '\0'; keepempty=false)

        if "SCRAM-SHA-256" ∉ mechanisms
            close(socket)
            throw(Error("no supported SASL mechanisms: $mechanisms"))
        end
        client = SASLAuth.SCRAMSHA256Client(user, password)
        msg, _ = SASLAuth.step!(client, nothing)
        bytes = Vector{UInt8}(msg)
        writemessage(socket, debug, 'p', "SCRAM-SHA-256", Int32(length(bytes)), bytes)
        mt, len = readheader(socket, debug)
        @assert mt == UInt8('R')
        return authRequest(debug, len, socket, user, password, client)
    elseif auth_code == 11
        # SASL Challenge
        challenge = String(read(socket, len - 4))
        msg, _ = SASLAuth.step!(client, challenge)
        writemessage(socket, debug, 'p', Vector{UInt8}(msg))
        mt, len = readheader(socket, debug)
        @assert mt == UInt8('R')
        return authRequest(debug, len, socket, user, password, client)
    elseif auth_code == 12
        # SASL Final Message
        final_msg = String(read(socket, len - 4))
        _, done = SASLAuth.step!(client, final_msg)
        @assert done
        mt, len = readheader(socket, debug)
        @assert mt == UInt8('R')
        @assert ntoh(read(socket, Int32)) == 0
        return socket
    else
        close(socket)
        throw(Error("unknown authentication code: $auth_code"))
    end
end

function connect(host::String, port::Integer, dbname::String, user::String, password::Union{String, Nothing}, debug::Bool, application_name::Union{String, Nothing}, connect_timeout::Union{Int, Nothing}, sslmode::Union{String, Nothing}, sslrootcert::Union{String, Nothing}, sslcert::Union{String, Nothing}, sslkey::Union{String, Nothing}, sslcapath::Union{String, Nothing}, statement_timeout::Union{Int, Nothing})
    socket = connectbuffered(host, port; connect_timeout)
    sslmode_str = sslmode === nothing ? "prefer" : lowercase(String(sslmode))
    sslmode_str == "disable" || sslmode_str == "prefer" || sslmode_str == "require" || sslmode_str == "verify-full" || throw(Error("invalid sslmode: $sslmode_str"))
    if sslmode_str != "disable"
        # send SSLRequest
        writemessage(socket, debug, '\0', Int32(80877103))
        mt = read(socket, UInt8)
        if mt == UInt8('S')
            # upgrade socket to tls and do handshake
            socket = tlsupgrade(
                socket;
                connect_timeout,
                server_name=host,
                verify_peer=sslmode_str == "verify-full",
                ssl_cert=sslcert,
                ssl_key=sslkey,
                ssl_cacert=sslrootcert,
                ssl_capath=sslcapath,
            )
        elseif mt == UInt8('N')
            (sslmode_str == "require" || sslmode_str == "verify-full") && throw(Error("server does not support SSL"))
        else
            @assert mt == UInt8('N') "unexpected message type: $(Char(mt))"
        end
    end
    # Build startup parameters
    params = [("user", user), ("database", dbname)]
    if !isnothing(application_name)
        push!(params, ("application_name", application_name))
    end
    if !isnothing(statement_timeout)
        push!(params, ("options", "-c statement_timeout=$(statement_timeout)"))
    end
    writemessage(socket, debug, '\0', Int32(196608), params..., UInt8(0))
    # read initial response
    mt, len = readheader(socket, debug)
    if mt == UInt8('E')
        # error
        close(socket)
        throw(errorResponse(len, socket, debug))
    elseif mt == UInt8('R')
        authRequest(debug, len, socket, user, password)
    elseif mt == UInt8('v')
        # server version too old
        close(socket)
        throw(Error("server version too old"))
    end
    pid, skey, server_params = waitfor(socket, debug, 'K', 'Z')
    return socket, pid, skey, server_params
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
    mt, len = readheader(socket)
    @assert mt == UInt8('t') "unexpected message type: $(Char(mt))"
    nparams = Int(ntoh(read(socket, Int16)))
    skip(socket, len - 2)
    mt, len = readheader(socket)
    if mt == UInt8('n')
        # no data
        waitfor(socket, debug, 'Z')
        return nparams, cols, types
    end
    @assert mt == UInt8('T') "unexpected message type: $(Char(mt))"
    ncols = Int(ntoh(read(socket, Int16)))
    buf = read(socket, len - 2)
    i = 1
    while i < len - 2
        ptr = pointer(buf, i)
        plen = Int(@ccall strlen(ptr::Ptr{Cvoid})::Csize_t)
        name = _symbol(ptr, plen)
        i += plen + 1
        i += 4 # skip table oid
        i += 2 # skip column number
        typeId = Int(ntoh(unsafe_load(Ptr{Int32}(pointer(buf, i)))))
        push!(types, typeId)
        i += 4
        i += 2 # skip type length
        # typeModifier = Int(ntoh(unsafe_load(Ptr{Int32}(pointer(buf, i)))))
        i += 4
        i += 2 # skip format code
        push!(cols, name)
    end
    waitfor(socket, debug, 'Z')
    return nparams, cols, types
end

struct DataRow
    socket::IO
    names::Vector{Symbol}
    typeIds::Vector{Int}
    type_registry::Dict{Int, TypeInfo}
end

struct PostgresStyle <: StructUtils.StructStyle end

StructUtils.fieldtagkey(::PostgresStyle) = :postgres
StructUtils.structlike(::PostgresStyle, ::Type{<:Number}) = false
StructUtils.structlike(::PostgresStyle, ::Type{<:JSON.LazyValue}) = false
StructUtils.lift(::PostgresStyle, ::Type{T}, x::T) where {T<:JSON.LazyValue} = x, nothing
StructUtils.lift(::PostgresStyle, ::Type{T}, x::T, tags) where {T<:JSON.LazyValue} = x, nothing

function StructUtils.applyeach(::PostgresStyle, f, dr::DataRow)
    ncols = Int(ntoh(read(dr.socket, Int16)))
    for i = 1:ncols
        len = Int(ntoh(read(dr.socket, Int32)))
        if len == -1
            # null
            f(dr.names[i], nothing)
        else
            #TODO: reuse a large buffer for reading values into then parse from
            str = Base._string_n(len)
            unsafe_read(dr.socket, pointer(str), len)
            @inbounds applycast(f, dr.names[i], dr.typeIds[i], str, dr.type_registry)
        end
    end
    return
end

struct Exec
    socket::IO
    names::Vector{Symbol}
    typeIds::Vector{Int}
    type_registry::Dict{Int, TypeInfo}
    debug::Bool
    notice_callback::Function
    notification_callback::Function
end

function StructUtils.applyeach(::PostgresStyle, f, e::Exec)
    nrows = 0
    error = false
    error_msg = nothing
    while true
        mt, len = readheader(e.socket)
        if mt == UInt8('E')
            # error
            error = true
            error_msg = errorResponse(len, e.socket, e.debug)
        elseif error && mt == UInt8('Z')
            # error followed by ready
            skip(e.socket, len)
            error_msg === nothing && throw(Error("unexpected error response"))
            throw(error_msg)
        elseif mt == UInt8('T')
            # row description
            skip(e.socket, len)
        elseif mt == UInt8('n')
            # no data
            skip(e.socket, len)
        elseif mt == UInt8('I')
            # empty query response
            skip(e.socket, len)
        elseif mt == UInt8('S')
            # parameter status
            skip(e.socket, len)
        elseif mt == UInt8('A')
            # notification response
            notification = notificationResponse(len, e.socket)
            e.notification_callback(notification)
        elseif mt == UInt8('D')
            nrows += 1
            f(nrows, DataRow(e.socket, e.names, e.typeIds, e.type_registry))
        elseif mt == UInt8('C')
            # command complete
            #TODO: should we read the rows affected here and store them in Exec or something?
            skip(e.socket, len)
        elseif mt == UInt8('Z')
            skip(e.socket, len)
            break
        elseif mt == UInt8('N')
            # notice response
            notice = noticeResponse(len, e.socket)
            e.notice_callback(notice)
        else
            close(e.socket)
            throw(Error("unexpected message type: $(Char(mt))"))
        end
    end
    return
end

function exec(socket, stmtname::String, params::Vector{Union{String, Missing}}, names, typeIds, type_registry::Dict{Int, TypeInfo}, debug::Bool, rowlimit::Int=0, notice_callback::Function=(notice)->nothing, notification_callback::Function=(notification)->nothing)
    #TODO: support binary format: here and in applycast
    npformats = Int16(0) # all params use text format
    nparams = Int16(length(params))
    # bind, then execute, then sync
    writemessages(socket, debug, ('B', "", stmtname, npformats, nparams, Params(params), Int16(0)), ('E', "", Int32(rowlimit)), ('S',))
    waitfor(socket, debug, '2')
    return Exec(socket, names, typeIds, type_registry, debug, notice_callback, notification_callback)
end

function exec(socket, query::String, debug::Bool)
    writemessages(socket, debug, ('Q', query))
    waitfor(socket, debug, 'Z')
    #TODO: handle all the various response message types, like applyeach above + describeprepared
    return
end

function copy_in(socket, query::String, source::IO, debug::Bool, notice_callback::Function, notification_callback::Function)
    writemessage(socket, debug, 'Q', query)
    error_msg = nothing
    while true
        mt, len = readheader(socket, debug)
        if mt == UInt8('G')
            skip(socket, len)
            break
        elseif mt == UInt8('E')
            error_msg = errorResponse(len, socket, debug)
        elseif mt == UInt8('N')
            notice = noticeResponse(len, socket)
            notice_callback(notice)
        elseif mt == UInt8('A')
            notification = notificationResponse(len, socket)
            notification_callback(notification)
        else
            skip(socket, len)
        end
    end
    error_msg === nothing || throw(error_msg)
    buf = Vector{UInt8}(undef, 16384)
    while !eof(source)
        n = readbytes!(source, buf, length(buf))
        n == 0 && break
        writemessage(socket, debug, 'd', view(buf, 1:n))
    end
    writemessage(socket, debug, 'c')
    error_msg = nothing
    while true
        mt, len = readheader(socket, debug)
        if mt == UInt8('E')
            error_msg = errorResponse(len, socket, debug)
        elseif mt == UInt8('C')
            skip(socket, len)
        elseif mt == UInt8('N')
            notice = noticeResponse(len, socket)
            notice_callback(notice)
        elseif mt == UInt8('A')
            notification = notificationResponse(len, socket)
            notification_callback(notification)
        elseif mt == UInt8('Z')
            skip(socket, len)
            break
        else
            skip(socket, len)
        end
    end
    error_msg === nothing || throw(error_msg)
    return
end

function copy_out(socket, query::String, dest::IO, debug::Bool, notice_callback::Function, notification_callback::Function)
    writemessage(socket, debug, 'Q', query)
    error_msg = nothing
    while true
        mt, len = readheader(socket, debug)
        if mt == UInt8('H')
            skip(socket, len)
        elseif mt == UInt8('d')
            write(dest, read(socket, len))
        elseif mt == UInt8('c')
            skip(socket, len)
        elseif mt == UInt8('C')
            skip(socket, len)
        elseif mt == UInt8('E')
            error_msg = errorResponse(len, socket, debug)
        elseif mt == UInt8('N')
            notice = noticeResponse(len, socket)
            notice_callback(notice)
        elseif mt == UInt8('A')
            notification = notificationResponse(len, socket)
            notification_callback(notification)
        elseif mt == UInt8('Z')
            skip(socket, len)
            break
        else
            skip(socket, len)
        end
    end
    error_msg === nothing || throw(error_msg)
    return dest
end

function close_statement(socket, name::String, debug::Bool)
    writemessages(socket, debug, ('C', UInt8('S'), name), ('S',))
    waitfor(socket, debug, '3', 'Z')
    return
end

function cancel_request(host::String, port::Int, pid::Int32, skey::Int32, debug::Bool=false)
    socket = connectbuffered(host, port)
    try
        buf = IOBuffer(Vector{UInt8}(undef, 16); write=true)
        write(buf, hton(Int32(16)))
        write(buf, hton(Int32(80877102)))  # CancelRequest code
        write(buf, hton(pid))
        write(buf, hton(skey))
        write(socket, take!(buf))
        flush(socket)
        return true
    catch
        return false
    finally
        close(socket)
    end
end

export cancel_request

# function escape(conn::PGconn, s::AbstractString)
#     str = C.PQescapeLiteral(ptr, s, sizeof(s))
#     escaped = unsafe_string(str)
#     C.PQfreemem(str)
#     return escaped
# end

include("../array_parsing.jl")
using .ArrayParsing

end
