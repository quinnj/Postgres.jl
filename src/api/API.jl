module API

using UUIDs, Dates, AwsIO, Base64, SHA, MD5, Parsers, StructUtils, Logging, JSONBase, Random

export PostgresStyle

struct Error <: Exception
    msg::String
end
Base.showerror(io::IO, e::Error) = print(io, e.msg)

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
    msg = "Postgres.Error:\n"
    while i < length(buf)
        code = Char(buf[i])
        i += 1
        val = unsafe_string(pointer(buf, i))
        i += sizeof(val) + 1
        if haskey(ERROR_CODE, code)
            name, show = ERROR_CODE[code]
            show && (msg *= "    $name: $val\n")
        end
    end
    debug && @error msg
    return msg
end

function pbkdf2(pwd, salt, iter)
    ctx = HMAC_CTX(SHA2_256_CTX(), Vector{UInt8}(pwd))
    update!(ctx, salt)
    update!(ctx, b"\x00\x00\x00\x01")
    U = digest!(ctx)
    T = copy(U)
    for _ = 2:iter
        U = hmac_sha256(pwd, U)
        for i = 1:length(U)
            @inbounds T[i] = xor(U[i], T[i])
        end
    end
    return T
end

struct Params
    params::Vector{Union{String, Missing}}
end

msgsizeof(x::String) = sizeof(x) + 1
msgsizeof(x::Vector{UInt8}) = sizeof(x)
msgsizeof(x) = sizeof(x)
msgsizeof(x::Params) = sum(4 + (ismissing(p) ? 0 : sizeof(p)) for p in x.params; init=0)

writepart(io, x) = write(io, x)
function writepart(io, x::String)
    write(io, x)
    write(io, UInt8(0))
end
writepart(io, x::Integer) = write(io, hton(x))
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
    error_msg = ""
    found = sum(UInt8, codes)
    pid = skey = Int32(0)
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
    error && throw(Error(error_msg))
    return pid, skey
end

function authRequest(debug, len, socket, user, password, nonce=nothing)
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
            throw(Error(errorResponse(len, socket, debug)))
        elseif mt == UInt8('R')
            auth_code = read(socket, Int32)
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
            throw(Error(errorResponse(len, socket, debug)))
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
        # Specifies that SASL authentication is required.
        data = String(read(socket, len - 4))
        mechanisms = split(data, '\0'; keepempty=false)
        if "SCRAM-SHA-256" in mechanisms
            # send SASLInitialResponse
            nonce = String(rand(UInt8('a'):UInt8('z'), 18))
            msg = codeunits("n,,n=$user,r=$nonce")
            writemessage(socket, debug, 'p', "SCRAM-SHA-256", Int32(sizeof(msg)), msg)
            mt, len = readheader(socket, debug)
            @assert mt == UInt8('R')
            return authRequest(debug, len, socket, user, password, nonce)
        else
            close(socket)
            throw(Error("no supported SASL mechanisms: $mechanisms"))
        end
    elseif auth_code == 11
        # Specifies that this message contains a SASL challenge.
        rawchallenge = String(read(socket, len - 4))
        challenge = split(rawchallenge, ',')
        salt = base64decode(split(challenge[2], '='; limit=2)[2])
        itercount = parse(Int, split(challenge[3], '='; limit=2)[2])
        saltedPassword = pbkdf2(Vector{UInt8}(password), salt, itercount)
        clientKey = SHA.hmac_sha256(saltedPassword, "Client Key")
        storedKey = SHA.sha256(clientKey)
        # Example values; replace with actual messages exchanged with the server
        clientFirstMessageBare = "n=$user,r=$nonce"
        clientFinalMessageWithoutProof = "c=biws,$(challenge[1])"
        authMessage = clientFirstMessageBare * "," * rawchallenge * "," * clientFinalMessageWithoutProof
        clientSignature = SHA.hmac_sha256(storedKey, authMessage)
        # ClientProof = ClientKey XOR ClientSignature
        clientproof = base64encode(xor.(clientKey, clientSignature))
        msg = codeunits("c=biws,$(challenge[1]),p=$clientproof")
        writemessage(socket, debug, 'p', msg)
        mt, len = readheader(socket, debug)
        if mt == UInt8('E')
            # error
            close(socket)
            throw(Error(errorResponse(len, socket, debug)))
        end
        @assert mt == UInt8('R') "unexpected message type: $(Char(mt))"
        return authRequest(debug, len, socket, user, password)
    elseif auth_code == 12
        # Specifies that SASL authentication has completed.
        data = String(read(socket, len - 4))
        #TODO: validate server signature
        mt, len = readheader(socket, debug)
        @assert mt == UInt8('R')
        @assert read(socket, Int32) == 0
        return socket
    else
        close(socket)
        throw(Error("unknown authentication code: $auth_code"))
    end
end

function connect(host::String, port::Integer, dbname::String, user::String, password::Union{String, Nothing}, debug::Bool)
    socket = AwsIO.Sockets.Client(host, port)
    # send SSLRequest
    writemessage(socket, debug, '\0', Int32(80877103))
    mt = read(socket, UInt8)
    if mt == UInt8('S')
        # upgrade socket to tls and do handshake
        AwsIO.tlsupgrade!(socket)
    else
        @assert mt == UInt8('N') "unexpected message type: $(Char(mt))"
    end
    writemessage(socket, debug, '\0', Int32(196608), "user", user, "database", dbname, UInt8(0))
    # read initial response
    mt, len = readheader(socket, debug)
    if mt == UInt8('E')
        # error
        close(socket)
        throw(Error(errorResponse(len, socket, debug)))
    elseif mt == UInt8('R')
        authRequest(debug, len, socket, user, password)
    elseif mt == UInt8('v')
        # server version too old
        close(socket)
        throw(Error("server version too old"))
    end
    pid, skey = waitfor(socket, debug, 'K', 'Z')
    return socket, pid, skey
end

function prepare(socket, sql::String, debug::Bool)
    name = randstring(Random.RandomDevice(), 36)
    writemessages(socket, debug, ('P', name, sql, Int16(0)), ('S',))
    waitfor(socket, debug, '1', 'Z')
    return name
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
        return nparams, cols, types
    end
    @assert mt == UInt8('T') "unexpected message type: $(Char(mt))"
    ncols = Int(ntoh(read(socket, Int16)))
    buf = read(socket, len - 2)
    i = 1
    while i < len - 2
        ptr = pointer(buf, i)
        plen = @ccall strlen(ptr::Ptr{Cvoid})::Csize_t
        name = _symbol(ptr, plen)
        i += sizeof(name) + 1
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
    return nparams, cols, types
end

struct DataRow
    socket::AwsIO.Sockets.Client
    names::Vector{Symbol}
    typeIds::Vector{Int}
end

struct PostgresStyle <: StructUtils.StructStyle end

StructUtils.fieldtagkey(::Type{PostgresStyle}) = :postgres

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
            @inbounds applycast(f, dr.names[i], dr.typeIds[i], str)
        end
    end
    return
end

struct Exec
    socket::AwsIO.Sockets.Client
    names::Vector{Symbol}
    typeIds::Vector{Int}
    debug::Bool
end

function StructUtils.applyeach(::PostgresStyle, f, e::Exec)
    nrows = 0
    error = false
    error_msg = ""
    while true
        mt, len = readheader(e.socket)
        if mt == UInt8('E')
            # error
            error = true
            error_msg = errorResponse(len, e.socket, e.debug)
        elseif error && mt == UInt8('Z')
            # error followed by ready
            skip(e.socket, len)
            throw(Error(error_msg))
        elseif mt == UInt8('D')
            nrows += 1
            f(nrows, DataRow(e.socket, e.names, e.typeIds))
        elseif mt == UInt8('C')
            # command complete
            #TODO: should we read the rows affected here and store them in Exec or something?
            skip(e.socket, len)
        elseif mt == UInt8('Z')
            skip(e.socket, len)
            break
        elseif mt == UInt8('N')
            # notice response
            buf = read(e.socket, len)
            # parse notice fields
            i = 1
            msg = ""
            while i < length(buf)
                code = Char(buf[i])
                i += 1
                val = unsafe_string(pointer(buf, i))
                i += sizeof(val) + 1
                if code == 'M'
                    msg = val
                    break
                end
            end
            @warn msg
        else
            close(e.socket)
            throw(Error("unexpected message type: $(Char(mt))"))
        end
    end
    return
end

function exec(socket, stmtname::String, params::Vector{Union{String, Missing}}, names, typeIds, debug::Bool, rowlimit::Int=0)
    #TODO: support binary format: here and in applycast
    npformats = Int16(0) # all params use text format
    nparams = Int16(length(params))
    # bind, then execute, then sync
    writemessages(socket, debug, ('B', "", stmtname, npformats, nparams, Params(params), Int16(0)), ('E', "", Int32(rowlimit)), ('S',))
    waitfor(socket, debug, '2')
    return Exec(socket, names, typeIds, debug)
end

function exec(socket, query::String, debug::Bool)
    writemessages(socket, debug, ('Q', query))
    waitfor(socket, debug, 'Z')
    #TODO: handle all the various response message types, like applyeach above + describeprepared
    return
end

# function escape(conn::PGconn, s::AbstractString)
#     str = C.PQescapeLiteral(ptr, s, sizeof(s))
#     escaped = unsafe_string(str)
#     C.PQfreemem(str)
#     return escaped
# end

include("types.jl")

end