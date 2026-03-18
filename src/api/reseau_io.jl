const ReseauConn = Union{Reseau.TCP.Conn, Reseau.TLS.Conn}
const DEFAULT_BUFFER_BYTES = 16 * 1024

mutable struct BufferedConn{C <: ReseauConn} <: IO
    conn::C
    buf::Vector{UInt8}
    next::Int
    stop::Int
    open::Bool
    eof_seen::Bool
end

function BufferedConn(conn::C; buffer_bytes::Integer=DEFAULT_BUFFER_BYTES) where {C <: ReseauConn}
    buffer_bytes > 0 || throw(ArgumentError("buffer_bytes must be > 0"))
    return BufferedConn{C}(conn, Vector{UInt8}(undef, Int(buffer_bytes)), 1, 0, true, false)
end

@inline function available(io::BufferedConn)::Int
    io.next > io.stop && return 0
    return io.stop - io.next + 1
end

function fillbuffer!(io::BufferedConn)::Int
    io.eof_seen && return 0
    try
        n = readbytes!(io.conn, io.buf, length(io.buf); all=false)
        io.next = 1
        io.stop = n
        if n == 0
            io.eof_seen = true
        end
        return n
    catch err
        err isa EOFError || rethrow(err)
        io.next = 1
        io.stop = 0
        io.eof_seen = true
        return 0
    end
end

function connectbuffered(host::AbstractString, port::Integer; connect_timeout::Union{Int, Nothing}=nothing)
    address = string(host, ":", Int(port))
    conn = if connect_timeout === nothing
        Reseau.TCP.connect(address)
    else
        timeout_ns = Int64(connect_timeout) * 1_000_000_000
        Reseau.TCP.connect(address; timeout_ns)
    end
    return BufferedConn(conn)
end

function tlsupgrade(
        io::BufferedConn{<:Reseau.TCP.Conn};
        connect_timeout::Union{Int, Nothing}=nothing,
        server_name::Union{String, Nothing}=nothing,
        verify_peer::Bool=true,
        ssl_cert::Union{String, Nothing}=nothing,
        ssl_key::Union{String, Nothing}=nothing,
        ssl_cacert::Union{String, Nothing}=nothing,
        ssl_capath::Union{String, Nothing}=nothing,
    )
    ca_file = ssl_cacert === nothing ? ssl_capath : ssl_cacert
    handshake_timeout_ns = connect_timeout === nothing ? Int64(0) : Int64(connect_timeout) * 1_000_000_000
    tls_conn = Reseau.TLS.client(
        io.conn,
        Reseau.TLS.Config(
            ;
            server_name,
            verify_peer,
            cert_file=ssl_cert,
            key_file=ssl_key,
            ca_file,
            handshake_timeout_ns,
        ),
    )
    try
        Reseau.TLS.handshake!(tls_conn)
        io.open = false
        return BufferedConn(tls_conn; buffer_bytes=length(io.buf))
    catch
        close(tls_conn)
        rethrow()
    end
end

function Base.close(io::BufferedConn)
    io.open || return nothing
    io.open = false
    close(io.conn)
    return nothing
end

Base.isopen(io::BufferedConn) = io.open
Base.flush(io::BufferedConn) = nothing

function Base.eof(io::BufferedConn)::Bool
    !io.open && return true
    available(io) > 0 && return false
    io.eof_seen && return true
    return fillbuffer!(io) == 0
end

function Base.bytesavailable(io::BufferedConn)::Int
    avail = available(io)
    avail > 0 && return avail
    eof(io) && return 0
    return available(io)
end

function Base.write(io::BufferedConn, buf::StridedVector{UInt8})::Int
    io.open || throw(EOFError())
    return write(io.conn, buf)
end

function Base.write(io::BufferedConn, b::UInt8)::Int
    io.open || throw(EOFError())
    return write(io.conn, UInt8[b])
end

function Base.unsafe_write(io::BufferedConn, ptr::Ptr{UInt8}, nbytes::UInt)
    io.open || throw(EOFError())
    n = Int(nbytes)
    n == 0 && return 0
    return GC.@preserve ptr begin
        bytes = unsafe_wrap(Vector{UInt8}, ptr, n)
        write(io.conn, bytes)
    end
end

function Base.read(io::BufferedConn, ::Type{UInt8})::UInt8
    eof(io) && throw(EOFError())
    b = @inbounds io.buf[io.next]
    io.next += 1
    return b
end

function Base.readbytes!(io::BufferedConn, dst::Vector{UInt8}, nb::Integer=length(dst))::Int
    target = min(Int(nb), length(dst))
    target <= 0 && return 0
    total = 0
    while total < target
        avail = available(io)
        if avail == 0
            fillbuffer!(io) == 0 && break
            avail = available(io)
        end
        chunk = min(avail, target - total)
        copyto!(dst, total + 1, io.buf, io.next, chunk)
        io.next += chunk
        total += chunk
    end
    return total
end

function Base.unsafe_read(io::BufferedConn, ptr::Ptr{UInt8}, nbytes::UInt)
    remaining = Int(nbytes)
    offset = 0
    buf = io.buf
    while remaining > 0
        avail = available(io)
        if avail == 0
            fillbuffer!(io) == 0 && throw(EOFError())
            avail = available(io)
        end
        chunk = min(avail, remaining)
        GC.@preserve buf begin
            unsafe_copyto!(ptr + offset, pointer(buf, io.next), chunk)
        end
        io.next += chunk
        offset += chunk
        remaining -= chunk
    end
    return nothing
end

function Base.skip(io::BufferedConn, n::Integer)
    remaining = Int(n)
    remaining < 0 && throw(ArgumentError("cannot skip a negative number of bytes"))
    while remaining > 0
        avail = available(io)
        if avail == 0
            fillbuffer!(io) == 0 && throw(EOFError())
            avail = available(io)
        end
        chunk = min(avail, remaining)
        io.next += chunk
        remaining -= chunk
    end
    return io
end
