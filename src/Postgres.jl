module Postgres

using DBInterface, Dates, UUIDs, Parsers, Tables, StructUtils, JSONBase

export DBInterface

# For non-api errors that happen in Posgres.jl
struct PosgresInterfaceError
    msg::String
end
Base.showerror(io::IO, e::PosgresInterfaceError) = print(io, e.msg)

include("api/API.jl")
using .API

# T parameter is always Statement
mutable struct Connection{IO, T} <: DBInterface.Connection
    const lock::ReentrantLock
    socket::IO
    const host::String
    const user::String
    const password::Union{String, Nothing}
    const dbname::String
    const port::Int
    # pid/skey are used to send cancellation request to backend
    pid::Int32
    skey::Int32
    const statements::Dict{String, T} # sql string -> Statement
    closed::Bool # if explicitly closed by user; guarded by lock
    debug::Bool

    function Connection(host::AbstractString, user::AbstractString, password::Union{AbstractString, Nothing}, dbname::AbstractString, port::Integer, debug::Bool)
        host = String(host)
        user = String(user)
        dbname = String(dbname)
        port = Int(port)
        password = password === nothing ? nothing : String(password)
        #TODO: if values have spaces, need to single-quote them
        # also need to escape single quotes/backslahes then with backslashes
        socket, pid, skey = API.connect(host, port, dbname, user, password, debug)
        return new{typeof(socket), Statement}(ReentrantLock(), socket, host, user, password, dbname, port, pid, skey, Dict{String, Statement}(), false, debug)
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
    return
end

disconnected() = throw(PosgresInterfaceError("postgres connection has been closed or disconnected"))

function checkconn(conn::Connection)
    Base.assert_havelock(conn.lock)
    if !isopen(conn.socket) && !conn.closed
        # connection is closed, but not explicitly, reconnect
        conn.socket, conn.pid, conn.skey = API.connect(conn.host, conn.port, conn.dbname, conn.user, conn.password, conn.debug)
        empty!(conn.statements)
        @warn "postgres connection was closed; reconnected"
    end
    isopen(conn.socket) || disconnected()
    return
end

#TODO: docstring
DBInterface.connect(::Type{Connection}, host::AbstractString, user::AbstractString, passwd::Union{AbstractString, Nothing}; dbname::AbstractString="", port::Integer=5432, debug::Bool=false, kw...) =
    Connection(host, user, passwd, dbname, port, debug; kw...)

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

include("execute.jl")

# escape(conn::Connection, s::AbstractString) = API.escape(conn.pg, s)

end