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
                c.table_name = '$table' AND c.table_schema = '$schema'
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
    """))
end

end