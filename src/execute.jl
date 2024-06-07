struct ResultRow <: Tables.AbstractRow
    data::Vector{Any}
    names::Vector{Symbol}
    types::Vector{Type}
    lookup::Dict{Symbol, Int}
    rownumber::Int
end

struct Result <: AbstractVector{ResultRow}
    names::Vector{Symbol}
    types::Vector{Type}
    rows::Vector{ResultRow}
end

Base.size(r::Result) = (length(r.rows),)
Base.getindex(r::Result, i::Integer) = r.rows[i]

getdata(r::ResultRow) = getfield(r, :data)
getnames(r::ResultRow) = getfield(r, :names)
gettypes(r::ResultRow) = getfield(r, :types)
getlookup(r::ResultRow) = getfield(r, :lookup)
getrownumber(r::ResultRow) = getfield(r, :rownumber)

Tables.columnnames(r::ResultRow) = getnames(r)

function Tables.getcolumn(r::ResultRow, ::Type{T}, i::Int, nm::Symbol) where {T}
    return getdata(r)[i]
end

Tables.getcolumn(r::ResultRow, i::Int) = Tables.getcolumn(r, gettypes(r)[i], i, getnames(r)[i])
Tables.getcolumn(r::ResultRow, nm::Symbol) = Tables.getcolumn(r, getlookup(r)[nm])

Tables.schema(r::Result) = Tables.Schema(r.names, r.types)

# DBInterface.lastrowid(result::Result) = API.lastrowid(result.result)

DBInterface.close!(result::Result) = close(result.result)

mutable struct Statement <: DBInterface.Statement
    const conn::Connection
    name::String
    const sql::String
    const nfields::Int
    const names::Vector{Symbol}
    const typeIds::Vector{Int}
    const nparams::Int
    # holds references to params as strings
    const params::Vector{Union{String, Missing}} 
end

function Base.show(io::IO, stmt::Statement)
    println(io, "Postgres.Statement:")
    print(io, stmt.sql)
end

function checkstmt(stmt::Statement)
    checkconn(stmt.conn)
    if !haskey(stmt.conn.statements, stmt.sql)
        # if the connection was reset, we need to re-prepare the statement
        stmt.name = API.prepare(stmt.conn.socket, stmt.sql)
        stmt.conn.statements[stmt.sql] = stmt
    end
    return
end

function DBInterface.prepare(conn::Connection, sql::AbstractString; debug::Bool=false)
    sql_str = String(sql)
    @lock conn.lock begin
        checkconn(conn)
        # check if we've already prepared this sql before
        haskey(conn.statements, sql_str) && return conn.statements[sql_str]
        # new statement to prepare
        name = API.prepare(conn.socket, sql_str, debug)
        nparams, names, types = API.describeprepared(conn.socket, name, debug)
        params = Union{String, Missing}[missing for _ = 1:nparams]
        stmt = Statement(conn, name, sql_str, length(names), names, types, nparams, params)
        conn.statements[sql_str] = stmt
        return stmt
    end
end

_param(x::AbstractString) = String(x)
_param(x) = string(x)
_param(x::Missing) = x
_param(::Nothing) = missing
# convert to postgres array literal syntax: { x, y, z }
# strings must be double-quoted and double quotes and backslashes escaped
# missing values are NULL
_aparam(x::AbstractString) = string("\"", replace(x, r"([\"\\])" => "\\1"), "\"")
_aparam(::Missing) = "NULL"
_aparam(::Nothing) = "NULL"
_aparam(x) = _param(x)
_param(x::AbstractVector) = string("{", join([_aparam(y) for y in x], ", "), "}")

@noinline param_mismatch(sql, nparams, n) = throw(PosgresInterfaceError("number of parameters provided ($n) does not match number of placeholders ($nparams) in sql: $sql"))

mutable struct RowClosure
    data::Vector{Any}
    types::Vector{Type}
    i::Int
end

@inline function (f::RowClosure)(k, v)
    if v === nothing
        # translate nothing -> missing for Tables.jl
        @inbounds f.types[f.i] = Union{f.types[f.i], Missing}
        @inbounds f.data[f.i] = missing
    else
        @inbounds f.data[f.i] = v
    end
    f.i += 1
    return
end

function makeresult(e::API.Exec)
    names, typeIds = e.names, e.typeIds
    types = Type[API.juliatype(x -> x, i) for i in typeIds]
    lookup = Dict(x => i for (i, x) in enumerate(names))
    rows = ResultRow[]
    StructUtils.applyeach(PostgresStyle(), e) do i, row
        data = Vector{Any}(undef, length(names))
        StructUtils.applyeach(PostgresStyle(), RowClosure(data, types, 1), row)
        push!(rows, ResultRow(data, names, types, lookup, i))
    end
    return Result(names, types, rows)
end

function DBInterface.execute(stmt::Statement, params=nothing, ::Type{T}=Any; debug::Bool=false, binary::Bool=false) where {T}
    # validate params
    nparams = 0
    if params !== nothing
        for p in params
            nparams += 1
            nparams > stmt.nparams && param_mismatch(stmt.sql, stmt.nparams, nparams)
            stmt.params[nparams] = _param(p)
        end
    end
    nparams == stmt.nparams || param_mismatch(stmt.sql, stmt.nparams, nparams)
    @lock stmt.conn.lock begin
        # check that connection/statement are ok
        checkstmt(stmt)
        e = API.exec(stmt.conn.socket, stmt.name, stmt.params, stmt.names, stmt.typeIds, debug)
        return T === Any ? makeresult(e) : StructUtils.arraylike(T) ? StructUtils.make(PostgresStyle(), T, e) : only(StructUtils.make(PostgresStyle(), Vector{T}, e))
    end
end

function DBInterface.execute(conn::Connection, sql::AbstractString, params=nothing, ::Type{T}=Any; debug::Bool=false) where {T}
    if count(';', sql) > 1
        # multiple statement, execute in single exec call
        @lock conn.lock begin
            # check that connection is ok
            checkconn(conn)
            API.exec(conn.socket, sql, debug)
            return
        end
    else
        stmt = DBInterface.prepare(conn, sql; debug)
        return DBInterface.execute(stmt, params, T; debug)
    end
end
