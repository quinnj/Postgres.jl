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

function DBInterface.close!(::Result)
    return
end

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
    closed::Bool
    cached::Bool
    generation::Int
    last_used::Int
end

mutable struct Cursor
    const conn::Connection
    const portal::String
    const names::Vector{Symbol}
    const typeIds::Vector{Int}
    const types::Vector{Type}
    const lookup::Dict{Symbol, Int}
    const fetchsize::Int
    buffer::Vector{ResultRow}
    index::Int
    done::Bool
    rowcount::Int
    owns_transaction::Bool
end

Base.IteratorSize(::Type{Cursor}) = Base.SizeUnknown()
Base.IteratorEltype(::Type{Cursor}) = Base.HasEltype()
Base.eltype(::Type{Cursor}) = ResultRow

function Base.show(io::IO, stmt::Statement)
    println(io, "Postgres.Statement:")
    print(io, stmt.sql)
end

function checkstmt(stmt::Statement)
    checkconn(stmt.conn)
    stmt.closed && throw(PostgresInterfaceError("statement has been closed"))
    if stmt.cached
        if stmt.generation != stmt.conn.generation || !haskey(stmt.conn.statements, stmt.sql)
            # if the connection was reset, we need to re-prepare the statement
            stmt.name = API.prepare(stmt.conn.socket, stmt.sql, stmt.conn.debug)
            stmt.conn.statements[stmt.sql] = stmt
            stmt.generation = stmt.conn.generation
        end
        touch_statement!(stmt.conn, stmt)
    elseif stmt.generation != stmt.conn.generation
        stmt.name = API.prepare(stmt.conn.socket, stmt.sql, stmt.conn.debug)
        stmt.generation = stmt.conn.generation
    end
    !stmt.cached && touch_statement!(stmt.conn, stmt)
    return
end

function DBInterface.prepare(conn::Connection, sql::AbstractString; debug::Bool=false)
    sql_str = String(sql)
    @lock conn.lock begin
        checkconn(conn)
        # check if we've already prepared this sql before
        if haskey(conn.statements, sql_str)
            stmt = conn.statements[sql_str]
            touch_statement!(conn, stmt)
            return stmt
        end
        if conn.statement_cache_maxsize == 0
            name = API.prepare(conn.socket, sql_str, debug)
            nparams, names, types = API.describeprepared(conn.socket, name, debug)
            params = Union{String, Missing}[missing for _ = 1:nparams]
            last_used = next_statement_clock!(conn)
            return Statement(conn, name, sql_str, length(names), names, types, nparams, params, false, false, conn.generation, last_used)
        end
        # evict if at max size
        while length(conn.statements) >= conn.statement_cache_maxsize
            evict_lru_statement!(conn)
        end
        # new statement to prepare
        name = API.prepare(conn.socket, sql_str, debug)
        nparams, names, types = API.describeprepared(conn.socket, name, debug)
        params = Union{String, Missing}[missing for _ = 1:nparams]
        last_used = next_statement_clock!(conn)
        stmt = Statement(conn, name, sql_str, length(names), names, types, nparams, params, false, true, conn.generation, last_used)
        conn.statements[sql_str] = stmt
        return stmt
    end
end

function DBInterface.close!(stmt::Statement)
    @lock stmt.conn.lock begin
        stmt.closed && return
        if !isopen(stmt.conn.socket)
            stmt.cached && haskey(stmt.conn.statements, stmt.sql) && delete!(stmt.conn.statements, stmt.sql)
            stmt.closed = true
            return
        end
        checkconn(stmt.conn)
        stmt.cached && haskey(stmt.conn.statements, stmt.sql) && stmt.conn.statements[stmt.sql] === stmt && delete!(stmt.conn.statements, stmt.sql)
        API.close_statement(stmt.conn.socket, stmt.name, stmt.conn.debug)
        stmt.closed = true
    end
    return
end

function DBInterface.close!(cursor::Cursor)
    owns_transaction = cursor.owns_transaction
    @lock cursor.conn.lock begin
        if !cursor.done
            API.writemessages(cursor.conn.socket, cursor.conn.debug, ('C', UInt8('P'), cursor.portal), ('S',))
            API.waitfor(cursor.conn.socket, cursor.conn.debug, '3', 'Z')
        end
        cursor.done = true
        empty!(cursor.buffer)
    end
    owns_transaction && in_transaction(cursor.conn) && commit(cursor.conn)
    return
end
Base.close(cursor::Cursor) = DBInterface.close!(cursor)

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

@noinline param_mismatch(sql, nparams, n) = throw(PostgresInterfaceError("number of parameters provided ($n) does not match number of placeholders ($nparams) in sql: $sql"))

function bind_params!(dest::Vector{Union{String, Missing}}, params, sql::AbstractString)
    nparams = 0
    if params !== nothing
        for p in params
            nparams += 1
            nparams > length(dest) && param_mismatch(sql, length(dest), nparams)
            dest[nparams] = _param(p)
        end
    end
    nparams == length(dest) || param_mismatch(sql, length(dest), nparams)
    return
end

function build_params(params, nparams::Int, sql::AbstractString)
    dest = Union{String, Missing}[missing for _ = 1:nparams]
    bind_params!(dest, params, sql)
    return dest
end

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
        if v isa AbstractVector && Missing <: eltype(v)
            @inbounds f.types[f.i] = typeof(v)
        end
        @inbounds f.data[f.i] = v
    end
    f.i += 1
    return
end

function makeresult(e::API.Exec)
    names, typeIds = e.names, e.typeIds
    types = Type[API.juliatype(x -> x, i, e.type_registry) for i in typeIds]
    lookup = Dict(x => i for (i, x) in enumerate(names))
    rows = ResultRow[]
    StructUtils.applyeach(PostgresStyle(), e) do i, row
        data = Vector{Any}(undef, length(names))
        StructUtils.applyeach(PostgresStyle(), RowClosure(data, types, 1), row)
        push!(rows, ResultRow(data, names, types, lookup, i))
    end
    return Result(names, types, rows)
end

function read_portal_batch!(cursor::Cursor)
    conn = cursor.conn
    rows = ResultRow[]
    error_msg = nothing
    done = false
    while true
        mt, len = API.readheader(conn.socket, conn.debug)
        if mt == UInt8('D')
            cursor.rowcount += 1
            data = Vector{Any}(undef, length(cursor.names))
            StructUtils.applyeach(PostgresStyle(), RowClosure(data, cursor.types, 1), API.DataRow(conn.socket, cursor.names, cursor.typeIds, conn.type_registry))
            push!(rows, ResultRow(data, cursor.names, cursor.types, cursor.lookup, cursor.rowcount))
        elseif mt == UInt8('s')
            API.skipbytes!(conn.socket, len)
            done = false
        elseif mt == UInt8('C')
            API.skipbytes!(conn.socket, len)
            done = true
        elseif mt == UInt8('N')
            notice = API.noticeResponse(len, conn.socket)
            conn.notice_callback(notice)
        elseif mt == UInt8('A')
            notification = API.notificationResponse(len, conn.socket)
            conn.notification_callback(notification)
        elseif mt == UInt8('E')
            error_msg = API.errorResponse(len, conn.socket, conn.debug)
        elseif mt == UInt8('Z')
            API.skipbytes!(conn.socket, len)
            break
        else
            API.skipbytes!(conn.socket, len)
        end
    end
    error_msg === nothing || throw(error_msg)
    cursor.buffer = rows
    cursor.index = 1
    cursor.done = done
    return
end

function fetch_portal!(cursor::Cursor)
    conn = cursor.conn
    @lock conn.lock begin
        checkconn(conn)
        API.writemessages(conn.socket, conn.debug, ('E', cursor.portal, Int32(cursor.fetchsize)), ('S',))
        read_portal_batch!(cursor)
    end
    return
end

function Base.iterate(cursor::Cursor, state=nothing)
    cursor.done && cursor.index > length(cursor.buffer) && return nothing
    if cursor.index > length(cursor.buffer)
        fetch_portal!(cursor)
        cursor.index > length(cursor.buffer) && cursor.done && return nothing
    end
    row = cursor.buffer[cursor.index]
    cursor.index += 1
    return row, nothing
end

function DBInterface.execute(stmt::Statement, params=nothing, ::Type{T}=Any; debug::Bool=false, binary::Bool=false) where {T}
    logger = stmt.conn.query_logger
    log_enabled = logger !== NOOP_QUERY_LOGGER
    start_ns = log_enabled ? time_ns() : 0
    result = nothing
    try
        @lock stmt.conn.lock begin
            # check that connection/statement are ok
            checkstmt(stmt)
            bind_params!(stmt.params, params, stmt.sql)
            e = API.exec(stmt.conn.socket, stmt.name, stmt.params, stmt.names, stmt.typeIds, stmt.conn.type_registry, debug, 0, stmt.conn.notice_callback, stmt.conn.notification_callback)
            result = T === Any ? makeresult(e) : StructUtils.arraylike(T) ? StructUtils.make(T, e, PostgresStyle()) : only(StructUtils.make(Vector{T}, e, PostgresStyle()))
        end
        log_enabled && log_query(logger, :execute, (sql=stmt.sql, params=params, duration_ns=time_ns() - start_ns, success=true))
        return result
    catch err
        log_enabled && log_query(logger, :execute, (sql=stmt.sql, params=params, duration_ns=time_ns() - start_ns, success=false, error=err))
        rethrow()
    end
end

function DBInterface.execute(conn::Connection, sql::AbstractString, params=nothing, ::Type{T}=Any; debug::Bool=false) where {T}
    sql_str = String(sql)
    logger = conn.query_logger
    log_enabled = logger !== NOOP_QUERY_LOGGER
    start_ns = log_enabled ? time_ns() : 0
    result = nothing
    try
        @lock conn.lock begin
            checkconn(conn)
            stmtname = API.prepare(conn.socket, sql_str, debug; name="")
            nparams, names, types = API.describeprepared(conn.socket, stmtname, debug)
            params_vec = build_params(params, nparams, sql_str)
            e = API.exec(conn.socket, stmtname, params_vec, names, types, conn.type_registry, debug, 0, conn.notice_callback, conn.notification_callback)
            result = T === Any ? makeresult(e) : StructUtils.arraylike(T) ? StructUtils.make(T, e, PostgresStyle()) : only(StructUtils.make(Vector{T}, e, PostgresStyle()))
        end
        log_enabled && log_query(logger, :execute, (sql=sql_str, params=params, duration_ns=time_ns() - start_ns, success=true))
        return result
    catch err
        log_enabled && log_query(logger, :execute, (sql=sql_str, params=params, duration_ns=time_ns() - start_ns, success=false, error=err))
        rethrow()
    end
end

function cursor(stmt::Statement, params=nothing; fetchsize::Integer=1000, owns_transaction::Bool=false)
    conn = stmt.conn
    @lock conn.lock begin
        checkstmt(stmt)
        bind_params!(stmt.params, params, stmt.sql)
        portal = string(UUIDs.uuid4())
        types = Type[API.juliatype(x -> x, i, conn.type_registry) for i in stmt.typeIds]
        lookup = Dict(x => i for (i, x) in enumerate(stmt.names))
        cursor = Cursor(conn, portal, stmt.names, stmt.typeIds, types, lookup, max(1, Int(fetchsize)), ResultRow[], 1, false, 0, owns_transaction)
        API.writemessages(conn.socket, conn.debug, ('B', portal, stmt.name, Int16(0), Int16(length(stmt.params)), API.Params(stmt.params), Int16(0)), ('E', portal, Int32(cursor.fetchsize)), ('S',))
        read_portal_batch!(cursor)
        return cursor
    end
end

function cursor(conn::Connection, sql::AbstractString, params=nothing; fetchsize::Integer=1000, debug::Bool=false)
    owns_transaction = false
    in_transaction(conn) || (start_transaction(conn); owns_transaction = true)
    stmt = DBInterface.prepare(conn, sql; debug=debug)
    return cursor(stmt, params; fetchsize=fetchsize, owns_transaction=owns_transaction)
end
