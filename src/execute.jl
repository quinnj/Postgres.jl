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
    command_tag::Union{Nothing, String}
    rows_affected::Union{Nothing, Int}
end

Base.size(r::Result) = (length(r.rows),)
Base.getindex(r::Result, i::Integer) = r.rows[i]

"""
    Postgres.command_tag(result) -> Union{String, Nothing}

The PostgreSQL command completion tag for the executed statement, e.g.
`"SELECT 5"`, `"INSERT 0 2"`, or `"UPDATE 3"`.
"""
command_tag(r::Result) = r.command_tag

"""
    Postgres.rows_affected(result) -> Union{Int, Nothing}

The number of rows the statement affected (parsed from the command tag), or
`nothing` when the statement doesn't report one.
"""
rows_affected(r::Result) = r.rows_affected

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

function DBInterface.close!(::Result)
    return
end

# parametric on the connection's style so `conn` stays a concrete type — with the
# 2-parameter Connection, a bare `Connection{Statement}` field is a UnionAll, making
# every stmt.conn access (and everything downstream) dynamic under `juliac --trim`
mutable struct Statement{S <: API.AbstractPostgresStyle} <: DBInterface.Statement
    const conn::Connection{Statement{S}, S}
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

DBInterface.getconnection(stmt::Statement) = stmt.conn

# parametric on the connection's style, same rationale as Statement{S}
mutable struct Cursor{S <: API.AbstractPostgresStyle}
    const conn::Connection{Statement{S}, S}
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

Base.IteratorSize(::Type{<:Cursor}) = Base.SizeUnknown()
Base.IteratorEltype(::Type{<:Cursor}) = Base.HasEltype()
Base.eltype(::Type{<:Cursor}) = ResultRow

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
            return Statement{_style_type(conn)}(conn, name, sql_str, length(names), names, types, nparams, params, false, false, conn.generation, last_used)
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
        stmt = Statement{_style_type(conn)}(conn, name, sql_str, length(names), names, types, nparams, params, false, true, conn.generation, last_used)
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
        stmt.cached && haskey(stmt.conn.statements, stmt.sql) && stmt.conn.statements[stmt.sql] === stmt && delete!(stmt.conn.statements, stmt.sql)
        API.close_statement(stmt.conn.socket, stmt.name, stmt.conn.debug)
        stmt.closed = true
    end
    return
end

# Finish the transaction a cursor opened for itself. If the connection died,
# clear the bookkeeping directly rather than trying to COMMIT: leaving
# in_transaction set would make checkconn refuse to reconnect forever, and the
# server-side transaction is already gone with the session.
function finish_cursor_transaction!(conn::Connection)
    if !isopen(conn)
        clear_transaction_state!(conn)
        return
    end
    in_transaction(conn) && commit(conn)
    return
end

# same, for the failure path: roll back rather than commit
function abort_cursor_transaction!(conn::Connection)
    if !isopen(conn)
        clear_transaction_state!(conn)
        return
    end
    in_transaction(conn) && rollback(conn)
    return
end

function DBInterface.close!(cursor::Cursor)
    owns_transaction = cursor.owns_transaction
    closed_cleanly = false
    try
        @lock cursor.conn.lock begin
            if !cursor.done
                API.writemessages(cursor.conn.socket, cursor.conn.debug, ('C', UInt8('P'), cursor.portal), ('S',))
                API.waitfor(cursor.conn.socket, cursor.conn.debug, '3', 'Z')
            end
            cursor.done = true
            empty!(cursor.buffer)
        end
        closed_cleanly = true
    finally
        # take responsibility exactly once: closing an already-closed cursor
        # must not commit whatever transaction the caller has open now
        cursor.owns_transaction = false
        if owns_transaction
            if closed_cleanly
                # a COMMIT failure here means the caller's writes did not land,
                # so it must propagate rather than be swallowed
                finish_cursor_transaction!(cursor.conn)
            else
                try
                    finish_cursor_transaction!(cursor.conn)
                catch
                    # already unwinding; don't mask the original error
                end
            end
        end
    end
    return
end
Base.close(cursor::Cursor) = DBInterface.close!(cursor)

_param(x::AbstractString)::String = String(x)
_param(x)::String = string(x)
_param(x::Missing) = x
_param(::Nothing) = missing
_param(x::AbstractVector{UInt8})::String = string("\\x", bytes2hex(x))
# convert to postgres array literal syntax: { x, y, z }
# strings must be double-quoted and double quotes and backslashes escaped
# missing values are NULL
_aparam(x::AbstractString)::String = string("\"", replace(x, r"([\"\\])" => s"\\\1"), "\"")
_aparam(::Missing)::String = "NULL"
_aparam(::Nothing)::String = "NULL"
_aparam(x)::String = _param(x)
function _param(x::AbstractVector)::String
    io = IOBuffer()
    write(io, '{')
    first_item = true
    for y in x
        if first_item
            first_item = false
        else
            write(io, ", ")
        end
        write(io, _aparam(y))
    end
    write(io, '}')
    return String(take!(io))
end

@noinline param_mismatch(sql, nparams, n) = throw(PostgresInterfaceError("number of parameters provided ($n) does not match number of placeholders ($nparams) in sql: $sql"))

@generated function bind_tuple_params!(dest::Vector{Union{String, Missing}}, params::Tuple{Vararg{Any, N}}) where {N}
    assigns = [:(dest[$i] = _param(params[$i])) for i in 1:N]
    return Expr(:block, assigns..., :(return nothing))
end

function bind_params!(dest::Vector{Union{String, Missing}}, params::Tuple, sql::AbstractString)
    nparams = length(params)
    nparams > length(dest) && param_mismatch(sql, length(dest), nparams)
    nparams == length(dest) || param_mismatch(sql, length(dest), nparams)
    bind_tuple_params!(dest, params)
    return
end

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

# @nospecialize(v): parse_value's return is Any by nature (OID-driven); the value
# lands in a Vector{Any}, so one instance suffices and the applycast call site
# stays statically resolvable under --trim
@inline function (f::RowClosure)(k, @nospecialize(v))
    if v === nothing
        # translate nothing -> missing for Tables.jl
        @inbounds f.types[f.i] = Union{f.types[f.i], Missing}
        @inbounds f.data[f.i] = missing
    else
        # the OID-derived column type is a default; widen the schema whenever
        # the parsed value doesn't fit it (nullable or nested array elements,
        # values from a custom parser), so Tables.schema stays truthful.
        # Widening must be monotone — replacing would let a later row narrow
        # the schema back to a type earlier rows don't satisfy.
        @inbounds if !(v isa f.types[f.i])
            @inbounds f.types[f.i] = Union{f.types[f.i], typeof(v)}
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
    StructUtils.applyeach(e.style, e) do i, row
        data = Vector{Any}(undef, length(names))
        StructUtils.applyeach(e.style, RowClosure(data, types, 1), row)
        push!(rows, ResultRow(data, names, types, lookup, i))
    end
    return Result(names, types, rows, e.command_tag[], e.rows_affected[])
end

function read_portal_batch!(cursor::Cursor)
    conn = cursor.conn
    rows = ResultRow[]
    error_msg = nothing
    consumer_error = nothing
    copy_in_statement = false
    copy_out_statement = false
    done = false
    try
        while true
            mt, len = API.readheader(conn.socket, conn.debug)
            if mt == UInt8('D')
                cursor.rowcount += 1
                if consumer_error === nothing
                    row = API.DataRow(read(conn.socket, len), cursor.names, cursor.typeIds, conn.type_registry)
                    try
                        data = Vector{Any}(undef, length(cursor.names))
                        StructUtils.applyeach(conn.style, RowClosure(data, cursor.types, 1), row)
                        push!(rows, ResultRow(data, cursor.names, cursor.types, cursor.lookup, cursor.rowcount))
                    catch err
                        # value conversion failed; keep reading through
                        # ReadyForQuery so the connection stays usable
                        consumer_error = err
                    end
                else
                    API.skipbytes!(conn.socket, len)
                end
            elseif mt == UInt8('s')
                API.skipbytes!(conn.socket, len)
                done = false
            elseif mt == UInt8('C')
                API.skipbytes!(conn.socket, len)
                done = true
            elseif mt == UInt8('G')
                # CopyInResponse: a COPY ... FROM STDIN statement was used with
                # a cursor. Abort the copy with CopyFail so the stream returns
                # to ready instead of deadlocking; a clear error is thrown
                # below. A fresh Sync must follow: the one sent with
                # Bind/Execute was ignored during copy-in mode.
                API.skipbytes!(conn.socket, len)
                copy_in_statement = true
                API.writemessages(conn.socket, conn.debug, ('f', "COPY FROM STDIN is not supported via cursor"), ('S',))
            elseif mt == UInt8('H') || mt == UInt8('d') || mt == UInt8('c')
                # CopyOutResponse/CopyData/CopyDone: drain the copy-out stream
                mt == UInt8('H') && (copy_out_statement = true)
                API.skipbytes!(conn.socket, len)
            elseif mt == UInt8('N')
                notice = API.noticeResponse(len, conn.socket)
                API.notice_callback(conn.style, notice)
            elseif mt == UInt8('A')
                notification = API.notificationResponse(len, conn.socket)
                API.notification_callback(conn.style, notification)
            elseif mt == UInt8('E')
                error_msg = API.errorResponse(len, conn.socket, conn.debug)
            elseif mt == UInt8('Z')
                API.skipbytes!(conn.socket, len)
                break
            else
                API.skipbytes!(conn.socket, len)
            end
        end
    catch
        # bailed mid-stream: the connection must never be reused
        close(conn.socket)
        error_msg === nothing || throw(error_msg)
        rethrow()
    end
    # same precedence as the execute path: for copy-in the server error is
    # just the CopyFail artifact; for copy-out a server error is a genuine
    # mid-stream failure and wins over the misuse error
    if copy_in_statement
        cursor.done = true
        throw(PostgresInterfaceError("COPY ... FROM STDIN is not supported via cursor; use Postgres.copy_from"))
    end
    if copy_out_statement
        cursor.done = true
        error_msg === nothing || throw(error_msg)
        throw(PostgresInterfaceError("COPY ... TO STDOUT is not supported via cursor; use Postgres.copy_to"))
    end
    error_msg === nothing || throw(error_msg)
    consumer_error === nothing || throw(consumer_error)
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

function DBInterface.execute(stmt::Statement, params=nothing, ::Type{T}=Any; debug::Bool=false) where {T}
    style = stmt.conn.style
    log_enabled = API.query_logging_enabled(style)
    start_ns = log_enabled ? time_ns() : 0
    result = nothing
    try
        @lock stmt.conn.lock begin
            # check that connection/statement are ok
            checkstmt(stmt)
            bind_params!(stmt.params, params, stmt.sql)
            # isa-split the socket union with per-branch typeasserts (identical calls in
            # both branches get tail-merged back into one dynamic call by the optimizer),
            # so the exec call resolves statically under `juliac --trim`
            socket = stmt.conn.socket
            e = if socket isa Reseau.TCP.Conn
                API.exec(style, socket::Reseau.TCP.Conn, stmt.name, stmt.params, stmt.names, stmt.typeIds, stmt.conn.type_registry, debug, 0)
            else
                API.exec(style, socket::Reseau.TLS.Conn, stmt.name, stmt.params, stmt.names, stmt.typeIds, stmt.conn.type_registry, debug, 0)
            end
            # in a finally: a failed statement still drained to ReadyForQuery
            # and its status is authoritative — skipping the copy on the error
            # path leaves the transaction tracking stale
            try
                result = T === Any ? makeresult(e) : StructUtils.arraylike(T) ? StructUtils.make(T, e, style) : only(StructUtils.make(Vector{T}, e, style))
            finally
                stmt.conn.server_in_transaction = API.in_transaction_status(e.tx_status[])
            end
        end
        log_enabled && API.query_logger(style, :execute, (sql=stmt.sql, params=params, duration_ns=time_ns() - start_ns, success=true))
        return result
    catch err
        log_enabled && API.query_logger(style, :execute, (sql=stmt.sql, params=params, duration_ns=time_ns() - start_ns, success=false, error=err))
        rethrow()
    end
end

function DBInterface.execute(conn::Connection, sql::AbstractString, params=nothing, ::Type{T}=Any; debug::Bool=false) where {T}
    sql_str = String(sql)
    style = conn.style
    log_enabled = API.query_logging_enabled(style)
    start_ns = log_enabled ? time_ns() : 0
    result = nothing
    try
        @lock conn.lock begin
            checkconn(conn)
            stmtname = API.prepare(conn.socket, sql_str, debug; name="")
            nparams, names, types = API.describeprepared(conn.socket, stmtname, debug)
            params_vec = build_params(params, nparams, sql_str)
            # see the statement-execute method: socket union isa-split for --trim
            socket = conn.socket
            e = if socket isa Reseau.TCP.Conn
                API.exec(style, socket::Reseau.TCP.Conn, stmtname, params_vec, names, types, conn.type_registry, debug, 0)
            else
                API.exec(style, socket::Reseau.TLS.Conn, stmtname, params_vec, names, types, conn.type_registry, debug, 0)
            end
            # in a finally, as in the statement-execute method above
            try
                result = T === Any ? makeresult(e) : StructUtils.arraylike(T) ? StructUtils.make(T, e, style) : only(StructUtils.make(Vector{T}, e, style))
            finally
                conn.server_in_transaction = API.in_transaction_status(e.tx_status[])
            end
        end
        log_enabled && API.query_logger(style, :execute, (sql=sql_str, params=params, duration_ns=time_ns() - start_ns, success=true))
        return result
    catch err
        log_enabled && API.query_logger(style, :execute, (sql=sql_str, params=params, duration_ns=time_ns() - start_ns, success=false, error=err))
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
        cursor = Cursor{_style_type(conn)}(conn, portal, stmt.names, stmt.typeIds, types, lookup, max(1, Int(fetchsize)), ResultRow[], 1, false, 0, owns_transaction)
        API.writemessages(conn.socket, conn.debug, ('B', portal, stmt.name, Int16(0), Int16(length(stmt.params)), API.Params(stmt.params), Int16(0)), ('E', portal, Int32(cursor.fetchsize)), ('S',))
        read_portal_batch!(cursor)
        return cursor
    end
end

"""
    Postgres.cursor(conn, sql, params=nothing; fetchsize=1000) -> Cursor
    Postgres.cursor(stmt, params=nothing; fetchsize=1000) -> Cursor

Execute a query and stream its result rows in batches of `fetchsize` instead
of materializing them all at once. The returned cursor iterates rows; close it
with `DBInterface.close!(cursor)`. A cursor requires a transaction: one is
started (and committed on close) if the connection isn't already in one.
"""
function cursor(conn::Connection, sql::AbstractString, params=nothing; fetchsize::Integer=1000, debug::Bool=false)
    owns_transaction = false
    # a transaction opened with raw SQL counts as "already in one": the server
    # status sees it even though the client flag doesn't, and owning it here
    # would mean committing the caller's transaction on cursor close
    already_in_tx = @lock conn.lock (conn.in_transaction || conn.server_in_transaction)
    already_in_tx || (start_transaction(conn); owns_transaction = true)
    try
        stmt = DBInterface.prepare(conn, sql; debug=debug)
        return cursor(stmt, params; fetchsize=fetchsize, owns_transaction=owns_transaction)
    catch
        # don't leave the transaction we started dangling on a failed cursor
        # don't leave the transaction we started dangling on a failed cursor;
        # if the connection died, clear the state directly (a ROLLBACK can't be
        # delivered, and leaving it set would block reconnect forever)
        if owns_transaction
            try
                abort_cursor_transaction!(conn)
            catch
                # already unwinding; don't mask the original error
            end
        end
        rethrow()
    end
end
