module ConnectionString

struct ConnectionParams
    host::String
    port::Int
    user::String
    password::Union{String, Nothing}
    dbname::String
    application_name::Union{String, Nothing}
    connect_timeout::Union{Int, Nothing}
    sslmode::Union{String, Nothing}
    sslrootcert::Union{String, Nothing}
    sslcert::Union{String, Nothing}
    sslkey::Union{String, Nothing}
    sslcapath::Union{String, Nothing}
    statement_timeout::Union{Int, Nothing}
    statement_cache_maxsize::Int
    debug::Bool
    reconnect::Bool
end

function ConnectionParams(; host::String="localhost", port::Int=5432, user::String="", password::Union{String, Nothing}=nothing, dbname::String="", application_name::Union{String, Nothing}=nothing, connect_timeout::Union{Int, Nothing}=nothing, sslmode::Union{String, Nothing}=nothing, sslrootcert::Union{String, Nothing}=nothing, sslcert::Union{String, Nothing}=nothing, sslkey::Union{String, Nothing}=nothing, sslcapath::Union{String, Nothing}=nothing, statement_timeout::Union{Int, Nothing}=nothing, statement_cache_maxsize::Int=100, debug::Bool=false, reconnect::Bool=false)
    return ConnectionParams(host, port, user, password, dbname, application_name, connect_timeout, sslmode, sslrootcert, sslcert, sslkey, sslcapath, statement_timeout, statement_cache_maxsize, debug, reconnect)
end

function parse_dsn(dsn::String)
    lowered = lowercase(dsn)
    (startswith(lowered, "postgres://") || startswith(lowered, "postgresql://")) && return parse_uri(dsn)
    host = "localhost"
    port = 5432
    user = ""
    password = nothing
    dbname = ""
    application_name = nothing
    connect_timeout = nothing
    sslmode = nothing
    sslrootcert = nothing
    sslcert = nothing
    sslkey = nothing
    sslcapath = nothing
    statement_timeout = nothing
    statement_cache_maxsize = 100

    parts = split(dsn, ';')
    for part in parts
        part = strip(part)
        isempty(part) && continue
        if occursin('=', part)
            key, value = split(part, '='; limit=2)
            key = lowercase(strip(key))
            value = strip(value)
            key == "host" && (host = value)
            key == "port" && (port = parse(Int, value))
            key == "user" && (user = value)
            key == "password" && (password = value)
            key == "dbname" && (dbname = value)
            key == "application_name" && (application_name = value)
            key == "connect_timeout" && (connect_timeout = parse(Int, value))
            key == "sslmode" && (sslmode = lowercase(value))
            key == "sslrootcert" && (sslrootcert = value)
            key == "sslcert" && (sslcert = value)
            key == "sslkey" && (sslkey = value)
            key == "sslcapath" && (sslcapath = value)
            key == "statement_timeout" && (statement_timeout = parse(Int, value))
            key == "statement_cache_maxsize" && (statement_cache_maxsize = parse(Int, value))
        end
    end

    return ConnectionParams(; host=host, port=port, user=user, password=password, dbname=dbname, application_name=application_name, connect_timeout=connect_timeout, sslmode=sslmode, sslrootcert=sslrootcert, sslcert=sslcert, sslkey=sslkey, sslcapath=sslcapath, statement_timeout=statement_timeout, statement_cache_maxsize=statement_cache_maxsize)
end

function url_decode(val::String)
    buf = IOBuffer()
    i = 1
    while i <= lastindex(val)
        c = val[i]
        if c == '%'
            i + 2 <= lastindex(val) || break
            hex = val[i + 1:i + 2]
            write(buf, UInt8(parse(Int, hex; base=16)))
            i += 3
        elseif c == '+'
            write(buf, UInt8(' '))
            i += 1
        else
            write(buf, UInt8(codeunit(val, i)))
            i = nextind(val, i)
        end
    end
    return String(take!(buf))
end

function parse_query_params(query::String)
    params = Dict{String, String}()
    for pair in split(query, '&')
        isempty(pair) && continue
        key, value = split(pair, '='; limit=2)
        params[url_decode(key)] = url_decode(value)
    end
    return params
end

function parse_uri(uri::String)
    lowered = lowercase(uri)
    startswith(lowered, "postgres://") && (uri = uri[12:end])
    startswith(lowered, "postgresql://") && (uri = uri[15:end])
    user = ""
    password = nothing
    host = "localhost"
    port = 5432
    dbname = ""
    application_name = nothing
    connect_timeout = nothing
    sslmode = nothing
    sslrootcert = nothing
    sslcert = nothing
    sslkey = nothing
    sslcapath = nothing
    statement_timeout = nothing
    statement_cache_maxsize = 100
    main, query = occursin('?', uri) ? split(uri, '?'; limit=2) : (uri, "")
    userinfo, hostpart = occursin('@', main) ? split(main, '@'; limit=2) : ("", main)
    if !isempty(userinfo)
        if occursin(':', userinfo)
            usr, pwd = split(userinfo, ':'; limit=2)
            user = url_decode(usr)
            password = url_decode(pwd)
        else
            user = url_decode(userinfo)
        end
    end
    hostport, db = occursin('/', hostpart) ? split(hostpart, '/'; limit=2) : (hostpart, "")
    !isempty(db) && (dbname = url_decode(db))
    if startswith(hostport, "[")
        closing = findfirst(isequal(']'), hostport)
        closing === nothing || (host = hostport[2:closing - 1])
        rest = closing === nothing ? "" : hostport[closing + 1:end]
        if startswith(rest, ":")
            port = parse(Int, rest[2:end])
        end
    elseif !isempty(hostport)
        if occursin(':', hostport)
            host_str, port_str = split(hostport, ':'; limit=2)
            host = url_decode(host_str)
            port = parse(Int, port_str)
        else
            host = url_decode(hostport)
        end
    end
    if !isempty(query)
        params = parse_query_params(query)
        haskey(params, "user") && (user = params["user"])
        haskey(params, "password") && (password = params["password"])
        haskey(params, "dbname") && (dbname = params["dbname"])
        haskey(params, "application_name") && (application_name = params["application_name"])
        haskey(params, "connect_timeout") && (connect_timeout = parse(Int, params["connect_timeout"]))
        haskey(params, "sslmode") && (sslmode = lowercase(params["sslmode"]))
        haskey(params, "sslrootcert") && (sslrootcert = params["sslrootcert"])
        haskey(params, "sslcert") && (sslcert = params["sslcert"])
        haskey(params, "sslkey") && (sslkey = params["sslkey"])
        haskey(params, "sslcapath") && (sslcapath = params["sslcapath"])
        haskey(params, "statement_timeout") && (statement_timeout = parse(Int, params["statement_timeout"]))
        haskey(params, "statement_cache_maxsize") && (statement_cache_maxsize = parse(Int, params["statement_cache_maxsize"]))
    end
    return ConnectionParams(; host=host, port=port, user=user, password=password, dbname=dbname, application_name=application_name, connect_timeout=connect_timeout, sslmode=sslmode, sslrootcert=sslrootcert, sslcert=sslcert, sslkey=sslkey, sslcapath=sslcapath, statement_timeout=statement_timeout, statement_cache_maxsize=statement_cache_maxsize)
end

function parse_dsn(dsn::Nothing)
    return ConnectionParams()
end

export ConnectionParams, parse_dsn

end
