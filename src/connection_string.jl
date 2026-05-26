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

default_user() = get(ENV, "PGUSER", get(ENV, "USER", get(ENV, "USERNAME", "")))

function parse_optional_int(value::Union{String, Nothing})
    value === nothing && return nothing
    isempty(value) && return nothing
    return parse(Int, value)
end

function connection_defaults()
    user = default_user()
    return Dict{String, String}(
        "host" => get(ENV, "PGHOST", "localhost"),
        "port" => get(ENV, "PGPORT", "5432"),
        "user" => user,
        "statement_cache_maxsize" => "100",
    )
end

function apply_env_defaults!(values::Dict{String, String})
    env_map = (
        "dbname" => "PGDATABASE",
        "password" => "PGPASSWORD",
        "application_name" => "PGAPPNAME",
        "connect_timeout" => "PGCONNECT_TIMEOUT",
        "sslmode" => "PGSSLMODE",
        "sslrootcert" => "PGSSLROOTCERT",
        "sslcert" => "PGSSLCERT",
        "sslkey" => "PGSSLKEY",
        "sslcapath" => "PGSSLCAPATH",
    )
    for (key, envkey) in env_map
        !haskey(values, key) && haskey(ENV, envkey) && (values[key] = ENV[envkey])
    end
    return values
end

function params_from_values(values::Dict{String, String})
    merged = connection_defaults()
    merge!(merged, values)
    apply_env_defaults!(merged)
    user = get(merged, "user", "")
    dbname = get(merged, "dbname", user)
    return ConnectionParams(
        ;
        host=get(merged, "host", "localhost"),
        port=parse(Int, get(merged, "port", "5432")),
        user=user,
        password=get(merged, "password", nothing),
        dbname=dbname,
        application_name=get(merged, "application_name", nothing),
        connect_timeout=parse_optional_int(get(merged, "connect_timeout", nothing)),
        sslmode=haskey(merged, "sslmode") ? lowercase(merged["sslmode"]) : nothing,
        sslrootcert=get(merged, "sslrootcert", nothing),
        sslcert=get(merged, "sslcert", nothing),
        sslkey=get(merged, "sslkey", nothing),
        sslcapath=get(merged, "sslcapath", nothing),
        statement_timeout=parse_optional_int(get(merged, "statement_timeout", nothing)),
        statement_cache_maxsize=parse(Int, get(merged, "statement_cache_maxsize", "100")),
    )
end

function parse_keyword_dsn(dsn::String)
    values = Dict{String, String}()
    i = firstindex(dsn)
    while i <= lastindex(dsn)
        while i <= lastindex(dsn) && (isspace(dsn[i]) || dsn[i] == ';')
            i = nextind(dsn, i)
        end
        i > lastindex(dsn) && break
        key_start = i
        while i <= lastindex(dsn) && dsn[i] != '='
            i = nextind(dsn, i)
        end
        i > lastindex(dsn) && break
        key = lowercase(strip(dsn[key_start:prevind(dsn, i)]))
        i = nextind(dsn, i)
        while i <= lastindex(dsn) && isspace(dsn[i])
            i = nextind(dsn, i)
        end
        buf = IOBuffer()
        if i <= lastindex(dsn) && dsn[i] == '\''
            i = nextind(dsn, i)
            while i <= lastindex(dsn)
                c = dsn[i]
                if c == '\\'
                    i = nextind(dsn, i)
                    if i <= lastindex(dsn)
                        write(buf, dsn[i])
                        i = nextind(dsn, i)
                    end
                elseif c == '\''
                    i = nextind(dsn, i)
                    break
                else
                    write(buf, c)
                    i = nextind(dsn, i)
                end
            end
        else
            while i <= lastindex(dsn) && !isspace(dsn[i]) && dsn[i] != ';'
                c = dsn[i]
                if c == '\\'
                    i = nextind(dsn, i)
                    if i <= lastindex(dsn)
                        write(buf, dsn[i])
                        i = nextind(dsn, i)
                    end
                else
                    write(buf, c)
                    i = nextind(dsn, i)
                end
            end
        end
        !isempty(key) && (values[key] = String(take!(buf)))
    end
    return values
end

function parse_dsn(dsn::String)
    lowered = lowercase(dsn)
    (startswith(lowered, "postgres://") || startswith(lowered, "postgresql://")) && return parse_uri(dsn)
    return params_from_values(parse_keyword_dsn(dsn))
end

function url_decode(val::AbstractString; plus_as_space::Bool=false)
    buf = IOBuffer()
    i = 1
    while i <= lastindex(val)
        c = val[i]
        if c == '%'
            i + 2 <= lastindex(val) || break
            hex = val[i + 1:i + 2]
            write(buf, UInt8(parse(Int, hex; base=16)))
            i += 3
        elseif c == '+' && plus_as_space
            write(buf, UInt8(' '))
            i += 1
        else
            write(buf, c)
            i = nextind(val, i)
        end
    end
    return String(take!(buf))
end

function parse_query_params(query::AbstractString)
    params = Dict{String, String}()
    for pair in split(query, '&')
        isempty(pair) && continue
        key, value = occursin('=', pair) ? split(pair, '='; limit=2) : (pair, "")
        params[url_decode(key; plus_as_space=true)] = url_decode(value; plus_as_space=true)
    end
    return params
end

function parse_uri(uri::String)
    lowered = lowercase(uri)
    startswith(lowered, "postgres://") && (uri = uri[lastindex("postgres://") + 1:end])
    startswith(lowered, "postgresql://") && (uri = uri[lastindex("postgresql://") + 1:end])
    values = Dict{String, String}()
    main, query = occursin('?', uri) ? split(uri, '?'; limit=2) : (uri, "")
    userinfo, hostpart = occursin('@', main) ? split(main, '@'; limit=2) : ("", main)
    if !isempty(userinfo)
        if occursin(':', userinfo)
            usr, pwd = split(userinfo, ':'; limit=2)
            values["user"] = url_decode(usr)
            values["password"] = url_decode(pwd)
        else
            values["user"] = url_decode(userinfo)
        end
    end
    hostport, db = occursin('/', hostpart) ? split(hostpart, '/'; limit=2) : (hostpart, "")
    !isempty(db) && (values["dbname"] = url_decode(db))
    if startswith(hostport, "[")
        closing = findfirst(isequal(']'), hostport)
        closing === nothing || (values["host"] = hostport[2:closing - 1])
        rest = closing === nothing ? "" : hostport[closing + 1:end]
        if startswith(rest, ":")
            values["port"] = rest[2:end]
        end
    elseif !isempty(hostport)
        if occursin(':', hostport)
            host_str, port_str = split(hostport, ':'; limit=2)
            values["host"] = url_decode(host_str)
            values["port"] = port_str
        else
            values["host"] = url_decode(hostport)
        end
    end
    if !isempty(query)
        params = parse_query_params(query)
        for key in ("user", "password", "dbname", "application_name", "connect_timeout", "sslmode", "sslrootcert", "sslcert", "sslkey", "sslcapath", "statement_timeout", "statement_cache_maxsize")
            haskey(params, key) && (values[key] = params[key])
        end
    end
    return params_from_values(values)
end

function parse_dsn(dsn::Nothing)
    return params_from_values(Dict{String, String}())
end

export ConnectionParams, parse_dsn

end
