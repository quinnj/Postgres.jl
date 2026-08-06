module ConnectionString

using URIs

"""
    Postgres.ConnectionParams(; host="localhost", port=5432, user="", password=nothing,
                              dbname="", kwargs...)

Structured connection options, an alternative to DSN strings:

    params = Postgres.ConnectionParams(host="127.0.0.1", user="postgres", dbname="postgres")
    conn = DBInterface.connect(Postgres.Connection, params)

Also produced by `Postgres.parse_dsn`. Supported keyword
arguments mirror the connection keywords: `application_name`,
`connect_timeout`, `sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `sslcapath`,
`sslservername`, `statement_timeout`, `statement_cache_maxsize`, `debug`, and
`reconnect`.
"""
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
    sslservername::Union{String, Nothing}
    statement_timeout::Union{Int, Nothing}
    statement_cache_maxsize::Int
    debug::Bool
    reconnect::Bool
end

function ConnectionParams(; host::String="localhost", port::Int=5432, user::String="", password::Union{String, Nothing}=nothing, dbname::String="", application_name::Union{String, Nothing}=nothing, connect_timeout::Union{Int, Nothing}=nothing, sslmode::Union{String, Nothing}=nothing, sslrootcert::Union{String, Nothing}=nothing, sslcert::Union{String, Nothing}=nothing, sslkey::Union{String, Nothing}=nothing, sslcapath::Union{String, Nothing}=nothing, sslservername::Union{String, Nothing}=nothing, statement_timeout::Union{Int, Nothing}=nothing, statement_cache_maxsize::Int=100, debug::Bool=false, reconnect::Bool=false)
    return ConnectionParams(host, port, user, password, dbname, application_name, connect_timeout, sslmode, sslrootcert, sslcert, sslkey, sslcapath, sslservername, statement_timeout, statement_cache_maxsize, debug, reconnect)
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

const KNOWN_PARAMS = Set([
    "host", "port", "user", "password", "dbname", "application_name",
    "connect_timeout", "sslmode", "sslrootcert", "sslcert", "sslkey",
    "sslcapath", "sslservername", "statement_timeout",
    "statement_cache_maxsize", "debug", "reconnect",
])

parse_bool_param(value::Union{String, Nothing}, default::Bool) = value === nothing ? default : lowercase(value) in ("1", "on", "true", "yes")

# An unrecognized key is almost always a typo, and silently dropping it is
# dangerous: "ssl_mode=verify-full" would leave sslmode unset and fall back to
# an unverified connection while the caller believes otherwise. libpq errors
# on unknown keywords for the same reason.
function check_known_params(values::Dict{String, String})
    for key in keys(values)
        key in KNOWN_PARAMS || throw(ArgumentError("unrecognized connection parameter \"$key\"; recognized parameters are $(join(sort!(collect(KNOWN_PARAMS)), ", "))"))
    end
    return values
end

function params_from_values(values::Dict{String, String})
    check_known_params(values)
    merged = connection_defaults()
    merge!(merged, values)
    apply_env_defaults!(merged)
    user = get(merged, "user", "")
    dbname = get(merged, "dbname", user)
    return ConnectionParams(
        ;
        host=get(merged, "host", "localhost"),
        # empty values (an unset PGPORT expanded into the environment) fall
        # back to the default rather than failing to parse
        port=something(parse_optional_int(get(merged, "port", nothing)), 5432),
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
        sslservername=get(merged, "sslservername", nothing),
        statement_timeout=parse_optional_int(get(merged, "statement_timeout", nothing)),
        statement_cache_maxsize=something(parse_optional_int(get(merged, "statement_cache_maxsize", nothing)), 100),
        debug=parse_bool_param(get(merged, "debug", nothing), false),
        reconnect=parse_bool_param(get(merged, "reconnect", nothing), false),
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

"""
    Postgres.parse_dsn(dsn) -> ConnectionParams

Parse a libpq-style keyword string (`"host=127.0.0.1 user=postgres"`) or a
PostgreSQL URI (`"postgresql://user:pass@host:5432/dbname"`) into
`ConnectionParams`. Unset options fall back
to the `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGAPPNAME`,
`PGCONNECT_TIMEOUT`, and `PGSSL*` environment variables, then to defaults.
"""
function parse_dsn(dsn::String)
    lowered = lowercase(dsn)
    (startswith(lowered, "postgres://") || startswith(lowered, "postgresql://")) && return parse_uri(dsn)
    return params_from_values(parse_keyword_dsn(dsn))
end

function parse_uri(uri::String)
    parsed = URIs.URI(uri)
    scheme = lowercase(String(parsed.scheme))
    (scheme == "postgres" || scheme == "postgresql") || throw(ArgumentError("invalid PostgreSQL URI scheme: $scheme"))
    values = Dict{String, String}()
    userinfo = String(parsed.userinfo)
    if !isempty(userinfo)
        if occursin(':', userinfo)
            usr, pwd = split(userinfo, ':'; limit=2)
            values["user"] = URIs.unescapeuri(usr)
            values["password"] = URIs.unescapeuri(pwd)
        else
            values["user"] = URIs.unescapeuri(userinfo)
        end
    end

    host = String(parsed.host)
    !isempty(host) && (values["host"] = URIs.unescapeuri(host))
    port = String(parsed.port)
    !isempty(port) && (values["port"] = port)

    path = String(parsed.path)
    if startswith(path, "/") && length(path) > 1
        values["dbname"] = URIs.unescapeuri(path[nextind(path, firstindex(path)):end])
    end

    query = String(parsed.query)
    if !isempty(query)
        params = URIs.queryparams(query)
        for (key, value) in params
            key in KNOWN_PARAMS || throw(ArgumentError("unrecognized connection parameter \"$key\" in URI"))
            values[key] = value
        end
    end
    return params_from_values(values)
end

function parse_dsn(dsn::Nothing)
    return params_from_values(Dict{String, String}())
end

export ConnectionParams, parse_dsn

end
