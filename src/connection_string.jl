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

function Base.show(io::IO, params::ConnectionParams)
    password = params.password === nothing ? "nothing" : "***"
    print(io, "Postgres.ConnectionParams(host=", repr(params.host),
          ", port=", params.port, ", user=", repr(params.user),
          ", password=", password, ", dbname=", repr(params.dbname), ")")
end
Base.show(io::IO, ::MIME"text/plain", params::ConnectionParams) = show(io, params)

default_user() = get(ENV, "PGUSER", get(ENV, "USER", get(ENV, "USERNAME", "")))

function parse_optional_int(value::Union{String, Nothing}, key::String="")
    value === nothing && return nothing
    isempty(value) && return nothing
    parsed = tryparse(Int, value)
    parsed === nothing && throw(ArgumentError("invalid value \"$value\" for connection parameter \"$key\"; expected an integer"))
    return parsed
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

# libpq keywords this driver doesn't implement. They are accepted and ignored
# rather than rejected: managed-PostgreSQL providers routinely include them in
# the connection URI they hand users, and failing on a DSN that names a real
# libpq option would be worse than not honoring it.
const IGNORED_PARAMS = Set([
    "channel_binding", "target_session_attrs", "options", "gssencmode",
    "gsslib", "krbsrvname", "sslnegotiation", "sslcompression", "sslcrl",
    "sslcrldir", "sslpassword", "requiressl", "requirepeer", "hostaddr",
    "client_encoding", "passfile", "service", "fallback_application_name",
    "keepalives", "keepalives_idle", "keepalives_interval", "keepalives_count",
    "tcp_user_timeout", "load_balance_hosts", "replication",
])

function parse_bool_param(value::Union{String, Nothing}, default::Bool, key::String)
    value === nothing && return default
    # an empty value means "unset", as it does for the integer parameters
    isempty(value) && return default
    lowered = lowercase(value)
    lowered in ("1", "on", "true", "yes") && return true
    lowered in ("0", "off", "false", "no") && return false
    throw(ArgumentError("invalid value \"$value\" for connection parameter \"$key\"; expected a boolean (on/off, true/false, yes/no, 1/0)"))
end

# Ignored keywords that change security or connection-selection behavior when
# set: silently dropping "channel_binding=require" or a CRL file would leave
# the caller believing a protection is in place. The values listed are the
# no-op defaults for each keyword; any other value is rejected.
const SECURITY_SENSITIVE_IGNORED = Dict(
    "channel_binding" => ("", "prefer", "disable"),
    "target_session_attrs" => ("", "any"),
    "options" => ("",),
    "gssencmode" => ("", "prefer", "disable"),
    "sslnegotiation" => ("", "postgres"),
    "sslcompression" => ("", "0"),
    "sslcrl" => ("",),
    "sslcrldir" => ("",),
    "sslpassword" => ("",),
    "requiressl" => ("", "0"),
    "requirepeer" => ("",),
    "hostaddr" => ("",),
    "client_encoding" => ("", "UTF8", "UTF-8", "utf8", "utf-8"),
    "passfile" => ("",),
    "service" => ("",),
    "load_balance_hosts" => ("", "disable"),
    "replication" => ("", "0", "false", "off"),
)

function check_ignored_param(key::String, value::String)
    inert = get(SECURITY_SENSITIVE_IGNORED, key, nothing)
    inert === nothing && return
    value in inert && return
    throw(ArgumentError("connection parameter \"$key=$value\" is not supported by Postgres.jl and cannot be safely ignored"))
end

# An unrecognized key is almost always a typo, and silently dropping it is
# dangerous: "ssl_mode=verify-full" would leave sslmode unset and fall back to
# an unverified connection while the caller believes otherwise. libpq errors
# on unknown keywords for the same reason.
function check_known_params(values::Dict{String, String})
    for (key, value) in values
        (key in KNOWN_PARAMS || key in IGNORED_PARAMS) ||
            throw(ArgumentError("unrecognized connection parameter \"$key\"; recognized parameters are $(join(sort!(collect(KNOWN_PARAMS)), ", "))"))
        key in IGNORED_PARAMS && check_ignored_param(key, value)
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
        port=something(parse_optional_int(get(merged, "port", nothing), "port"), 5432),
        user=user,
        password=get(merged, "password", nothing),
        dbname=dbname,
        application_name=get(merged, "application_name", nothing),
        connect_timeout=parse_optional_int(get(merged, "connect_timeout", nothing), "connect_timeout"),
        # deliberately NOT empty-tolerant, matching libpq: an unexpanded
        # ${PGSSLMODE} that was meant to be verify-full must fail loudly
        # rather than fall back to the unauthenticated default
        sslmode=haskey(merged, "sslmode") ? lowercase(merged["sslmode"]) : nothing,
        sslrootcert=get(merged, "sslrootcert", nothing),
        sslcert=get(merged, "sslcert", nothing),
        sslkey=get(merged, "sslkey", nothing),
        sslcapath=get(merged, "sslcapath", nothing),
        sslservername=get(merged, "sslservername", nothing),
        statement_timeout=parse_optional_int(get(merged, "statement_timeout", nothing), "statement_timeout"),
        statement_cache_maxsize=something(parse_optional_int(get(merged, "statement_cache_maxsize", nothing), "statement_cache_maxsize"), 100),
        debug=parse_bool_param(get(merged, "debug", nothing), false, "debug"),
        reconnect=parse_bool_param(get(merged, "reconnect", nothing), false, "reconnect"),
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
        while i <= lastindex(dsn) && dsn[i] != '=' &&
              !isspace(dsn[i]) && dsn[i] != ';'
            i = nextind(dsn, i)
        end
        key_end = prevind(dsn, i)
        key = key_end < key_start ? "" : lowercase(String(dsn[key_start:key_end]))
        isempty(key) && throw(ArgumentError("empty connection parameter name"))
        while i <= lastindex(dsn) && isspace(dsn[i])
            i = nextind(dsn, i)
        end
        (i <= lastindex(dsn) && dsn[i] == '=') ||
            throw(ArgumentError("connection parameter \"$key\" is missing '='"))
        i = nextind(dsn, i)
        while i <= lastindex(dsn) && isspace(dsn[i])
            i = nextind(dsn, i)
        end

        buf = IOBuffer()
        if i <= lastindex(dsn) && dsn[i] == '\''
            i = nextind(dsn, i)
            closed_quote = false
            while i <= lastindex(dsn)
                c = dsn[i]
                if c == '\\'
                    i = nextind(dsn, i)
                    i <= lastindex(dsn) ||
                        throw(ArgumentError("dangling escape in value for connection parameter \"$key\""))
                    write(buf, dsn[i])
                    i = nextind(dsn, i)
                elseif c == '\''
                    i = nextind(dsn, i)
                    closed_quote = true
                    break
                else
                    write(buf, c)
                    i = nextind(dsn, i)
                end
            end
            closed_quote ||
                throw(ArgumentError("unterminated quoted value for connection parameter \"$key\""))
            if i <= lastindex(dsn) && !isspace(dsn[i]) && dsn[i] != ';'
                throw(ArgumentError("unexpected text after quoted value for connection parameter \"$key\""))
            end
        else
            while i <= lastindex(dsn) && !isspace(dsn[i]) && dsn[i] != ';'
                c = dsn[i]
                if c == '\\'
                    i = nextind(dsn, i)
                    i <= lastindex(dsn) ||
                        throw(ArgumentError("dangling escape in value for connection parameter \"$key\""))
                    write(buf, dsn[i])
                    i = nextind(dsn, i)
                else
                    write(buf, c)
                    i = nextind(dsn, i)
                end
            end
        end
        values[key] = String(take!(buf))
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
            (key in KNOWN_PARAMS || key in IGNORED_PARAMS) ||
                throw(ArgumentError("unrecognized connection parameter \"$key\" in URI; recognized parameters are $(join(sort!(collect(KNOWN_PARAMS)), ", "))"))
            key in IGNORED_PARAMS && check_ignored_param(key, value)
            # keys we accept but don't implement must not reach params_from_values
            key in KNOWN_PARAMS && (values[key] = value)
        end
    end
    return params_from_values(values)
end

function parse_dsn(dsn::Nothing)
    return params_from_values(Dict{String, String}())
end

export ConnectionParams, parse_dsn

end
