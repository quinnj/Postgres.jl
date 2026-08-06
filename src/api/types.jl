const JSONType = typeof(JSON.lazy("1"))

"""
    AbstractPostgresStyle <: StructUtils.StructStyle

Style hierarchy for customizing driver behavior, following the StructUtils "style"
pattern. Pass a custom style to `Connection(; style=MyStyle())` and overload the
behavior interface on it:

    Postgres.query_logging_enabled(::MyStyle) = true
    Postgres.query_logger(::MyStyle, event::Symbol, info::NamedTuple) = ...
    Postgres.notice_callback(::MyStyle, notice) = ...
    Postgres.notification_callback(::MyStyle, notification) = ...

Custom styles inherit the default row-materialization traits (lift/structlike/...),
which dispatch on `AbstractPostgresStyle`, and are used as the StructUtils style when
materializing query results — so `StructUtils.lift` overloads on a custom style apply
to row values too. Static dispatch on the style (rather than `Function`-typed callback
fields) also keeps the driver compilable under `juliac --trim`.
"""
abstract type AbstractPostgresStyle <: StructUtils.StructStyle end

"The default style: no query logging, NOTICE messages surface as `@warn`."
struct PostgresStyle <: AbstractPostgresStyle end

# behavior interface (style-first; overload on your own style)
query_logging_enabled(::AbstractPostgresStyle) = false
query_logger(::AbstractPostgresStyle, event::Symbol, info::NamedTuple) = nothing
function notice_callback(::AbstractPostgresStyle, notice)
    msg = get(notice, "M", "")
    !isempty(msg) && @warn msg
    return nothing
end
notification_callback(::AbstractPostgresStyle, notification) = nothing

StructUtils.fieldtagkey(::AbstractPostgresStyle) = :postgres
StructUtils.structlike(::AbstractPostgresStyle, ::Type{<:Number}) = false
StructUtils.structlike(::AbstractPostgresStyle, ::Type{<:JSON.LazyValue}) = false
StructUtils.lift(::AbstractPostgresStyle, ::Type{T}, x::T) where {T<:JSON.LazyValue} = x, nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{T}, x::T, tags) where {T<:JSON.LazyValue} = x, nothing


"""
    Postgres.Numeric

Exact decimal representation of a PostgreSQL `numeric`/`decimal` value:
`coeff * 10^-scale`, where `coeff` is a `BigInt` and `scale` the number of
digits after the decimal point. Preserves the value and scale exactly (no
floating-point rounding). `print`/`string` produce the decimal text form.

The PostgreSQL special values `NaN`, `Infinity`, and `-Infinity` cannot be
represented and throw an error when encountered.
"""
struct Numeric
    coeff::BigInt
    scale::Int
end
StructUtils.structlike(::AbstractPostgresStyle, ::Type{Numeric}) = false

Base.:(==)(a::Numeric, b::Numeric) = a.coeff == b.coeff && a.scale == b.scale

"""
    Postgres.PostgresRange{T}

A PostgreSQL range value (`int4range`, `numrange`, `tstzrange`, ...). `lower`
and `upper` are the bounds (`missing` when unbounded), `lower_inclusive` and
`upper_inclusive` indicate whether each bound is inclusive, and `empty` is
`true` for the empty range.
"""
struct PostgresRange{T}
    lower::Union{T, Missing}
    upper::Union{T, Missing}
    lower_inclusive::Bool
    upper_inclusive::Bool
    empty::Bool
end

# ── CastFn: trim-safe type-erased value caster (the Reseau TaskFn pattern) ──
# A per-callable-type @generated @cfunction whose first C argument is the callable
# (Ref{F}), so the parser call inside the trampoline is concretely dispatched; the
# registry invocation is a ccall through the stored pointer — statically resolvable
# under `juliac --trim`, where a `Function`-typed field call is open-set dynamic
# dispatch. The C signature is primitive-only (the verifier rejects boxed-Any
# cfunction signatures): value/registry/result cross as raw pointers to
# caller-GC.@preserve'd objects. `_root` keeps the callable alive.

struct _CastCallWrapper <: Function end

@generated function _cast_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_CastCallWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}))
    end
end

struct CastFn
    ptr::Ptr{Cvoid}       # @cfunction pointer (specialized per callable type F)
    objptr::Ptr{Cvoid}    # pointer to the callable object
    _root::Any            # GC root — prevents collection, never dispatched on
end

function CastFn(callable::F) where F
    ptr = _cast_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return CastFn(ptr, objptr, objref)
end

CastFn(callable::CastFn) = callable

struct TypeInfo
    julia_type::Type
    parser::Union{CastFn, Nothing}
end

# convenience: registry entries and register_type! keep passing plain functions
TypeInfo(julia_type::Type, parser::Function) = TypeInfo(julia_type, CastFn(parser))

function (::_CastCallWrapper)(f::F, valptr::Ptr{Cvoid}, regptr::Ptr{Cvoid}, outptr::Ptr{Cvoid}) where {F}
    valref = unsafe_pointer_to_objref(valptr)::Base.RefValue{Any}
    out = unsafe_pointer_to_objref(outptr)::Base.RefValue{Any}
    registry = unsafe_pointer_to_objref(regptr)::Dict{Int, TypeInfo}
    out[] = f(valref[]::String, registry)
    return nothing
end

@inline function (c::CastFn)(val::String, registry::Dict{Int, TypeInfo})
    valref = Ref{Any}(val)
    out = Ref{Any}(nothing)
    GC.@preserve valref out registry begin
        ccall(c.ptr, Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), c.objptr, pointer_from_objref(valref), pointer_from_objref(registry), pointer_from_objref(out))
    end
    return out[]
end

const IntervalType = Union{Dates.Period, Dates.CompoundPeriod}

# Populated in `_populate_default_type_registry!` (called from API.__init__): the
# entries hold CastFn @cfunction pointers, which must be created at runtime — a
# precompile-time-built const would serialize stale pointers into the image
# (bus error on first use).
const DEFAULT_TYPE_REGISTRY = Dict{Int, TypeInfo}()

function _populate_default_type_registry!()
    merge!(DEFAULT_TYPE_REGISTRY, Dict{Int, TypeInfo}(
    23 => TypeInfo(Int32, nothing),
    26 => TypeInfo(Cuint, nothing),
    20 => TypeInfo(Int64, nothing),
    21 => TypeInfo(Int16, nothing),
    16 => TypeInfo(Bool, nothing),
    3802 => TypeInfo(JSONType, nothing),
    114 => TypeInfo(JSONType, nothing),
    25 => TypeInfo(String, nothing),
    1043 => TypeInfo(String, nothing),
    1042 => TypeInfo(String, nothing),
    24 => TypeInfo(String, nothing),
    19 => TypeInfo(String, nothing),
    2950 => TypeInfo(UUID, nothing),
    700 => TypeInfo(Float32, nothing),
    701 => TypeInfo(Float64, nothing),
    1700 => TypeInfo(Numeric, (val, registry) -> parse_numeric(val)),
    1114 => TypeInfo(DateTime, nothing),
    1184 => TypeInfo(DateTime, nothing),
    1082 => TypeInfo(Date, nothing),
    1083 => TypeInfo(Time, nothing),
    1186 => TypeInfo(IntervalType, (val, registry) -> parse_interval(val)),
    17 => TypeInfo(Vector{UInt8}, nothing),
    18 => TypeInfo(Char, nothing),
    1560 => TypeInfo(Bool, nothing),
    1000 => TypeInfo(Vector{Bool}, nothing),
    1001 => TypeInfo(Vector{Vector{UInt8}}, (val, registry) -> parse_array_by_oid(val, 17, registry)),
    1005 => TypeInfo(Vector{Int16}, nothing),
    1007 => TypeInfo(Vector{Int32}, nothing),
    1016 => TypeInfo(Vector{Int64}, nothing),
    1021 => TypeInfo(Vector{Float32}, nothing),
    1022 => TypeInfo(Vector{Float64}, nothing),
    1009 => TypeInfo(Vector{String}, nothing),
    1014 => TypeInfo(Vector{String}, nothing),
    1015 => TypeInfo(Vector{String}, nothing),
    1115 => TypeInfo(Vector{DateTime}, (val, registry) -> parse_array_by_oid(val, 1114, registry)),
    1182 => TypeInfo(Vector{Date}, (val, registry) -> parse_array_by_oid(val, 1082, registry)),
    1183 => TypeInfo(Vector{Time}, (val, registry) -> parse_array_by_oid(val, 1083, registry)),
    1185 => TypeInfo(Vector{DateTime}, (val, registry) -> parse_array_by_oid(val, 1184, registry)),
    1187 => TypeInfo(Vector{IntervalType}, (val, registry) -> parse_array_by_oid(val, 1186, registry)),
    1231 => TypeInfo(Vector{Numeric}, (val, registry) -> parse_array_by_oid(val, 1700, registry)),
    199 => TypeInfo(Vector{JSONType}, (val, registry) -> parse_array_by_oid(val, 114, registry)),
    2951 => TypeInfo(Vector{UUID}, (val, registry) -> parse_array_by_oid(val, 2950, registry)),
    3807 => TypeInfo(Vector{JSONType}, (val, registry) -> parse_array_by_oid(val, 3802, registry)),
    3904 => TypeInfo(PostgresRange{Int32}, (val, registry) -> parse_range(val, 23, registry)),
    3926 => TypeInfo(PostgresRange{Int64}, (val, registry) -> parse_range(val, 20, registry)),
    3906 => TypeInfo(PostgresRange{Numeric}, (val, registry) -> parse_range(val, 1700, registry)),
    3908 => TypeInfo(PostgresRange{DateTime}, (val, registry) -> parse_range(val, 1114, registry)),
    3910 => TypeInfo(PostgresRange{DateTime}, (val, registry) -> parse_range(val, 1184, registry)),
    3912 => TypeInfo(PostgresRange{Date}, (val, registry) -> parse_range(val, 1082, registry)),
    ))
    return nothing
end

default_type_info(oid::Int) = get(DEFAULT_TYPE_REGISTRY, oid, TypeInfo(String, nothing))

type_info(registry::Dict{Int, TypeInfo}, oid::Int) = get(registry, oid, default_type_info(oid))

@inline function juliatype(f, oid::Int, registry::Dict{Int, TypeInfo})
    info = type_info(registry, oid)
    return f(info.julia_type)
end

function register_type!(registry::Dict{Int, TypeInfo}, oid::Integer, julia_type::Type; parser::Union{Function, Nothing}=nothing)
    registry[Int(oid)] = TypeInfo(julia_type, parser)
    return registry
end

@inline function tzoffset_seconds(offset::AbstractString)
    isempty(offset) && return 0
    sign = offset[1] == '-' ? -1 : 1
    digits = replace(String(offset[2:end]), ":" => "")
    isempty(digits) && return 0
    hours = parse(Int, digits[1:2])
    mins = length(digits) >= 4 ? parse(Int, digits[3:4]) : 0
    return sign * (hours * 3600 + mins * 60)
end

# ── hand-rolled postgres text-format date/time parsing ──────────────────────
# The wire formats are fixed-layout ("YYYY-MM-DD", "HH:MM:SS[.ffffff]",
# "YYYY-MM-DD HH:MM:SS[.ffffff][±TZ]"), so direct digit extraction is both faster
# than the generic Dates machinery and — decisive under `juliac --trim` — fully
# static: Parsers' dateformat path iterates a type-erased Vector{AbstractDateToken},
# which is dynamic dispatch per token. Fractional seconds beyond millisecond
# precision are truncated (DateTime/Time storage precision).
@inline _pg_digit(b::UInt8)::Int = Int(b - UInt8('0'))
@inline _pg_isdigit(b::UInt8)::Bool = UInt8('0') <= b <= UInt8('9')

@inline function _pg_date_at(c, o::Int)::Date
    y = _pg_digit(c[o]) * 1000 + _pg_digit(c[o+1]) * 100 + _pg_digit(c[o+2]) * 10 + _pg_digit(c[o+3])
    m = _pg_digit(c[o+5]) * 10 + _pg_digit(c[o+6])
    d = _pg_digit(c[o+8]) * 10 + _pg_digit(c[o+9])
    return Date(y, m, d)
end

@inline function _pg_hms_at(c, o::Int)
    h = _pg_digit(c[o]) * 10 + _pg_digit(c[o+1])
    mi = _pg_digit(c[o+3]) * 10 + _pg_digit(c[o+4])
    se = _pg_digit(c[o+6]) * 10 + _pg_digit(c[o+7])
    ms = 0
    i = o + 8
    if i <= length(c) && c[i] == UInt8('.')
        i += 1
        mult = 100
        while i <= length(c) && _pg_isdigit(c[i])
            if mult > 0
                ms += _pg_digit(c[i]) * mult
                mult ÷= 10
            end
            i += 1
        end
    end
    return h, mi, se, ms
end

function pg_parse_date(s::AbstractString)::Date
    c = codeunits(s)
    length(c) >= 10 || throw(ArgumentError("invalid postgres date"))
    return _pg_date_at(c, 1)
end

function pg_parse_time(s::AbstractString)::Time
    c = codeunits(s)
    length(c) >= 8 || throw(ArgumentError("invalid postgres time"))
    h, mi, se, ms = _pg_hms_at(c, 1)
    return Time(h, mi, se, ms)
end

function pg_parse_datetime(s::AbstractString)::DateTime
    c = codeunits(s)
    length(c) >= 19 || throw(ArgumentError("invalid postgres timestamp"))
    d = _pg_date_at(c, 1)
    h, mi, se, ms = _pg_hms_at(c, 12)
    return DateTime(Dates.year(d), Dates.month(d), Dates.day(d), h, mi, se, ms)
end

# timestamptz column into a DateTime field: sniff a trailing offset/Z
function pg_parse_datetime_any(s::AbstractString)::DateTime
    isempty(s) && throw(ArgumentError("invalid postgres timestamp"))
    ch = s[end]
    if ch == 'Z' || (length(s) >= 20 && (any(isequal('+'), SubString(s, 20)) || any(isequal('-'), SubString(s, 20))))
        return parse_timestamptz(String(s))
    end
    return pg_parse_datetime(s)
end

@inline function parse_timestamptz(val::String)
    lastindex(val) == 0 && throw(ArgumentError("invalid postgres timestamptz"))
    if val[end] == 'Z'
        ts = SubString(val, 1, prevind(val, lastindex(val)))
        return pg_parse_datetime(ts)
    end
    space_idx = findfirst(isequal(' '), val)
    space_idx === nothing && return pg_parse_datetime(val)
    offset_idx = nothing
    i = lastindex(val)
    while i > space_idx
        c = val[i]
        if c == '+' || c == '-'
            offset_idx = i
            break
        end
        i = prevind(val, i)
    end
    offset_idx === nothing && return pg_parse_datetime(val)
    ts = SubString(val, 1, prevind(val, offset_idx))
    dt = pg_parse_datetime(ts)
    offset = SubString(val, offset_idx)
    seconds = tzoffset_seconds(offset)
    return dt - Dates.Second(seconds)
end

function numeric_string(num::Numeric)
    coeff = num.coeff
    scale = num.scale
    sign = coeff < 0 ? "-" : ""
    digits = string(abs(coeff))
    scale <= 0 && return sign * digits * repeat("0", -scale)
    if length(digits) <= scale
        padding = repeat("0", scale - length(digits))
        return sign * "0." * padding * digits
    end
    split_at = length(digits) - scale
    return sign * digits[1:split_at] * "." * digits[split_at + 1:end]
end

Base.show(io::IO, num::Numeric) = print(io, numeric_string(num))

function parse_numeric(val::String)
    stripped = strip(val)
    stripped == "" && return Numeric(BigInt(0), 0)
    lowered = lowercase(stripped)
    (lowered == "nan" || lowered == "infinity" || lowered == "-infinity" || lowered == "+infinity") &&
        throw(PostgresInterfaceError("postgres numeric special value \"$stripped\" cannot be represented as Postgres.Numeric"))
    sign = 1
    if stripped[1] == '-'
        sign = -1
        stripped = stripped[2:end]
    elseif stripped[1] == '+'
        stripped = stripped[2:end]
    end
    exp_index = findfirst(c -> c == 'e' || c == 'E', stripped)
    exp_val = 0
    if exp_index !== nothing
        exp_val = parse(Int, stripped[exp_index + 1:end])
        stripped = stripped[1:exp_index - 1]
    end
    parts = split(stripped, '.'; limit=2)
    int_part = parts[1]
    frac_part = length(parts) == 2 ? parts[2] : ""
    scale = length(frac_part) - exp_val
    digits = int_part * frac_part
    digits == "" && return Numeric(BigInt(0), 0)
    coeff = parse(BigInt, digits)
    if scale < 0
        coeff *= big(10) ^ (-scale)
        scale = 0
    end
    return Numeric(sign * coeff, scale)
end

function parse_interval_time(token::AbstractString)
    sign = startswith(token, "-") ? -1 : 1
    token = startswith(token, "-") || startswith(token, "+") ? token[2:end] : token
    parts = split(token, ':')
    length(parts) == 3 || return Dates.Period[]
    hours = sign * parse(Int, parts[1])
    minutes = sign * parse(Int, parts[2])
    seconds_part = parts[3]
    seconds = 0
    milliseconds = 0
    if occursin('.', seconds_part)
        whole, frac = split(seconds_part, '.'; limit=2)
        seconds = parse(Int, whole)
        fs = frac[1:min(end, 3)]
        milliseconds = parse(Int, fs) * 10^(3 - length(fs))
    else
        seconds = parse(Int, seconds_part)
    end
    periods = Dates.Period[]
    hours != 0 && push!(periods, Dates.Hour(hours))
    minutes != 0 && push!(periods, Dates.Minute(minutes))
    seconds != 0 && push!(periods, Dates.Second(sign * seconds))
    milliseconds != 0 && push!(periods, Dates.Millisecond(sign * milliseconds))
    return periods
end

function parse_interval(val::String)
    tokens = split(strip(val))
    periods = Dates.Period[]
    i = 1
    while i <= length(tokens)
        token = tokens[i]
        if occursin(':', token)
            append!(periods, parse_interval_time(token))
            i += 1
            continue
        end
        i == length(tokens) && break
        amount = parse(Int, token)
        unit = lowercase(tokens[i + 1])
        if startswith(unit, "year")
            push!(periods, Dates.Year(amount))
        elseif startswith(unit, "mon")
            push!(periods, Dates.Month(amount))
        elseif startswith(unit, "day")
            push!(periods, Dates.Day(amount))
        elseif startswith(unit, "hour")
            push!(periods, Dates.Hour(amount))
        elseif startswith(unit, "min")
            push!(periods, Dates.Minute(amount))
        elseif startswith(unit, "sec")
            push!(periods, Dates.Second(amount))
        end
        i += 2
    end
    isempty(periods) && return Dates.Millisecond(0)
    length(periods) == 1 && return only(periods)
    # n=0 construction skips CompoundPeriod's canonicalize loop (whose Period +
    # merge is dynamic dispatch under --trim); pg interval text is already
    # canonical: unique units, descending order, zero units omitted
    cp = Dates.CompoundPeriod(Dates.Period[])
    append!(cp.periods, periods)
    return cp
end

function split_range_values(val::String)
    code = codeunits(val)
    pos = 0
    in_quotes = false
    escaped = false
    for i in 1:length(code)
        c = code[i]
        if escaped
            escaped = false
        elseif in_quotes && c == UInt8('\\')
            escaped = true
        elseif c == UInt8('"')
            in_quotes = !in_quotes
        elseif c == UInt8(',') && !in_quotes
            pos = i
            break
        end
    end
    pos == 0 && return val, ""
    left = pos == 1 ? "" : String(code[1:pos - 1])
    right = pos == length(code) ? "" : String(code[pos + 1:end])
    return left, right
end

function parse_range_value(token::String, typeId::Int, registry::Dict{Int, TypeInfo})
    token == "" && return missing
    return parse_value(typeId, token, registry)
end

# construct over the standard range element types explicitly: PostgresRange{T}
# from a runtime `julia_type` field is a runtime apply_type under --trim
@noinline function _make_range(::Type{T}, @nospecialize(lower), @nospecialize(upper), li::Bool, ui::Bool, empty::Bool) where {T}
    l = lower === missing ? missing : (lower::T)
    u = upper === missing ? missing : (upper::T)
    return PostgresRange{T}(l, u, li, ui, empty)
end

function _range_typed(@nospecialize(T), @nospecialize(lower), @nospecialize(upper), li::Bool, ui::Bool, empty::Bool)
    T === Int32 && return _make_range(Int32, lower, upper, li, ui, empty)
    T === Int64 && return _make_range(Int64, lower, upper, li, ui, empty)
    T === Float64 && return _make_range(Float64, lower, upper, li, ui, empty)
    T === Numeric && return _make_range(Numeric, lower, upper, li, ui, empty)
    T === Date && return _make_range(Date, lower, upper, li, ui, empty)
    T === DateTime && return _make_range(DateTime, lower, upper, li, ui, empty)
    throw(PostgresInterfaceError("no trim-safe range constructor registered for this element type; " *
                                 "register a parser function for the range type"))
end

function parse_range(val::String, typeId::Int, registry::Dict{Int, TypeInfo})
    T = type_info(registry, typeId).julia_type
    lowercase(val) == "empty" && return _range_typed(T, missing, missing, false, false, true)
    lower_inclusive = val[1] == '['
    upper_inclusive = val[end] == ']'
    inner = val[2:end - 1]
    left, right = split_range_values(inner)
    lower = parse_range_value(left, typeId, registry)
    upper = parse_range_value(right, typeId, registry)
    return _range_typed(T, lower, upper, lower_inclusive, upper_inclusive, false)
end

parse_array_scalar(typeId::Int, registry::Dict{Int, TypeInfo}, value::Missing) = missing
parse_array_scalar(typeId::Int, registry::Dict{Int, TypeInfo}, value::AbstractString) = parse_value(typeId, String(value), registry)
# explicit two-level walk: the self-recursive AbstractVector method is an
# unresolved invoke under --trim; deeper nesting throws (register a parser
# function for exotic multidimensional array types)
function parse_array_scalar(typeId::Int, registry::Dict{Int, TypeInfo}, value::AbstractVector)
    return Any[v === missing ? missing :
               v isa String ? parse_value(typeId, v, registry) :
               v isa SubString{String} ? parse_value(typeId, String(v), registry) :
               v isa Vector{Any} ? _parse_array_level2(typeId, registry, v) :
               v isa Vector{String} ? _parse_array_level2(typeId, registry, v) :
               v isa Vector{Union{Missing, String}} ? _parse_array_level2(typeId, registry, v) :
               v
               for v in value]
end
function _parse_array_level2(typeId::Int, registry::Dict{Int, TypeInfo},
                             value::Union{Vector{Any}, Vector{String}, Vector{Union{Missing, String}}})
    return Any[v === missing ? missing :
               v isa String ? parse_value(typeId, v, registry) :
               v isa SubString{String} ? parse_value(typeId, String(v), registry) :
               v isa AbstractVector ? throw(PostgresInterfaceError("arrays nested deeper than two dimensions are not supported on the untyped parse path")) :
               v
               for v in value]
end

function parse_array_by_oid(val::String, typeId::Int, registry::Dict{Int, TypeInfo})
    parsed = parse_array(val, String)
    return parse_array_scalar(typeId, registry, parsed)
end

function parse_composite_fields(val::String)
    code = codeunits(val)
    pos = 1
    fields = Vector{Union{String, Missing}}()
    if pos <= length(code) && code[pos] == UInt8('(')
        pos += 1
    end
    while pos <= length(code)
        pos > length(code) && break
        if code[pos] == UInt8(')')
            pos += 1
            break
        end
        if code[pos] == UInt8('"')
            pos += 1
            buf = UInt8[]
            while pos <= length(code)
                c = code[pos]
                if c == UInt8('\\')
                    pos += 1
                    pos <= length(code) || break
                    push!(buf, code[pos])
                    pos += 1
                elseif c == UInt8('"')
                    pos += 1
                    break
                else
                    push!(buf, c)
                    pos += 1
                end
            end
            push!(fields, String(buf))
        else
            start = pos
            while pos <= length(code)
                c = code[pos]
                if c == UInt8(',') || c == UInt8(')')
                    break
                end
                pos += 1
            end
            token = String(code[start:pos - 1])
            token == "" ? push!(fields, missing) : push!(fields, token)
        end
        pos <= length(code) && code[pos] == UInt8(',') && (pos += 1)
        pos <= length(code) && code[pos] == UInt8(')') && (pos += 1; break)
    end
    return fields
end

@inline function hexnibble(b::UInt8)
    if b >= UInt8('0') && b <= UInt8('9')
        return b - UInt8('0')
    elseif b >= UInt8('a') && b <= UInt8('f')
        return b - UInt8('a') + 0x0a
    elseif b >= UInt8('A') && b <= UInt8('F')
        return b - UInt8('A') + 0x0a
    end
    throw(ArgumentError("invalid hex digit in bytea"))
end

@inline function decode_bytea_escape(val::String)
    cu = codeunits(val)
    out = UInt8[]
    i = 1
    while i <= length(cu)
        b = cu[i]
        if b == UInt8('\\')
            if i == length(cu)
                push!(out, b)
                i += 1
                continue
            end
            b2 = cu[i + 1]
            if b2 == UInt8('\\')
                push!(out, UInt8('\\'))
                i += 2
                continue
            elseif b2 >= UInt8('0') && b2 <= UInt8('7')
                v = 0
                j = 0
                while j < 3 && i + 1 + j <= length(cu)
                    d = cu[i + 1 + j]
                    if d < UInt8('0') || d > UInt8('7')
                        break
                    end
                    v = (v << 3) + (d - UInt8('0'))
                    j += 1
                end
                push!(out, UInt8(v))
                i += 1 + j
                continue
            end
            push!(out, b2)
            i += 2
        else
            push!(out, b)
            i += 1
        end
    end
    return out
end

@inline function decode_bytea(val::String)
    cu = codeunits(val)
    if length(cu) >= 2 && cu[1] == UInt8('\\') && cu[2] == UInt8('x')
        hexlen = length(cu) - 2
        isodd(hexlen) && throw(ArgumentError("invalid bytea hex length"))
        out = Vector{UInt8}(undef, hexlen ÷ 2)
        i = 3
        j = 1
        while i <= length(cu)
            hi = hexnibble(cu[i])
            lo = hexnibble(cu[i + 1])
            out[j] = UInt8((hi << 4) | lo)
            i += 2
            j += 1
        end
        return out
    end
    return decode_bytea_escape(val)
end

function parse_value(typeId::Int, val::String, registry::Dict{Int, TypeInfo})
    info = type_info(registry, typeId)
    if info.parser !== nothing
        return info.parser(val, registry)
    end
    T = info.julia_type
    if T == Bool
        if typeId == 1560
            return val == "1"
        end
        return val == "t"
    elseif T == Char
        return val[1]
    elseif T == DateTime
        if typeId == 1184
            return parse_timestamptz(val)
        end
        return pg_parse_datetime(val)
    elseif T == UUID
        return UUID(val)
    elseif T == Numeric
        return parse_numeric(val)
    elseif T == Int16
        return Parsers.parse(Int16, val)
    elseif T == Int32
        return Parsers.parse(Int32, val)
    elseif T == Int64
        return Parsers.parse(Int64, val)
    elseif T == Cuint
        return Parsers.parse(Cuint, val)
    elseif T == Float32
        return Parsers.parse(Float32, val)
    elseif T == Float64
        return Parsers.parse(Float64, val)
    elseif T == Date
        return pg_parse_date(val)
    elseif T == Time
        return pg_parse_time(val)
    elseif T <: Number || T <: Dates.TimeType
        # custom numeric/time registrations must supply a parser function: a
        # runtime-Type Parsers.parse here is unresolvable under --trim
        throw(PostgresInterfaceError("no parser registered for this type; pass a parser function when registering the type"))
    elseif T == Vector{UInt8}
        return decode_bytea(val)
    elseif T == JSONType
        return JSON.lazy(val)
    elseif T <: AbstractVector
        if T == Vector{String}
            return parse_array(val, String)
        elseif T == Vector{Int16}
            return parse_array(val, Int16)
        elseif T == Vector{Int32}
            return parse_array(val, Int32)
        elseif T == Vector{Int64}
            return parse_array(val, Int64)
        elseif T == Vector{Float32}
            return parse_array(val, Float32)
        elseif T == Vector{Float64}
            return parse_array(val, Float64)
        elseif T == Vector{Bool}
            return parse_array(val, Bool)
        end
        return parse_array(val, String)
    end
    return val
end

@inline function applycast(f, name, typeId, val::String, registry::Dict{Int, TypeInfo})
    f(name, parse_value(typeId, val, registry))
    return
end

# ── typed-struct materialization: parse by the declared field type ───────────
@static if isdefined(StructUtils, :InterpClosure) && isdefined(StructUtils, :HotStructClosure)
    # Typed targets know each field type, so let their PostgresStyle lift parse
    # the wire string directly. Untyped destinations keep the OID parser above.
    @inline function applycast(f::Union{StructUtils.InterpClosure, StructUtils.HotStructClosure}, name, typeId, val::String, registry::Dict{Int, TypeInfo})
        f(name, val)
        return
    end
end

StructUtils.lift(::AbstractPostgresStyle, ::Type{Int8}, s::String) = Parsers.parse(Int8, s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Bool}, s::String) = (s == "t" || s == "1"), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Char}, s::String) = s[1], nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Int16}, s::String) = Parsers.parse(Int16, s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Int32}, s::String) = Parsers.parse(Int32, s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Int64}, s::String) = Parsers.parse(Int64, s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Cuint}, s::String) = Parsers.parse(Cuint, s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Float32}, s::String) = Parsers.parse(Float32, s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Float64}, s::String) = Parsers.parse(Float64, s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Date}, s::String) = pg_parse_date(s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Time}, s::String) = pg_parse_time(s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{DateTime}, s::String) = pg_parse_datetime_any(s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{UUID}, s::String) = UUID(s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Numeric}, s::String) = parse_numeric(s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{IntervalType}, s::String) = parse_interval(s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{UInt8}}, s::String) = decode_bytea(s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{JSONType}, s::String) = JSON.lazy(s), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{String}}, s::String) = parse_array(s, String), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{Int16}}, s::String) = parse_array(s, Int16), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{Int32}}, s::String) = parse_array(s, Int32), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{Int64}}, s::String) = parse_array(s, Int64), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{Float32}}, s::String) = parse_array(s, Float32), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{Float64}}, s::String) = parse_array(s, Float64), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{Bool}}, s::String) = parse_array(s, Bool), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{Date}}, s::String) = parse_array(s, Date), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{Time}}, s::String) = parse_array(s, Time), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{DateTime}}, s::String) = parse_array(s, DateTime), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{UUID}}, s::String) = parse_array(s, UUID), nothing
StructUtils.lift(::AbstractPostgresStyle, ::Type{Vector{Numeric}}, s::String) = parse_array(s, Numeric), nothing

# For array-typed fields the generic `make` takes its arraylike branch (applyeach
# over the source) before consulting lifts — but our source is the wire STRING,
# which must be parsed, not iterated. Route (String source → AbstractVector target)
# through the lifts above.
StructUtils.make(st::AbstractPostgresStyle, ::Type{T}, s::String) where {T <: AbstractVector} = StructUtils.lift(st, T, s)
StructUtils.make(st::AbstractPostgresStyle, ::Type{T}, s::String, tags) where {T <: AbstractVector} = StructUtils.lift(st, T, s)
