const JSONType = typeof(JSON.lazy("1"))

struct Numeric
    coeff::BigInt
    scale::Int
end

Base.:(==)(a::Numeric, b::Numeric) = a.coeff == b.coeff && a.scale == b.scale

struct PostgresRange{T}
    lower::Union{T, Missing}
    upper::Union{T, Missing}
    lower_inclusive::Bool
    upper_inclusive::Bool
    empty::Bool
end

struct TypeInfo
    julia_type::Type
    parser::Union{Function, Nothing}
end

const IntervalType = Union{Dates.Period, Dates.CompoundPeriod}

const DEFAULT_TYPE_REGISTRY = Dict{Int, TypeInfo}(
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
)

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

const DATETIME_OPTIONS = Parsers.Options(dateformat=dateformat"yyyy-mm-dd HH:MM:SS.s")

@inline function tzoffset_seconds(offset::AbstractString)
    isempty(offset) && return 0
    sign = offset[1] == '-' ? -1 : 1
    digits = replace(String(offset[2:end]), ":" => "")
    isempty(digits) && return 0
    hours = parse(Int, digits[1:2])
    mins = length(digits) >= 4 ? parse(Int, digits[3:4]) : 0
    return sign * (hours * 3600 + mins * 60)
end

@inline function parse_timestamptz(val::String)
    lastindex(val) == 0 && return Parsers.parse(DateTime, val, DATETIME_OPTIONS)
    if val[end] == 'Z'
        ts = SubString(val, 1, prevind(val, lastindex(val)))
        return Parsers.parse(DateTime, ts, DATETIME_OPTIONS)
    end
    space_idx = findfirst(isequal(' '), val)
    space_idx === nothing && return Parsers.parse(DateTime, val, DATETIME_OPTIONS)
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
    offset_idx === nothing && return Parsers.parse(DateTime, val, DATETIME_OPTIONS)
    ts = SubString(val, 1, prevind(val, offset_idx))
    dt = Parsers.parse(DateTime, ts, DATETIME_OPTIONS)
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
        frac = rpad(frac[1:min(end, 3)], 3, '0')
        milliseconds = parse(Int, frac)
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
    return Dates.CompoundPeriod(periods...)
end

function split_range_values(val::String)
    code = codeunits(val)
    pos = 1
    in_quotes = false
    for i in 1:length(code)
        c = code[i]
        if c == UInt8('"')
            in_quotes = !in_quotes
        elseif c == UInt8(',') && !in_quotes
            pos = i
            break
        end
    end
    pos == 1 && return val, ""
    left = String(code[1:pos - 1])
    right = String(code[pos + 1:end])
    return left, right
end

function parse_range_value(token::String, typeId::Int, registry::Dict{Int, TypeInfo})
    token == "" && return missing
    return parse_value(typeId, token, registry)
end

function parse_range(val::String, typeId::Int, registry::Dict{Int, TypeInfo})
    lowercase(val) == "empty" && return PostgresRange{type_info(registry, typeId).julia_type}(missing, missing, false, false, true)
    lower_inclusive = val[1] == '['
    upper_inclusive = val[end] == ']'
    inner = val[2:end - 1]
    left, right = split_range_values(inner)
    lower = parse_range_value(left, typeId, registry)
    upper = parse_range_value(right, typeId, registry)
    T = type_info(registry, typeId).julia_type
    return PostgresRange{T}(lower, upper, lower_inclusive, upper_inclusive, false)
end

parse_array_scalar(typeId::Int, registry::Dict{Int, TypeInfo}, value::Missing) = missing
parse_array_scalar(typeId::Int, registry::Dict{Int, TypeInfo}, value::AbstractVector) = [parse_array_scalar(typeId, registry, v) for v in value]
parse_array_scalar(typeId::Int, registry::Dict{Int, TypeInfo}, value::AbstractString) = parse_value(typeId, String(value), registry)

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
        return Parsers.parse(T, val, DATETIME_OPTIONS)
    elseif T == UUID
        return UUID(val)
    elseif T == Numeric
        return parse_numeric(val)
    elseif T <: Number || T <: Dates.TimeType
        return Parsers.parse(T, val)
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
