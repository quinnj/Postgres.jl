module ArrayParsing

using Parsers, Dates, UUIDs
import ..pg_parse_date, ..pg_parse_time, ..pg_parse_datetime_any, ..parse_numeric, ..Numeric

const BRACKET_OPEN = UInt8('[')
const BRACKET_CLOSE = UInt8(']')
const BRACE_OPEN = UInt8('{')
const BRACE_CLOSE = UInt8('}')
const COMMA = UInt8(',')
const QUOTE = UInt8('"')
const BACKSLASH = UInt8('\\')
const NULL_STR = "NULL"
const SPACE = UInt8(' ')
const TAB = UInt8('\t')
const NEWLINE = UInt8('\n')
const CARRIAGE_RETURN = UInt8('\r')

is_ws(c::UInt8) = c == SPACE || c == TAB || c == NEWLINE || c == CARRIAGE_RETURN

function skip_ws(code::Base.CodeUnits{UInt8, String}, pos::Ref{Int})
    while pos[] <= length(code) && is_ws(code[pos[]])
        pos[] += 1
    end
    return
end

function parse_quoted(code::Base.CodeUnits{UInt8, String}, pos::Ref{Int})
    pos[] += 1
    buf = UInt8[]
    while pos[] <= length(code)
        c = code[pos[]]
        if c == BACKSLASH
            pos[] += 1
            pos[] <= length(code) || break
            push!(buf, code[pos[]])
            pos[] += 1
        elseif c == QUOTE
            pos[] += 1
            return String(buf)
        else
            push!(buf, c)
            pos[] += 1
        end
    end
    return String(buf)
end

function parse_unquoted(code::Base.CodeUnits{UInt8, String}, pos::Ref{Int})
    buf = UInt8[]
    while pos[] <= length(code)
        c = code[pos[]]
        if c == COMMA || c == BRACE_CLOSE || c == BRACKET_CLOSE
            break
        elseif c == BACKSLASH
            pos[] += 1
            pos[] <= length(code) || break
            push!(buf, code[pos[]])
            pos[] += 1
        else
            push!(buf, c)
            pos[] += 1
        end
    end
    return String(strip(String(buf)))
end

function parse_bool_token(token::String)
    lowered = lowercase(token)
    lowered == "t" && return true
    lowered == "true" && return true
    lowered == "1" && return true
    lowered == "f" && return false
    lowered == "false" && return false
    lowered == "0" && return false
    throw(ArgumentError("invalid boolean token: $token"))
end

function parse_scalar(token::String, inner_type::Type{T}, quoted::Bool) where {T}
    !quoted && token == NULL_STR && return missing
    inner_type === String && return token
    inner_type === Bool && return parse_bool_token(token)
    inner_type === Int16 && return Parsers.parse(Int16, token)
    inner_type === Int32 && return Parsers.parse(Int32, token)
    inner_type === Int64 && return Parsers.parse(Int64, token)
    inner_type === Float32 && return Parsers.parse(Float32, token)
    inner_type === Float64 && return Parsers.parse(Float64, token)
    inner_type === Date && return pg_parse_date(token)
    inner_type === Time && return pg_parse_time(token)
    inner_type === DateTime && return pg_parse_datetime_any(token)
    inner_type === UUID && return UUID(token)
    inner_type === Numeric && return parse_numeric(token)
    return token
end

function coerce_array(values::Vector{Any}, inner_type::Type{T}) where {T}
    isempty(values) && return inner_type[]
    has_nested = false
    has_missing = false
    for value in values
        value isa AbstractVector && (has_nested = true; break)
        value === missing && (has_missing = true)
    end
    has_nested && return values
    if has_missing
        dest = Union{inner_type, Missing}[]
        sizehint!(dest, length(values))
        for value in values
            if value === missing
                push!(dest, value)
            elseif value isa inner_type
                push!(dest, value)
            else
                return values
            end
        end
        return dest
    end
    dest = inner_type[]
    sizehint!(dest, length(values))
    for value in values
        value isa inner_type || return values
        push!(dest, value)
    end
    return dest
end

function parse_array_value(code::Base.CodeUnits{UInt8, String}, pos::Ref{Int}, inner_type::Type{T}) where {T}
    c = code[pos[]]
    if c == BRACE_OPEN || c == BRACKET_OPEN
        return parse_array_inner(code, pos, inner_type)
    elseif c == QUOTE
        token = parse_quoted(code, pos)
        return parse_scalar(token, inner_type, true)
    else
        token = parse_unquoted(code, pos)
        return parse_scalar(token, inner_type, false)
    end
end

function parse_array_inner(code::Base.CodeUnits{UInt8, String}, pos::Ref{Int}, inner_type::Type{T}) where {T}
    values = Any[]
    pos[] += 1
    while pos[] <= length(code)
        skip_ws(code, pos)
        pos[] > length(code) && break
        c = code[pos[]]
        if c == BRACE_CLOSE || c == BRACKET_CLOSE
            pos[] += 1
            break
        end
        value = parse_array_value(code, pos, inner_type)
        push!(values, value)
        skip_ws(code, pos)
        if pos[] <= length(code) && code[pos[]] == COMMA
            pos[] += 1
        end
    end
    return coerce_array(values, inner_type)
end

function parse_array(str::String, inner_type::Type{T}) where {T}
    code = codeunits(str)
    pos = Ref{Int}(1)
    skip_ws(code, pos)
    if pos[] > length(code)
        return inner_type[]
    end
    c = code[pos[]]
    if c == BRACE_OPEN || c == BRACKET_OPEN
        return parse_array_inner(code, pos, inner_type)
    end
    value = parse_scalar(str, inner_type, true)
    return coerce_array(Any[value], inner_type)
end

export parse_array

end
