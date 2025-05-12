const JSONType = typeof(JSON.lazy("1"))

@inline function juliatype(f, oid)
    if oid == 23
        return f(Int32)
    elseif oid == 26
        return f(Cuint)
    elseif oid == 20
        return f(Int64)
    elseif oid == 21
        return f(Int16)
    elseif oid == 16
        return f(Bool)
    elseif oid == 3802 || oid == 3807 || oid == 114 || oid == 199
        return f(JSONType)
    elseif oid == 25 || oid == 1043 || oid == 1042 || oid == 24 || oid == 19
        return f(String)
    elseif oid == 2950
        return f(UUID)
    elseif oid == 700
        return f(Float32)
    elseif oid == 701
        return f(Float64)
    elseif oid == 1700
        # return f(Dec64)
        return f(Float64)
    elseif oid == 1114
        return f(DateTime)
    elseif oid == 1184
        # timestamp with time zone
        #TODO: string for now
        return f(String)
    elseif oid == 1082
        return f(Date)
    elseif oid == 1083
        return f(Time)
    elseif oid == 17
        return f(Vector{UInt8})
    elseif oid == 18
        # char
        return f(Char) #??
    elseif oid == 114
        # return f(JSON)
        return f(String)
    elseif oid == 3802
        # return f(JSONB)
        return f(String)
    elseif oid == 1560
        # return f(Bit)
        return f(Bool)
    else
        # @warn "unsupported type oid $oid"
        return f(String)
    end
end

const DATETIME_OPTIONS = Parsers.Options(dateformat=dateformat"yyyy-mm-dd HH:MM:SS.s")

@inline function applycast(f, name, typeId, val::String)
    juliatype(typeId) do T
        if T == Bool
            f(name, val == "t")
        elseif T == Char
            f(name, val[1])
        elseif T == DateTime
            f(name, Parsers.parse(T, SubString(val, 1, min(23, sizeof(val))), DATETIME_OPTIONS))
        elseif T <: Number || T <: Dates.TimeType
            f(name, Parsers.parse(T, val))
        elseif T == Vector{UInt8}
            f(name, unsafe_wrap(Vector{UInt8}, pointer(val), sizeof(val)))
        elseif T == JSONType
            f(name, JSON.lazy(val))
        else
            # fallback
            f(name, val)
        end
        return
    end
    return
end
