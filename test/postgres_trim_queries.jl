using Dates
using DBInterface
using Postgres
using StructUtils
using UUIDs

struct TrimId
    profile_id::Int32
end

struct TrimCount
    count::Int32
end

struct TrimName
    display_name::String
end

StructUtils.@tags struct TrimProfile
    profileId::Int32 &(postgres=(name=:profile_id,),)
    displayName::String &(postgres=(name=:display_name,),)
    createdAt::DateTime &(postgres=(name=:created_at,),)
    active::Bool
    score::Union{Missing, Int32}
    uid::UUID
    flags::Vector{Int32}
end

function _postgres_trim_connect()
    host = get(ENV, "POSTGRES_TRIM_HOST", "127.0.0.1")
    port = parse(Int, get(ENV, "POSTGRES_TRIM_PORT", "5432"))
    user = get(ENV, "POSTGRES_TRIM_USER", "postgres")
    dbname = get(ENV, "POSTGRES_TRIM_DBNAME", "postgres")
    return DBInterface.connect(
        Postgres.Connection,
        host,
        user,
        nothing;
        dbname=dbname,
        port=port,
        sslmode="disable",
        connect_timeout=2,
        application_name="postgres_trim",
        statement_cache_maxsize=4,
    )
end

function _assert_trim_profile(profile::TrimProfile, id::Int32, name::String)::Nothing
    profile.profileId == id || error("unexpected profile id")
    profile.displayName == name || error("unexpected profile name")
    profile.active || error("expected active profile")
    profile.uid == UUID("12345678-1234-5678-1234-567812345678") || id != 1 || error("unexpected UUID")
    !isempty(profile.flags) || error("expected non-empty flags array")
    return nothing
end

function run_postgres_trim_queries()::Nothing
    conn = _postgres_trim_connect()
    try
        DBInterface.execute(conn, """
            CREATE TEMP TABLE trim_compile_profiles (
                profile_id integer PRIMARY KEY,
                display_name text NOT NULL,
                created_at timestamp NOT NULL,
                active boolean NOT NULL,
                score integer,
                uid uuid NOT NULL,
                flags integer[] NOT NULL
            )
            """)

        insert_sql = raw"""
            INSERT INTO trim_compile_profiles (
                profile_id,
                display_name,
                created_at,
                active,
                score,
                uid,
                flags
            ) VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7::integer[]
            )
            RETURNING profile_id
            """

        first_id = DBInterface.execute(
            conn,
            insert_sql,
            (
                Int32(1),
                "Ada",
                DateTime(2024, 1, 2, 3, 4, 5),
                true,
                Int32(99),
                UUID("12345678-1234-5678-1234-567812345678"),
                Int32[1, 2, 3],
            ),
            TrimId,
        )
        first_id.profile_id == 1 || error("unexpected inserted id")

        DBInterface.transaction(conn) do
            DBInterface.execute(
                conn,
                insert_sql,
                (
                    Int32(2),
                    "Grace",
                    DateTime(2024, 1, 3, 4, 5, 6),
                    true,
                    missing,
                    UUID("87654321-4321-8765-4321-876543218765"),
                    Int32[4, 5],
                ),
            )
        end

        stmt = DBInterface.prepare(conn, raw"""
            SELECT profile_id, display_name, created_at, active, score, uid, flags
            FROM trim_compile_profiles
            WHERE profile_id = $1
            """)
        try
            profile = DBInterface.execute(stmt, (Int32(1),), TrimProfile)
            _assert_trim_profile(profile, Int32(1), "Ada")
        finally
            DBInterface.close!(stmt)
        end

        profiles = DBInterface.execute(conn, """
            SELECT profile_id, display_name, created_at, active, score, uid, flags
            FROM trim_compile_profiles
            ORDER BY profile_id
            """, (), Vector{TrimProfile})
        length(profiles) == 2 || error("expected two profiles")
        _assert_trim_profile(profiles[2], Int32(2), "Grace")

        count_row = DBInterface.execute(
            conn,
            "SELECT count(*)::integer AS count FROM trim_compile_profiles",
            (),
            TrimCount,
        )
        count_row.count == 2 || error("unexpected typed count")

        name_row = DBInterface.execute(
            conn,
            "SELECT display_name FROM trim_compile_profiles WHERE profile_id = 1",
            (),
            TrimName,
        )
        name_row.display_name == "Ada" || error("unexpected typed name")

        update_result = DBInterface.execute(conn, "UPDATE trim_compile_profiles SET score = coalesce(score, 0) + 1")
        Postgres.rows_affected(update_result) == 2 || error("unexpected rows affected")
        occursin("UPDATE", Postgres.command_tag(update_result)) || error("unexpected command tag")
    finally
        DBInterface.close!(conn)
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_postgres_trim_queries()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
