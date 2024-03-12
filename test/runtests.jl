using Test, Dates, Postgres, DBInterface, Tables, Structs

Structs.@defaults struct Region
    region_id::Int = 0
    name::String = ""
    position::Int = 0
    region_type::Int = 0
    phone_prefix::Int = 0
    iso31661a2::String = ""
    iso31661a3::String = ""
    iso31662::String = ""
    parent_region_id::Union{Nothing, Int} = nothing
    created_at::DateTime = DateTime(0)
    created_by::Int = 0
    modified_at::DateTime = DateTime(0)
    modified_by::Int = 0
end

@noarg mutable struct Region2
    region_id::Int
    name::String
    position::Int
    region_type::Int
    phone_prefix::Int
    iso31661a2::String
    iso31661a3::String
    iso31662::String
    parent_region_id::Union{Nothing, Int}
    created_at::DateTime
    created_by::Int
    modified_at::DateTime
    modified_by::Int
end

@testset "Postgres" begin
    # requires postgres to be running
    conn = DBInterface.connect(Postgres.Connection, "localhost", "postgres", "admin"; dbname="postgres")
    @test isopen(conn)
    DBInterface.close!(conn)
    DBInterface.close!(conn)
    @test !isopen(conn)
    conn = DBInterface.connect(Postgres.Connection, "localhost", "postgres", "admin"; dbname="postgres")
    res = DBInterface.execute(conn, "SELECT 1 as a;") |> Tables.rowtable
    @test res[1].a == 1

    DBInterface.execute(conn, "DROP TABLE IF EXISTS __region__")
    res = DBInterface.execute(conn, """
    CREATE TABLE __region__ (
        region_id SERIAL PRIMARY KEY,
        name VARCHAR(45) NOT NULL,
        position INTEGER DEFAULT 5 NOT NULL,
        region_type SMALLINT DEFAULT 1 NOT NULL,
        phone_prefix INTEGER,
        ISO31661A2 CHAR(2),
        ISO31661A3 CHAR(3),
        ISO31662 VARCHAR(6),
        parent_region_id INTEGER,
        created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_by BIGINT,
        modified_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        modified_by BIGINT
    );
    """)
    @test isempty(res)

    DBInterface.execute(conn, "DELETE FROM __region__")
    stmt = DBInterface.prepare(conn, """
    INSERT INTO __region__ (
        name,
        position,
        region_type,
        phone_prefix,
        ISO31661A2,
        ISO31661A3,
        ISO31662,
        parent_region_id,
        created_at,
        created_by,
        modified_at,
        modified_by
    ) VALUES (\$1, \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$12) RETURNING region_id
    """)
    params = (
        name="__test__",
        position=1,
        region_type=2,
        phone_prefix=3,
        iso31661a2="aa",
        iso31661a3="bbb",
        iso31662="abcdef",
        parent_region_id=missing,
        created_at=DateTime(2024, 1, 28, 21, 30),
        created_by=100,
        modified_at="2024-02-13 05:28:17.756152",
        modified_by=100,
    )
    res = DBInterface.execute(stmt, params)
    @test length(res) == 1
    @test res[1].region_id isa Integer
    region_id = res[1].region_id
    res = DBInterface.execute(conn, "SELECT * FROM __region__") |> Tables.rowtable
    @test isequal(Base.setindex(res[1], params.modified_at, :modified_at), (; region_id, params...))

    # kwdef struct materialization
    res = DBInterface.execute(conn, "SELECT * FROM __region__", (), Region)
    @test res.region_id == region_id
    # mutable struct materialization
    res = DBInterface.execute(conn, "SELECT * FROM __region__", (), Region2)
    @test res.region_id == region_id
end