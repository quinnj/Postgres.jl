using Documenter, Postgres

makedocs(modules = [Postgres], sitename = "Postgres.jl")

deploydocs(repo = "github.com/quinnj/Postgres.jl.git", push_preview = true)
