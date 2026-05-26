using Documenter, Postgres

makedocs(modules = [Postgres], sitename = "Postgres.jl")

if get(ENV, "POSTGRES_DOCS_DEPLOY", "false") == "true"
    deploydocs(repo = "github.com/quinnj/Postgres.jl.git", push_preview = true)
end
