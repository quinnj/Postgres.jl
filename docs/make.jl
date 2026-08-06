using Documenter, Postgres

makedocs(
    modules = [Postgres],
    sitename = "Postgres.jl",
    pages = [
        "Home" => "index.md",
        "Manual" => "manual.md",
        "Support Policy" => "support.md",
    ],
)

if get(ENV, "POSTGRES_DOCS_DEPLOY", "false") == "true"
    deploydocs(repo = "github.com/JuliaDatabases/Postgres.jl.git", push_preview = true)
end
