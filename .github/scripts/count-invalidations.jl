import Pkg

package_name = get(ENV, "PACKAGE_NAME", "Postgres")
test_script = get(ENV, "TEST_SCRIPT", "import $package_name")

Pkg.activate(; temp=true)
Pkg.develop(Pkg.PackageSpec(path=pwd()))
Pkg.add([
    Pkg.PackageSpec(name="SnoopCompile", version="3", uuid="aa65fe97-06da-5843-b5b1-d5d13cad87d2"),
    Pkg.PackageSpec(name="SnoopCompileCore", uuid="e2b509da-e806-4183-be48-004708413034"),
    Pkg.PackageSpec(name="PrettyTables", uuid="08abe8d2-0d0c-5749-adfa-8a2ac140af0d"),
])

using SnoopCompileCore: @snoop_invalidations

invalidations = @snoop_invalidations begin
    Base.include_string(Main, test_script)
end

using SnoopCompile: SnoopCompile, filtermod, invalidation_trees, uinvalidated
package_module = getfield(Main, Symbol(package_name))
inv_owned = length(filtermod(package_module, invalidation_trees(invalidations)))
inv_total = length(uinvalidated(invalidations))
inv_deps = inv_total - inv_owned

@show inv_total inv_deps

import PrettyTables
SnoopCompile.report_invalidations(;
    invalidations,
    process_filename=x -> last(split(x, ".julia/packages/")),
    n_rows=parse(Int, get(ENV, "MAX_INVALIDATIONS", "0")),
)

using Printf
open(ENV["GITHUB_OUTPUT"], "a") do io
    println(io, @sprintf("total=%09d", inv_total))
    println(io, @sprintf("deps=%09d", inv_deps))
end
