using Test

const _POSTGRES_TRIM_SUPPORTED = VERSION >= v"1.12.0-rc1"
const _POSTGRES_TRIM_PRE_RELEASE = !isempty(VERSION.prerelease)
const _POSTGRES_JULIAC_ENTRYPOINT_EXPR = "using JuliaC; if isdefined(JuliaC, :main); JuliaC.main(ARGS); else JuliaC._main_cli(ARGS); end"

function _postgres_trim_compile_timeout_s()::Float64
    default = Sys.iswindows() ? "1200.0" : "180.0"
    return parse(Float64, get(ENV, "POSTGRES_TRIM_COMPILE_TIMEOUT_S", default))
end

function _postgres_trim_error_budget()::Int
    return parse(Int, get(ENV, "POSTGRES_TRIM_ERROR_BUDGET", "66"))
end

function _postgres_trim_project_path()::String
    active_project = Base.active_project()
    if active_project !== nothing && isfile(active_project)
        return dirname(active_project)
    end
    return normpath(joinpath(@__DIR__, ".."))
end

function _postgres_trim_env(cfg)
    run_env = copy(ENV)
    run_env["POSTGRES_TRIM_HOST"] = cfg.host
    run_env["POSTGRES_TRIM_PORT"] = string(cfg.port)
    run_env["POSTGRES_TRIM_USER"] = cfg.user
    run_env["POSTGRES_TRIM_DBNAME"] = cfg.dbname
    return run_env
end

function _run_postgres_trim_compile(project_path::String, script_path::String, output_name::String; timeout_s::Float64 = _postgres_trim_compile_timeout_s(), bundle_dir::Union{Nothing, String} = nothing)
    julia_exe = joinpath(Sys.BINDIR, Base.julia_exename())
    cmd = if bundle_dir === nothing
        `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$project_path -e $(_POSTGRES_JULIAC_ENTRYPOINT_EXPR) -- --output-exe $output_name --project=$project_path --experimental --trim=safe $script_path`
    else
        `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$project_path -e $(_POSTGRES_JULIAC_ENTRYPOINT_EXPR) -- --output-exe $output_name --bundle $bundle_dir --project=$project_path --experimental --trim=safe $script_path`
    end
    compile_env = copy(ENV)
    compile_env["RESEAU_PRECOMPILE_ONLY"] = get(ENV, "POSTGRES_TRIM_RESEAU_PRECOMPILE_ONLY", "tcp")
    cmd = setenv(cmd, compile_env)
    return _run_postgres_trim_command_with_timeout(cmd; timeout_s = timeout_s, log_label = "compile")
end

function _run_postgres_trim_executable(run_cmd::Cmd; timeout_s::Float64 = 30.0)
    return _run_postgres_trim_command_with_timeout(run_cmd; timeout_s = timeout_s, log_label = "run")
end

function _run_postgres_trim_command_with_timeout(cmd::Cmd; timeout_s::Float64, log_label::String)
    output_path = tempname()
    out = open(output_path, "w")
    exit_code = -1
    timed_out = false
    try
        proc = run(pipeline(ignorestatus(cmd), stdout = out, stderr = out); wait = false)
        timed_out = _wait_postgres_trim_process_with_timeout!(proc; timeout_s = timeout_s, log_label = log_label)
        exit_code = something(proc.exitcode, -1)
    finally
        close(out)
    end
    output = try
        read(output_path, String)
    catch
        ""
    finally
        rm(output_path; force = true)
    end
    return exit_code, output, timed_out
end

function _wait_postgres_trim_process_with_timeout!(proc::Base.Process; timeout_s::Float64, log_label::String)
    started_at = time()
    next_log_at = started_at + 10.0
    timed_out = false
    while Base.process_running(proc)
        now = time()
        if now - started_at >= timeout_s
            timed_out = true
            try
                kill(proc)
            catch
            end
            _kill_postgres_trim_windows_process_tree!(proc)
            _wait_postgres_trim_process_exit_after_kill!(proc; timeout_s = 5.0, log_label = log_label)
            return timed_out
        end
        if now >= next_log_at
            elapsed = round(now - started_at; digits = 1)
            println("[trim] $(log_label) WAIT $(elapsed)s")
            flush(stdout)
            next_log_at = now + 10.0
        end
        sleep(0.1)
    end
    if !Base.process_running(proc)
        try
            wait(proc)
        catch
        end
    end
    return timed_out
end

function _kill_postgres_trim_windows_process_tree!(proc::Base.Process)::Nothing
    Sys.iswindows() || return nothing
    pid = try
        getpid(proc)
    catch
        return nothing
    end
    try
        run(ignorestatus(`taskkill /PID $pid /T /F`))
    catch
    end
    return nothing
end

function _wait_postgres_trim_process_exit_after_kill!(proc::Base.Process; timeout_s::Float64, log_label::String)::Nothing
    deadline = time() + timeout_s
    while Base.process_running(proc) && time() < deadline
        sleep(0.1)
    end
    if Base.process_running(proc)
        println("[trim] $(log_label) process still running after kill; continuing after timeout")
        flush(stdout)
    end
    return nothing
end

function _postgres_trim_timeout_error(kind::String, script_file::String, output::String = "")
    msg = "trim $kind timed out for $(script_file)"
    if !isempty(output)
        msg = string(msg, "\n---- captured output ----\n", output, "\n---- end captured output ----")
    end
    throw(ArgumentError(msg))
end

function _maybe_print_postgres_trim_output(header::String, output::String)
    isempty(output) && return nothing
    println(header)
    println(output)
    println("---- end output ----")
    return nothing
end

function _postgres_trim_executable_timeout_s()::Float64
    default = Sys.iswindows() ? "180.0" : "30.0"
    return parse(Float64, get(ENV, "POSTGRES_TRIM_EXE_TIMEOUT_S", default))
end

function _postgres_trim_selected_workloads(workloads::Vector{Tuple{String, String}})::Vector{Tuple{String, String}}
    only = strip(get(ENV, "POSTGRES_TRIM_ONLY", ""))
    isempty(only) && return workloads
    selected = Tuple{String, String}[]
    for workload in workloads
        workload[1] == only && push!(selected, workload)
    end
    isempty(selected) && throw(ArgumentError("unknown POSTGRES_TRIM_ONLY workload: $(only)"))
    return selected
end

function _postgres_trim_use_bundle()::Bool
    return get(ENV, "POSTGRES_TRIM_BUNDLE", "0") == "1"
end

function _parse_postgres_trim_verify_totals(output::String)
    m = match(r"Trim verify finished with\s+(\d+)\s+errors,\s+(\d+)\s+warnings\.", output)
    m === nothing && return nothing
    return parse(Int, m.captures[1]), parse(Int, m.captures[2])
end

function _count_postgres_trim_verify_messages(output::String)::Tuple{Int,Int}
    errors = length(collect(eachmatch(r"Verifier error #\d+:", output)))
    warnings = length(collect(eachmatch(r"Verifier warning #\d+:", output)))
    return errors, warnings
end

function _run_postgres_trim_case(cfg, project_path::String, script_file::String, output_name::String)
    script_path = joinpath(@__DIR__, script_file)
    @test isfile(script_path)
    println("[trim] compile START $(script_file)")
    start_t = time()
    mktempdir() do tmpdir
        cd(tmpdir) do
            bundle_dir = _postgres_trim_use_bundle() ? joinpath(tmpdir, "bundle") : nothing
            exit_code, output, timed_out = _run_postgres_trim_compile(project_path, script_path, output_name; bundle_dir = bundle_dir)
            if timed_out
                _postgres_trim_timeout_error("compile", script_file, output)
            end
            totals = _parse_postgres_trim_verify_totals(output)
            trim_errors, trim_warnings = if totals === nothing
                fallback = _count_postgres_trim_verify_messages(output)
                if exit_code != 0 && fallback == (0, 0)
                    error("failed to parse trim verifier summary:\n$output")
                end
                fallback
            else
                totals
            end
            trim_error_budget = _postgres_trim_error_budget()
            println("[trim] verifier $(script_file): errors=$(trim_errors) warnings=$(trim_warnings) budget=$(trim_error_budget)")
            if get(ENV, "POSTGRES_TRIM_PRINT_OUTPUT", "0") == "1" || trim_errors > trim_error_budget || trim_warnings > 0
                _maybe_print_postgres_trim_output("---- trim compile output ($(script_file)) ----", output)
            end
            @test trim_errors <= trim_error_budget
            @test trim_warnings == 0
            if trim_errors > 0
                @test exit_code != 0
                println("[trim] executable skipped for $(script_file): verifier errors remain")
                return nothing
            end
            output_path = Sys.iswindows() ? "$(output_name).exe" : output_name
            run_path = bundle_dir === nothing ? output_path : joinpath(bundle_dir, "bin", output_path)
            @test exit_code == 0
            @test isfile(run_path)
            run_cmd = setenv(`$(abspath(run_path))`, _postgres_trim_env(cfg))
            run_timeout_s = _postgres_trim_executable_timeout_s()
            run_exit, run_output, run_timed_out = _run_postgres_trim_executable(run_cmd; timeout_s = run_timeout_s)
            if run_timed_out
                _postgres_trim_timeout_error("executable run", script_file, run_output)
            end
            if run_exit != 0
                _maybe_print_postgres_trim_output("---- trim executable output ($(script_file)) ----", run_output)
            end
            @test run_exit == 0
        end
    end
    println("[trim] compile DONE $(script_file) ($(round(time() - start_t; digits = 2))s)")
    return nothing
end

function run_postgres_trim_compile_tests(cfg)::Nothing
    @testset "Trim Compile" begin
        if Sys.iswindows()
            println("[trim] skip Windows: JuliaC trim compilation is currently too slow or stalls on Windows CI")
            @test true
        elseif !_POSTGRES_TRIM_SUPPORTED
            println("[trim] skip Julia < 1.12: JuliaC trim compilation is unavailable")
            @test true
        elseif _POSTGRES_TRIM_PRE_RELEASE
            println("[trim] skip prerelease Julia: trim verifier behavior is not stable yet")
            @test true
        elseif !(occursin("trust", DEFAULT_AUTH) || occursin("trust", DEFAULT_INITDB_ARGS))
            println("[trim] skip non-trust auth mode: main CI covers trim once, auth-mode jobs focus on authentication")
            @test true
        else
            project_path = _postgres_trim_project_path()
            println("[trim] project $(project_path)")
            trim_workloads = [
                ("postgres_trim_queries.jl", "postgres_trim_queries"),
            ]
            trim_workloads = _postgres_trim_selected_workloads(trim_workloads)
            for (script_file, output_name) in trim_workloads
                _run_postgres_trim_case(cfg, project_path, script_file, output_name)
            end
        end
    end
    return nothing
end
