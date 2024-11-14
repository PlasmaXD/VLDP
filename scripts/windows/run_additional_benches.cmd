@echo off

for /f "delims=" %%i in ('powershell get-date -format "{yyyy-MM-dd--HH-mm-ss}"') do set datetime=%%i

@REM Make parameter directory
if not exist .\benches\parameters mkdir .\benches\parameters

echo ALL BENCHES

@REM Specify number of warmup and measurement runs
echo 3 > .\benches\parameters\n_warmup
echo 100 > .\benches\parameters\n_measure

@REM For all benches
for %%r in (32, 64, 128, 256, 512, 1024) do (
    @REM Make output directory
    if not exist ".\results\raw\additional_benches\r_%%r" mkdir ".\results\raw\additional_benches\r_%%r"

    @REM Write parameters
    echo 8 > .\benches\parameters\input_bytes
    echo 8 > .\benches\parameters\gamma_bytes
    echo 8 > .\benches\parameters\time_bytes
    echo 4 > .\benches\parameters\mt_depth
    echo %%r > .\benches\parameters\randomness_bytes

    echo r=%%r

    @REM Run benches
    echo Running base_histogram [1/6]
    cargo bench --bench base_histogram --features print-trace > .\results\raw\additional_benches\r_%%r\%datetime%_bench_base_histogram.txt 2>&1

    echo Running expand_histogram [2/6]
    cargo bench --bench expand_histogram --features print-trace > .\results\raw\additional_benches\r_%%r\%datetime%_bench_expand_histogram.txt 2>&1

    echo Running shuffle_histogram [3/6]
    cargo bench --bench shuffle_histogram --features print-trace > .\results\raw\additional_benches\r_%%r\%datetime%_bench_shuffle_histogram.txt 2>&1

    echo Running base_real [4/6]
    cargo bench --bench base_real --features print-trace > .\results\raw\additional_benches\r_%%r\%datetime%_bench_base_real.txt 2>&1

    echo Running expand_real [5/6]
    cargo bench --bench expand_real --features print-trace > .\results\raw\additional_benches\r_%%r\%datetime%_bench_expand_real.txt 2>&1

    echo Running shuffle_real [6/6]
    cargo bench --bench shuffle_real --features print-trace > .\results\raw\additional_benches\r_%%r\%datetime%_bench_shuffle_real.txt 2>&1

    @REM Clear parameters
    del .\benches\parameters\input_bytes
    del .\benches\parameters\gamma_bytes
    del .\benches\parameters\time_bytes
    del .\benches\parameters\mt_depth
    del .\benches\parameters\randomness_bytes
)

echo EXPAND BENCHES ONLY

@REM Expand benches only
for %%m in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11) do (

    @REM Make output directory
    if not exist ".\results\raw\additional_benches\m_%%m" mkdir ".\results\raw\additional_benches\m_%%m"

    @REM Write parameters
    echo 8 > .\benches\parameters\input_bytes
    echo 8 > .\benches\parameters\gamma_bytes
    echo 8 > .\benches\parameters\time_bytes
    echo %%m > .\benches\parameters\mt_depth

    echo m=%%m

    @REM Run benches

    echo 16 > .\benches\parameters\randomness_bytes

    echo Running expand_histogram [1/2]
    cargo bench --bench expand_histogram --features print-trace > .\results\raw\additional_benches\m_%%m\%datetime%_bench_expand_histogram.txt 2>&1

    del .\benches\parameters\randomness_bytes
    echo 24 > .\benches\parameters\randomness_bytes

    echo Running expand_real [2/2]
    cargo bench --bench expand_real --features print-trace > .\results\raw\additional_benches\m_%%m\%datetime%_bench_expand_real.txt 2>&1

    @REM Clear parameters
    del .\benches\parameters\input_bytes
    del .\benches\parameters\gamma_bytes
    del .\benches\parameters\time_bytes
    del .\benches\parameters\mt_depth
    del .\benches\parameters\randomness_bytes
)

@REM Remove parameter directory
del .\benches\parameters\n_warmup
del .\benches\parameters\n_measure
rmdir .\benches\parameters

echo Parsing results
python .\scripts\parse_additional_bench_results.py %datetime%

echo Making plots
python .\scripts\make_plots.py %datetime%