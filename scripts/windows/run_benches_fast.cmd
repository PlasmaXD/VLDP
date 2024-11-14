@echo off

if not exist .\benches\parameters mkdir .\benches\parameters

@REM Specify number of warmup and measurement runs
echo 1 > .\benches\parameters\n_warmup
echo 10 > .\benches\parameters\n_measure

@REM Write parameters
echo 8 > .\benches\parameters\input_bytes
echo 8 > .\benches\parameters\gamma_bytes
echo 1 > .\benches\parameters\time_bytes
echo 4 > .\benches\parameters\mt_depth

for /f "delims=" %%i in ('powershell get-date -format "{yyyy-MM-dd--HH-mm-ss}"') do set datetime=%%i
if not exist ".\results\raw\benches" mkdir ".\results\raw\benches"

echo 16 > .\benches\parameters\randomness_bytes

echo Running base_histogram (1/6)
cargo bench --bench base_histogram --features print-trace > .\results\raw\benches\%datetime%_bench_base_histogram.txt 2>&1

echo Running expand_histogram (2/6)
cargo bench --bench expand_histogram --features print-trace > .\results\raw\benches\%datetime%_bench_expand_histogram.txt 2>&1

echo Running shuffle_histogram (3/6)
cargo bench --bench shuffle_histogram --features print-trace > .\results\raw\benches\%datetime%_bench_shuffle_histogram.txt 2>&1

del .\benches\parameters\randomness_bytes
echo 24 > .\benches\parameters\randomness_bytes

echo Running base_real (4/6)
cargo bench --bench base_real --features print-trace > .\results\raw\benches\%datetime%_bench_base_real.txt 2>&1

echo Running expand_real (5/6)
cargo bench --bench expand_real --features print-trace > .\results\raw\benches\%datetime%_bench_expand_real.txt 2>&1

echo Running shuffle_real (6/6)
cargo bench --bench shuffle_real --features print-trace > .\results\raw\benches\%datetime%_bench_shuffle_real.txt 2>&1

@REM Clear parameters
del .\benches\parameters\input_bytes
del .\benches\parameters\gamma_bytes
del .\benches\parameters\time_bytes
del .\benches\parameters\mt_depth
del .\benches\parameters\randomness_bytes
del .\benches\parameters\n_warmup
del .\benches\parameters\n_measure
rmdir .\benches\parameters

echo Parsing results
python .\scripts\parse_bench_results.py %datetime%
