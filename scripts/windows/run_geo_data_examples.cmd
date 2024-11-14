@echo off
for /f "delims=" %%i in ('powershell get-date -format "{yyyy-MM-dd--HH-mm-ss}"') do set datetime=%%i
if not exist ".\results\raw\geo_data" mkdir ".\results\raw\geo_data"

echo Running base (1/3)
cargo run --release --example geo_data_base > .\results\raw\geo_data\%datetime%_geo_data_base.txt 2>&1

echo Running expand (2/3)
cargo run --release --example geo_data_expand > .\results\raw\geo_data\%datetime%_geo_data_expand.txt 2>&1

echo Running shuffle (3/3)
cargo run --release --example geo_data_shuffle > .\results\raw\geo_data\%datetime%_geo_data_shuffle.txt 2>&1

echo Parsing results
python .\scripts\parse_geo_data_results.py %datetime%
