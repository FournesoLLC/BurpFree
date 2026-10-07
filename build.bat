@echo off
set PATH=C:\Program Files\nodejs;%PATH%
cd /d c:\Users\pc\Desktop\BurpFree\web
node .\node_modules\typescript\bin\tsc --noEmit 2>nul
set TSCERR=%ERRORLEVEL%
node .\node_modules\vite\bin\vite.js build > %TEMP%\bf-vite.log 2>&1
echo FE_OK (tsc=%TSCERR%)
set "CARGO_TARGET_DIR=F:\burpfree-target"
set PATH=C:\Users\pc\mingw64\bin;C:\Users\pc\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained;C:\Users\pc\.cargo\bin;C:\Users\pc\.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin;%PATH%
cd /d c:\Users\pc\Desktop\BurpFree
cargo build -p burpfree-tauri > %TEMP%\bf-tauri.log 2>&1
if errorlevel 1 (echo DBG_FAIL) else (echo DBG_OK)
