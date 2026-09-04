@echo off
title ContentGuard Pro MAX - Production Preview
echo ========================================================================
echo   CONTENTGUARD PRO MAX v1.0.1 — COMPILED PRODUCTION PREVIEW
echo ========================================================================
echo.
echo Launching compiled production bundle on port 4173...
echo Opening browser at http://localhost:4173 ...
echo.
start "" "http://localhost:4173"
call npm run preview -- --port 4173 --host 0.0.0.0
pause
