@echo off
title ContentGuard Pro MAX - Gateway Launch
echo ========================================================================
echo   CONTENTGUARD PRO MAX v1.0.1 — LOCAL GATEWAY LAUNCHER
echo ========================================================================
echo.
echo Starting local gateway server on port 3000...
echo Opening browser at http://localhost:3000 ...
echo.
start "" "http://localhost:3000"
call npm run dev
pause
