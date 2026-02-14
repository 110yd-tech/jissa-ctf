@echo off
echo ==========================================================
echo WARNING: This will DELETE the database (users, scores, logs)
echo ==========================================================
choice /M "Are you sure you want to reset the database?"
if errorlevel 2 goto :end

echo Deleting ctf.db...
if exist ctf.db (
    del ctf.db
    echo Database deleted.
) else (
    echo Database does not exist.
)

echo.
echo Please run 'run_server.bat' (or 'python app.py') to recreate and seed the database.
echo.
pause

:end
echo Cancelled.
pause
