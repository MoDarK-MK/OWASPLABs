@echo off
REM OWASP Labs Platform - Quick Start Guide (Windows)

echo.
echo ==================================================
echo   OWASP Vulnerable Labs Platform - Quick Start
echo ==================================================
echo.

echo Checking Prerequisites...

REM Check Docker
where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Docker not found. Please install Docker Desktop.
    pause
    exit /b 1
)

where docker-compose >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Docker Compose not found. Please install Docker Compose.
    pause
    exit /b 1
)

echo OK: Docker and Docker Compose found
echo.

echo Available Commands:
echo.
echo 1. START PLATFORM:
echo    docker-compose up -d
echo.

echo 2. VIEW LOGS:
echo    docker-compose logs -f
echo.

echo 3. ACCESS SERVICES:
echo    Frontend:  http://localhost:3000
echo    Backend:   http://localhost:5000
echo    Database:  localhost:5432
echo    Redis:     localhost:6379
echo.

echo 4. STOP PLATFORM:
echo    docker-compose down
echo.

echo 5. RESET DATABASE:
echo    docker-compose down -v
echo    docker-compose up -d
echo.

echo 6. VIEW ALL CONTAINERS:
echo    docker-compose ps
echo.

echo DEFAULT CREDENTIALS:
echo    Username: admin
echo    Password: admin123
echo.

echo DOCUMENTATION:
echo    - SETUP.md
echo    - LAB_DESCRIPTIONS.md
echo    - SOLUTION_GUIDES.md
echo    - PROJECT_SUMMARY.md
echo.

echo Ready to start? Run this command:
echo    docker-compose up -d
echo.

pause
