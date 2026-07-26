@echo off
chcp 65001 >nul

cd /d "%~dp0"

echo ================================
echo 필요한 패키지를 설치합니다.
echo 현재 폴더: %cd%
echo ================================

python -m pip install Flask requests beautifulsoup4 "bleach[css]" --disable-pip-version-check --no-cache-dir --timeout 30

echo.
echo 설치 작업이 끝났습니다.
pause