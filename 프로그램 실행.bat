@echo off
chcp 65001 >nul

cd /d "%~dp0"

echo ================================
echo 본문 추출기 실행 중...
echo 현재 폴더: %cd%
echo ================================

start "" cmd /c "timeout /t 2 >nul & start http://127.0.0.1:5000"

python app.py

echo.
echo 프로그램이 종료되었습니다.
pause