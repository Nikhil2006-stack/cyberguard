# CYBERGUARD Platform Launcher for PowerShell
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  CYBERGUARD: LIVE ETHICAL HACKING & DEFENSIVE CYBERSECURITY PLATFORM" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

# Verify Python
try {
    $pyVersion = python --version 2>&1
    Write-Host "[*] Detected $pyVersion" -ForegroundColor Green
} catch {
    Write-Error "[ERROR] Python was not found on your system PATH."
    Exit 1
}

Write-Host "[*] Verifying requirements..." -ForegroundColor Yellow
python -m pip install -r requirements.txt --quiet

Write-Host "[*] Initializing CYBERGUARD database and assets..." -ForegroundColor Yellow
python -c "from app import create_app; create_app()"

Write-Host "[*] Starting CYBERGUARD server on port 5000..." -ForegroundColor Green
Start-Process "http://localhost:5000"

python app.py
