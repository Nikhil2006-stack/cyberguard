# CYBERGUARD: Comprehensive Troubleshooting & Debugging Guide

---

## Common Issues & Step-by-Step Solutions

### 1. Port 5000 Already in Use
- **Symptom:** Terminal displays `OSError: [Errno 98] Address already in use` or `[Errno 10048] Only one usage of each socket address is normally permitted`.
- **Root Cause:** A previous instance of Python or another local service (like AirPlay or Docker) is already using port 5000.
- **Solution (Windows PowerShell):**
  ```powershell
  # Find which process is on port 5000
  netstat -ano | findstr :5000
  
  # Terminate process by PID (e.g., PID 14220)
  taskkill /PID 14220 /F
  ```
  Or change the port in `config.py` from `5000` to `5050` or launch with:
  ```powershell
  $env:PORT=5050; python app.py
  ```

---

### 2. Classmates Cannot Connect to the Laptop Hotspot
- **Symptom:** Students can connect to the Wi-Fi hotspot, but typing `http://<host_ip>:5000` in their mobile browser displays "Site cannot be reached" or connection times out.
- **Root Cause:** Windows Defender Firewall blocks inbound connections on private network adapters.
- **Solution:**
  1. Open Windows Search -> type **Windows Defender Firewall** -> open it.
  2. Click **Allow an app or feature through Windows Defender Firewall** on the left.
  3. Click **Change settings** (requires administrator).
  4. Find **Python** in the list and ensure the checkbox under **Private** is checked.
  5. Alternatively, run in an Administrator PowerShell window:
     ```powershell
     New-NetFirewallRule -DisplayName "CYBERGUARD Lab Port 5000" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
     ```

---

### 3. Burp Suite Not Intercepting Localhost Requests
- **Symptom:** You browse to `http://localhost:5000`, but nothing appears in Burp Suite Proxy HTTP history.
- **Root Cause:** Modern browsers (like Chrome or Firefox) bypass proxy settings for `localhost` and `127.0.0.1` by default.
- **Solution:**
  - **Option A (Easiest):** Use Burp's built-in browser! In Burp Suite, go to **Proxy** -> **Intercept** -> click **Open Browser**. This browser is pre-configured to proxy all localhost traffic.
  - **Option B:** In standard browsers, configure proxy bypass exceptions to remove `localhost` or use `http://127.0.0.1:5000` instead of `localhost`.

---

### 4. QR Image Upload Fails to Decode
- **Symptom:** Uploading a custom QR code displays: *"No QR code could be decoded from the uploaded image."*
- **Root Cause:** Blurry picture, low contrast, glare on the phone screen, or uncropped background.
- **Solution:**
  1. Use our built-in **"Test This QR"** button in Module 3 to test the clean pre-generated demonstration codes.
  2. If using your phone camera, ensure good ambient lighting and crop tightly around the QR code boundary.

---

### 5. Need to Reset the Database Before the Presentation
- **Symptom:** The database has accumulated messy test records and you want a pristine demonstration state.
- **Solution:**
  - Navigate to **Settings** (`/settings`) in your browser and click **"Reseed DB"**.
  - Alternatively, simply delete the SQLite file:
    ```powershell
    Remove-Item instance\cyberguard.db
    ```
    The next time you run `app.py`, it will automatically re-create the database with clean default accounts (`admin`, `student_a`, `student_b`) and demonstration baseline events!
