# CYBERGUARD: Free Cloud Deployment Guide
## Step-by-Step Instructions to Deploy Live on Render / Railway

Your project is already 100% prepared for cloud hosting with:
- `Procfile` configured with Gunicorn WSGI: `web: gunicorn "app:create_app()" --bind 0.0.0.0:$PORT`
- `render.yaml` configuration blueprint
- `requirements.txt` with production WSGI server (`gunicorn`)
- Local Git repository initialized and committed (`main` branch)

---

## METHOD 1: Deploy to Render.com (Recommended & 100% Free)

Render provides a completely free tier with automatic SSL/HTTPS, instant deployments, and continuous delivery from GitHub.

### Step 1: Create a GitHub Repository
1. Open your browser and go to: **[https://github.com/new](https://github.com/new)**
2. Sign in as **Nikhil2006-stack**.
3. Name the repository: `cyberguard`
4. Set it to **Public** (or **Private**).
5. **Do NOT** check "Add a README" or ".gitignore" (these already exist locally).
6. Click **Create repository**.

### Step 2: Push your Local Code to GitHub
Open your terminal in `c:\Users\HP\Desktop\cyberguard` and run:

```powershell
git branch -M main
git remote add origin https://github.com/Nikhil2006-stack/cyberguard.git
git push -u origin main
```
*(Enter your GitHub credentials or personal access token if prompted).*

### Step 3: Connect & Deploy on Render
1. Go to **[https://render.com](https://render.com)** and click **Sign Up** (Sign in with your GitHub account).
2. On your Render Dashboard, click the **New +** button in the top right.
3. Select **Web Service**.
4. Choose **"Build and deploy from a Git repository"** and click **Next**.
5. Connect your GitHub account and select your **cyberguard** repository.
6. Render will auto-detect the configuration:
   - **Name:** `cyberguard`
   - **Region:** Choose the closest region (e.g., Singapore, Frankfurt, or Oregon)
   - **Branch:** `main`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn "app:create_app()" --bind 0.0.0.0:$PORT`
   - **Instance Type:** Select **Free** ($0/month)
7. Click **Create Web Service**!

Render will build your application, install dependencies, run database initialization, and provide you with a live public URL within 2 minutes:
👉 **`https://cyberguard.onrender.com`**

---

## METHOD 2: Deploy to Railway.app (Alternative 1-Click)

1. Go to **[https://railway.app](https://railway.app)** and log in with GitHub.
2. Click **New Project** -> **Deploy from GitHub repo**.
3. Select `Nikhil2006-stack/cyberguard`.
4. Railway will automatically detect the `Procfile` and deploy your app.
5. In project settings, click **Generate Domain** to get a public `https://cyberguard-production.up.railway.app` URL.

---

## Verification After Deployment
Once deployed, open your live URL on any smartphone or laptop anywhere in the world to verify:
1. **SOC Dashboard:** Loads with live dynamic Chart.js charts.
2. **Phishing Analyzer:** Test sample phishing messages online.
3. **QR Scanner:** Upload or scan demonstration QR codes.
4. **Penetration Lab:** Perform the IDOR demonstration live (`/lab/vulnerable/profile/2` vs `/lab/secured/profile/2`).
5. **Audit Report:** Generate and download the PDF security report.
