# DPI Security Gateway — Quick Start & Deployment Guide

## 🚀 1. How to Run Locally (Windows / Mac / Linux)

### Option A: One-Click Launch (Windows)
Double-click `start.bat` in the root folder, or run in Terminal:
```cmd
start.bat
```

### Option B: Python Command
Run the following command from the project root directory:
```bash
python backend/main.py
```
Or with uvicorn directly:
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Once started, open your browser and navigate to:
- **Web Dashboard**: [http://localhost:8000](http://localhost:8000)
- **API Documentation (Swagger UI)**: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)

---

## 🌐 2. How to Host on Vercel

1. **Push to GitHub**:
   Ensure all files are pushed to your GitHub repository:
   `https://github.com/sushant-didwagh/DPI_Final_Project`

2. **Deploy on Vercel**:
   - Go to [Vercel Dashboard](https://vercel.com/new).
   - Import `sushant-didwagh/DPI_Final_Project`.
   - Vercel will automatically detect `vercel.json` and deploy both the FastAPI backend serverless functions and the static web UI.
   - Click **Deploy**.

---

## 👥 Project Team
- **Sushant Didwagh** — Lead Developer & DPI Security Architecture
- **Joel Emmanuel** — Backend Engine & Performance Optimization
- **Shashwati Pawar** — Telemetry Dashboard & Frontend UX Design
