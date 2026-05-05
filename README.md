# CyberTrace Digital Forensics Toolkit
### Complete Final Year Project – Setup & Demonstration Guide

---

## 📁 Project Structure

```
cybertrace/
├── app.py                        ← Flask entry point (run this)
├── requirements.txt              ← Python dependencies
├── README.md                     ← This file
│
├── backend/
│   ├── __init__.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── database.py           ← SQLite schema & log helper
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth_routes.py        ← /register  /login  /me
│   │   ├── file_routes.py        ← /upload  /files  /scan  /hash  /metadata
│   │   └── extra_routes.py       ← /logs  /network  /report  /stats
│   └── utils/
│       ├── __init__.py
│       ├── auth.py               ← JWT + bcrypt utilities
│       ├── forensics.py          ← Hash, scan, metadata extraction
│       └── reporter.py           ← HTML report generator
│
├── frontend/
│   ├── index.html                ← Single-page app shell
│   └── assets/
│       ├── css/main.css          ← Full cybersecurity-themed UI
│       └── js/
│           ├── api.js            ← API client (Auth/Files/Logs/Network/Reports)
│           ├── auth.js           ← Login / Register logic
│           ├── pages.js          ← All page renderers
│           └── app.js            ← Navigation, clock, toast, utilities
│
├── uploads/                      ← Evidence files stored here (auto-created)
├── reports/                      ← Generated HTML reports (auto-created)
└── database/
    └── cybertrace.db             ← SQLite database (auto-created on first run)
```

---

## 🗄️ Database Schema

### Table: `users`
| Column      | Type    | Description                        |
|-------------|---------|-------------------------------------|
| id          | INTEGER | Primary key (autoincrement)         |
| username    | TEXT    | Unique username                     |
| email       | TEXT    | Unique email                        |
| password    | TEXT    | bcrypt hash                         |
| role        | TEXT    | 'analyst' or 'admin'               |
| created_at  | TEXT    | ISO timestamp (default: NOW)        |

### Table: `files`
| Column          | Type    | Description                          |
|-----------------|---------|---------------------------------------|
| id              | INTEGER | Primary key                           |
| case_id         | TEXT    | e.g. CASE-2024-001                    |
| original_name   | TEXT    | Original filename                     |
| stored_name     | TEXT    | UUID-based safe filename on disk      |
| file_size       | INTEGER | Bytes                                 |
| file_type       | TEXT    | Extension e.g. .pdf                   |
| mime_type       | TEXT    | Detected MIME type                    |
| md5_hash        | TEXT    | MD5 hex digest                        |
| sha1_hash       | TEXT    | SHA-1 hex digest                      |
| sha256_hash     | TEXT    | SHA-256 hex digest                    |
| is_suspicious   | INTEGER | 0=clean, 1=flagged                    |
| analysis_result | TEXT    | JSON blob of scan findings            |
| uploaded_by     | INTEGER | FK → users.id                         |
| uploaded_at     | TEXT    | ISO timestamp                         |

### Table: `logs`
| Column     | Type    | Description                           |
|------------|---------|----------------------------------------|
| id         | INTEGER | Primary key                            |
| user_id    | INTEGER | FK → users.id                          |
| username   | TEXT    | Denormalised username                  |
| action     | TEXT    | upload/scan/hash/login/report/delete   |
| target     | TEXT    | Filename or resource                   |
| detail     | TEXT    | Human-readable description             |
| ip_address | TEXT    | Request IP                             |
| status     | TEXT    | success / warning / error              |
| created_at | TEXT    | ISO timestamp                          |

---

## ⚙️ How to Run Locally

### Step 1 – Clone / Download
```bash
# If using git:
git clone https://github.com/yourname/cybertrace.git
cd cybertrace

# Or just unzip the project folder and cd into it
cd cybertrace
```

### Step 2 – Create a Python virtual environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3 – Install dependencies
```bash
pip install -r requirements.txt
```

> **Note on `python-magic`:**
> - **Linux/macOS:** `python-magic` works out of the box (libmagic is usually installed).
> - **Windows:** Use `python-magic-bin` instead (already handled in requirements.txt via platform marker).
>   If you still get errors on Windows: `pip install python-magic-bin`

### Step 4 – Initialise the database
The database is auto-created the first time you run the app.

### Step 5 – Run the backend
```bash
python app.py
```

You should see:
```
╔══════════════════════════════════════════════╗
║   CyberTrace Digital Forensics Toolkit       ║
║   http://localhost:5000                      ║
╚══════════════════════════════════════════════╝
```

### Step 6 – Open the frontend
Open your browser and navigate to:
```
http://localhost:5000
```

The Flask server serves the frontend automatically.

---

## 🧪 How to Test the System

### 1. Create an account
- Click **Register**
- Username: `analyst01`, Email: `analyst@lab.com`, Password: `password123`

### 2. Log in
- Use the credentials you just created

### 3. Upload evidence
- Click **Upload Evidence** in the sidebar
- Enter Case ID: `CASE-001`
- Upload any file (PDF, image, .exe, .docx, etc.)

### 4. Scan a file
- Click **Evidence Files**
- Click **Scan** next to any uploaded file
- View the risk level and findings

### 5. Hash a file
- Click **Hash** next to any file
- MD5, SHA-1, SHA-256 are computed and stored
- Click **Detail** to view all hashes

### 6. View Audit Logs
- Click **Audit Logs**
- Filter by action, status or search term
- Every action is recorded with timestamp and IP

### 7. Monitor Network
- Click **Network Monitor**
- Connections refresh every 8 seconds
- ~30% of polls inject a simulated suspicious connection

### 8. Generate a Report
- Click **Reports**
- Enter `CASE-001` and click **Generate Report**
- Download the HTML file and open in browser
- Print → Save as PDF for a PDF copy

---

## 🌐 API Reference

All endpoints are under `/api/`. Protected endpoints require:
```
Authorization: Bearer <JWT token>
```

| Method | Endpoint              | Auth | Description                    |
|--------|-----------------------|------|--------------------------------|
| POST   | /register             | No   | Create user account            |
| POST   | /login                | No   | Authenticate, get JWT          |
| GET    | /me                   | Yes  | Get current user profile       |
| POST   | /upload               | Yes  | Upload evidence file           |
| GET    | /files                | Yes  | List all files                 |
| GET    | /files/:id            | Yes  | Get single file detail         |
| DELETE | /files/:id            | Yes  | Delete a file                  |
| POST   | /scan/:id             | Yes  | Run forensic scan              |
| POST   | /hash/:id             | Yes  | Compute hashes                 |
| GET    | /metadata/:id         | Yes  | Extract file metadata          |
| GET    | /logs                 | Yes  | Get paginated audit logs       |
| GET    | /network              | Yes  | Get network connections        |
| POST   | /report               | Yes  | Generate HTML report           |
| GET    | /report/:filename     | Yes  | Download generated report      |
| GET    | /stats                | Yes  | Dashboard statistics           |
| GET    | /health               | No   | Health check                   |

---

## 🚀 Deployment

### Option A: PythonAnywhere (Free)

1. Create a free account at https://www.pythonanywhere.com
2. Open a **Bash console** and clone your repo:
   ```bash
   git clone https://github.com/yourname/cybertrace.git
   cd cybertrace
   pip install -r requirements.txt --user
   ```
3. Go to **Web** tab → **Add new web app**
   - Choose **Manual configuration** → **Python 3.11**
4. Set source code directory to `/home/yourusername/cybertrace`
5. Set WSGI file: point it to `app.py`, add:
   ```python
   import sys
   sys.path.insert(0, '/home/yourusername/cybertrace')
   from app import app as application
   from backend.models.database import init_db
   init_db()
   ```
6. Click **Reload** – your app is live!

### Option B: Render (Free tier)

1. Push your code to GitHub
2. Create account at https://render.com
3. New Web Service → Connect your GitHub repo
4. Settings:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `gunicorn app:app`
   - Add environment variable: `FLASK_DEBUG=false`
5. Click **Create Web Service**

> **Note:** Add `gunicorn` to requirements.txt for deployment:
> ```
> gunicorn==21.2.0
> ```

---

## 🔐 Security Features

| Feature | Implementation |
|---------|----------------|
| Password hashing | bcrypt with 12 rounds (industry standard) |
| Authentication | JWT (HS256, 8-hour expiry) |
| Input validation | Server-side on all endpoints |
| File handling | UUID-based stored names, size limits |
| Path traversal | Report download sanitises filename |
| SQL injection | Parameterised queries throughout |
| CORS | Configurable, locked down in production |

---

## 🎓 Demonstrating to Your Supervisor

### Live Demo Script (15 minutes)

**1. Introduction (2 min)**
> "CyberTrace is a web-based digital forensics toolkit. I'll demonstrate its six core modules."

**2. Authentication (2 min)**
- Register a new account → show bcrypt hashing in database
- Log in → show JWT in browser localStorage DevTools

**3. Evidence Upload (2 min)**
- Upload 2-3 files: a PDF, an image, and a .bat or .exe file
- Show the progress bar and database entry

**4. Scan & Hash (3 min)**
- Run scan on the .bat/.exe file → show HIGH risk level, findings
- Run hash → show MD5/SHA-1/SHA-256
- Open Detail panel → show all metadata

**5. Audit Logs (2 min)**
- Switch to Audit Logs → show every action logged
- Demonstrate search and filter

**6. Network Monitor (1 min)**
- Switch to Network Monitor
- Refresh a few times until a suspicious connection appears

**7. Report Generation (2 min)**
- Generate report for CASE-001
- Open the HTML report → show professional layout
- Demonstrate browser Print → Save as PDF

### Key Talking Points for Supervisor
- **Chain of custody:** Every file gets SHA-256 hash for integrity verification
- **Audit trail:** Every action is logged with user, timestamp, IP
- **Rule-based detection:** Byte signatures, suspicious strings, extension checking
- **Metadata forensics:** EXIF from images, author from PDFs/DOCX
- **Secure by design:** JWT auth, bcrypt, parameterised queries, UUID filenames
- **Extensible:** Easy to add new file types, detection rules, or modules

---

## 📦 Sample Test Data

Run this to insert sample data quickly:
```bash
python seed_data.py
```

Or use the API:
```bash
# Register
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst01","email":"a@b.com","password":"password123"}'

# Login (save the token)
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst01","password":"password123"}'
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: magic` | Run `pip install python-magic-bin` (Windows) |
| `Address already in use` | Change port: `PORT=5001 python app.py` |
| Database locked | Delete `database/cybertrace.db` and restart |
| CORS errors in browser | Ensure you access via `http://localhost:5000` not file:// |
| Pillow import error | `pip install Pillow --upgrade` |

---

*CyberTrace v1.0 – Final Year Cybersecurity Project*
*Built with Python 3.11 + Flask + SQLite + JWT + bcrypt*
