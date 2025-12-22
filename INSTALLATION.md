# OWASP Labs Platform - Installation Guide

## Prerequisites

To run this project, you need to install the following tools:

### 1. Python

- Version: 3.9 or higher
- Download: https://www.python.org/downloads/
- On Windows, make sure to check "Add Python to PATH"

### 2. Node.js and npm

- Version: 18.0 or higher
- Download: https://nodejs.org/
- npm is automatically installed with Node.js

### 3. PostgreSQL

- Version: 14 or higher
- Download: https://www.postgresql.org/download/
- During installation, set a password for the postgres user

### 4. Redis (Optional but recommended)

- For Windows, use WSL or Windows version
- Download: https://redis.io/download
- For Windows: https://github.com/tporadowski/redis/releases

---

## Step 1: PostgreSQL Database Setup

### Create Database and User

Use PostgreSQL command line or pgAdmin:

```sql
CREATE DATABASE owasp_labs;
CREATE USER labs_admin WITH PASSWORD 'labs_password_123';
GRANT ALL PRIVILEGES ON DATABASE owasp_labs TO labs_admin;
```

### Run Database Scripts

```bash
psql -U labs_admin -d owasp_labs -f database/init.sql
psql -U labs_admin -d owasp_labs -f database/vulnerable_schemas.sql
```

Or use pgAdmin to manually execute the SQL files.

---

## Step 2: Backend Setup (Flask)

### 2.1 Install Python Dependencies

```bash
cd backend
pip install -r requirements.txt
```

If you encounter errors, use virtualenv:

```bash
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

### 2.2 Configure Environment Variables

Create a `.env` file in the project root:

```env
DATABASE_URL=postgresql://labs_admin:labs_password_123@localhost:5432/owasp_labs
SECRET_KEY=your-secret-key-change-in-production
REDIS_HOST=localhost
REDIS_PORT=6379
```

### 2.3 Run Backend

```bash
cd backend
python app.py
```

Backend will run on port 5000: `http://localhost:5000`

---

## Step 3: Frontend Setup (React)

### 3.1 Install Node.js Dependencies

```bash
cd frontend
npm install
```

### 3.2 Configure Backend URL

If needed, create a `.env` file in the frontend folder:

```env
REACT_APP_API_URL=http://localhost:5000
```

### 3.3 Run Frontend

```bash
npm start
```

Frontend will run on port 3000: `http://localhost:3000`

---

## Step 4: Access the Platform

After successfully running Backend and Frontend:

1. Open your browser
2. Navigate to `http://localhost:3000`
3. Login with default credentials:
   - **Username:** admin
   - **Password:** admin123

---

## Running Services Separately

### Run Redis (if installed)

```bash
redis-server
```

Or on Windows:

```bash
redis-server.exe
```

### Test Database Connection

```bash
psql -U labs_admin -d owasp_labs -h localhost
```

### Run Backend in Development Mode

```bash
cd backend
python app.py
```

### Run Frontend in Development Mode

```bash
cd frontend
npm start
```

---

## Quick Start (All-in-One)

### Linux/Mac:

```bash
#!/bin/bash
cd backend && python app.py &
cd ../frontend && npm start
```

### Windows (PowerShell):

```powershell
Start-Process -FilePath "python" -ArgumentList "backend\app.py" -NoNewWindow
Start-Process -FilePath "npm" -ArgumentList "start" -WorkingDirectory "frontend"
```

---

## Common Issues

### PostgreSQL Connection Error

- Ensure PostgreSQL is running
- Check port 5432
- Verify username and password in `.env`

### Python Package Installation Error

```bash
pip install --upgrade pip
pip install -r requirements.txt --no-cache-dir
```

### npm Package Installation Error

```bash
npm cache clean --force
npm install
```

### Frontend Cannot Connect to Backend

- Ensure Backend is running on port 5000
- Check CORS in `app.py`
- Verify API URL in Frontend

### Redis Error

If Redis is not installed, disable Redis-related code in `app.py` or install Redis.

---

## Build for Production

### Build Frontend

```bash
cd frontend
npm run build
```

Final files will be in `frontend/build` directory.

### Run Backend with Gunicorn (Production)

```bash
pip install gunicorn
cd backend
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## Ports Used

- **Frontend:** 3000
- **Backend API:** 5000
- **PostgreSQL:** 5432
- **Redis:** 6379

---

## Security

⚠️ **WARNING:** This platform is intentionally vulnerable for educational purposes.

- Never expose this to the public internet
- Only use in isolated educational environments
- Change default passwords
- Run on local networks or isolated VMs

---

## Additional Resources

- Flask Documentation: https://flask.palletsprojects.com/
- React Documentation: https://react.dev/
- PostgreSQL Documentation: https://www.postgresql.org/docs/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
