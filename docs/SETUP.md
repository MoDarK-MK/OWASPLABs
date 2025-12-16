# OWASP Vulnerable Labs Platform - Setup Guide

## 📋 Prerequisites

Before you begin, ensure you have the following installed on your system:

- **Docker**: [Install Docker](https://docs.docker.com/get-docker/)
- **Docker Compose**: [Install Docker Compose](https://docs.docker.com/compose/install/)
- **Git**: [Install Git](https://git-scm.com/)

### System Requirements

- **OS**: Linux (Ubuntu 20.04+), macOS (Intel & Apple Silicon), or Windows (WSL2)
- **RAM**: 4GB minimum (8GB recommended)
- **Disk Space**: 5GB available
- **Ports**: 3000, 5000, 5432, 6379 (must be available)

## 🚀 Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/owasp-labs-platform.git
cd owasp-labs-platform
```

### 2. Configure Environment Variables

Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Backend
SECRET_KEY=your-secret-key-change-in-production
JWT_SECRET=weak-jwt-secret-for-learning
DATABASE_URL=postgresql://labs_admin:labs_password_123@postgres:5432/owasp_labs

# Frontend
REACT_APP_API_URL=http://localhost:5000
REACT_APP_WS_URL=ws://localhost:5000

# Database
POSTGRES_USER=labs_admin
POSTGRES_PASSWORD=labs_password_123
POSTGRES_DB=owasp_labs
```

### 3. Start the Platform

```bash
# Build and start all containers
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### 4. Verify Installation

The platform should be available at:

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000
- **Database**: localhost:5432
- **Redis**: localhost:6379

### 5. Default Credentials

Use these credentials to log in:

```
Username: admin
Password: admin123
```

## 📊 Project Structure

```
owasp-labs/
├── docker-compose.yml          # Docker orchestration
├── .env.example                # Environment template
│
├── backend/                    # Flask API Backend
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                  # Main Flask application
│   ├── config.py               # Configuration
│   ├── models.py               # Database models
│   └── labs/                   # Lab implementations
│       ├── sql_injection/
│       ├── ssrf/
│       ├── csrf/
│       ├── xss/
│       ├── xxe/
│       ├── idor/
│       ├── rce/
│       └── command_injection/
│
├── frontend/                   # React Frontend
│   ├── Dockerfile
│   ├── package.json
│   ├── public/
│   └── src/
│       ├── App.jsx
│       ├── pages/              # Page components
│       ├── components/         # Reusable components
│       └── services/           # API services
│
├── database/                   # Database scripts
│   ├── init.sql                # Initial schema
│   └── vulnerable_schemas.sql  # Lab data
│
└── docs/                       # Documentation
    ├── SETUP.md                # This file
    ├── LAB_DESCRIPTIONS.md
    └── SOLUTION_GUIDES.md
```

## 🔧 Common Operations

### Access Database

```bash
# Connect to PostgreSQL
docker exec -it owasp-labs-db psql -U labs_admin -d owasp_labs

# List all tables
\dt

# Query users
SELECT * FROM users;
```

### View Logs

```bash
# All services
docker-compose logs

# Specific service
docker-compose logs backend
docker-compose logs frontend
docker-compose logs postgres
```

### Reset Database

```bash
# Stop and remove containers
docker-compose down -v

# Rebuild and restart
docker-compose up -d --build
```

### Rebuild Frontend

```bash
# Rebuild dependencies
docker exec owasp-labs-frontend npm install

# Restart frontend
docker-compose restart frontend
```

## 🛠️ Development

### Backend Development

```bash
# Install Python dependencies locally (optional)
cd backend
pip install -r requirements.txt

# Run Flask development server
python app.py

# Database migrations
python -m flask db upgrade
```

### Frontend Development

```bash
# Install dependencies
cd frontend
npm install

# Start development server
npm start

# Build for production
npm run build
```

### Adding New Labs

1. Create a new lab file in `backend/labs/{category}/`
2. Define the vulnerable endpoint
3. Add lab metadata to `database/vulnerable_schemas.sql`
4. Restart the backend: `docker-compose restart backend`

## 🔐 Security Considerations

This platform is **intentionally vulnerable** for educational purposes:

- ✅ Use in controlled environments only
- ✅ Never deploy to production
- ✅ Run on isolated networks
- ✅ Use firewall rules to restrict access
- ✅ Change default credentials in production

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Find process using port 3000
lsof -i :3000

# Kill process
kill -9 <PID>

# Or use different ports in docker-compose.yml
```

### Database Connection Error

```bash
# Check database status
docker exec owasp-labs-db pg_isready

# View database logs
docker-compose logs postgres
```

### Frontend Not Loading

```bash
# Clear cache and restart
docker-compose down
docker volume prune
docker-compose up -d --build
```

### Out of Disk Space

```bash
# Clean up Docker resources
docker system prune -a
docker volume prune

# Check disk usage
docker system df
```

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

## 📞 Support

For issues, questions, or contributions:

- 📧 Email: support@owasp-labs.local
- 🐙 GitHub Issues: [Report Bug](https://github.com/your-org/owasp-labs/issues)
- 💬 Discussion Forum: [Join Community](https://github.com/your-org/owasp-labs/discussions)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Last Updated**: December 2024  
**Version**: 1.0.0  
**Status**: Active Development
