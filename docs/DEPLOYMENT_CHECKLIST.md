# 🚀 OWASP Labs Platform - Deployment & Setup Checklist

## Pre-Installation Checklist

### System Requirements

- [ ] **OS**: Linux (Ubuntu 20.04+), macOS, or Windows (WSL2)
- [ ] **RAM**: Minimum 4GB (8GB recommended)
- [ ] **Disk Space**: 5GB available
- [ ] **CPU**: 2+ cores recommended

### Required Software

- [ ] Docker installed (`docker --version`)
- [ ] Docker Compose installed (`docker-compose --version`)
- [ ] Git installed (for cloning repository)
- [ ] Terminal/Command Prompt access

### Network & Ports

- [ ] Port 3000 available (Frontend)
- [ ] Port 5000 available (Backend API)
- [ ] Port 5432 available (PostgreSQL)
- [ ] Port 6379 available (Redis)
- [ ] Active internet connection (for pulling images)

---

## Installation Steps

### Step 1: Clone Repository

- [ ] Navigate to desired directory
- [ ] Run: `git clone https://github.com/your-org/owasp-labs-platform.git`
- [ ] Change directory: `cd owasp-labs-platform`

### Step 2: Configure Environment

- [ ] Copy `.env.example` to `.env`
  ```bash
  cp .env.example .env
  ```
- [ ] Review `.env` file for default settings
- [ ] Change admin password if deploying externally
- [ ] Update SECRET_KEY and JWT_SECRET

### Step 3: Build & Start Services

- [ ] Run Docker Compose:
  ```bash
  docker-compose up -d --build
  ```
- [ ] Wait 30-60 seconds for services to initialize
- [ ] Verify all containers are running:
  ```bash
  docker-compose ps
  ```

### Step 4: Verify Installation

- [ ] Check Backend API: `curl http://localhost:5000/health`
- [ ] Check Frontend: Open http://localhost:3000 in browser
- [ ] Check database: `docker exec owasp-labs-db pg_isready`

---

## Post-Installation Configuration

### Database Setup

- [ ] Verify database initialization
- [ ] Check database tables exist
- [ ] Confirm sample data loaded

### First Login

- [ ] Access Frontend: http://localhost:3000
- [ ] Login with credentials:
  - Username: `admin`
  - Password: `admin123`
- [ ] Verify dashboard loads correctly
- [ ] Check lab browser displays labs

### User Accounts

- [ ] Create test user account
- [ ] Test registration endpoint
- [ ] Verify JWT token generation
- [ ] Test logout functionality

---

## Platform Testing

### Frontend Testing

- [ ] Home page loads without errors
- [ ] Navigation links work
- [ ] Lab listing displays correctly
- [ ] Search and filters function
- [ ] Lab detail page loads
- [ ] Flag submission form works
- [ ] Leaderboard displays
- [ ] User profile page works
- [ ] Mobile responsiveness verified

### Backend Testing

- [ ] All API endpoints respond
- [ ] Authentication works (login/register)
- [ ] Lab endpoints return data
- [ ] Flag validation works
- [ ] Hint system responds
- [ ] Progress tracking updates
- [ ] Leaderboard returns rankings
- [ ] Error handling appropriate

### Database Testing

- [ ] Lab data populated correctly
- [ ] User sessions tracked
- [ ] Points system working
- [ ] Flag validation queries correct
- [ ] No errors in application logs

### Docker Testing

- [ ] All containers running stable
- [ ] Resource usage acceptable
- [ ] No memory leaks after 1 hour
- [ ] Services restart correctly after restart
- [ ] Volumes persistent after restart

---

## Security Hardening

### Before External Deployment (if applicable)

- [ ] Change `SECRET_KEY` in `.env`
- [ ] Change `JWT_SECRET` in `.env`
- [ ] Change admin password
- [ ] Set `FLASK_ENV=production`
- [ ] Disable `FLASK_DEBUG=0`
- [ ] Configure SSL/HTTPS
- [ ] Set up firewall rules
- [ ] Restrict database access
- [ ] Configure backup strategy

### Access Control

- [ ] Limit network access to lab subnet only
- [ ] Set up VPN access if needed
- [ ] Implement IP whitelisting
- [ ] Configure authentication provider
- [ ] Set up audit logging

---

## Monitoring & Maintenance

### Daily Checks

- [ ] Verify all containers running
- [ ] Check disk space usage
- [ ] Review application logs
- [ ] Monitor user activity

### Weekly Tasks

- [ ] Backup database
- [ ] Review security logs
- [ ] Check for updates
- [ ] Test disaster recovery

### Monthly Tasks

- [ ] Clean old sessions
- [ ] Archive old logs
- [ ] Performance analysis
- [ ] Security audit

---

## Troubleshooting Checklist

### Services Won't Start

- [ ] Check Docker daemon running
- [ ] Verify ports not in use: `lsof -i :3000`
- [ ] Check logs: `docker-compose logs`
- [ ] Rebuild: `docker-compose up -d --build`
- [ ] Clear volumes: `docker-compose down -v`

### Database Connection Issues

- [ ] Check PostgreSQL container: `docker-compose ps`
- [ ] Verify DATABASE_URL in `.env`
- [ ] Check database credentials
- [ ] Test connection: `docker exec owasp-labs-db psql -U labs_admin`

### Frontend Not Loading

- [ ] Check frontend logs: `docker-compose logs frontend`
- [ ] Verify Node modules installed
- [ ] Check REACT_APP_API_URL in `.env`
- [ ] Clear browser cache
- [ ] Rebuild frontend: `docker-compose restart frontend`

### API Errors

- [ ] Check backend logs: `docker-compose logs backend`
- [ ] Verify Flask app running
- [ ] Check database connectivity
- [ ] Review error messages in logs

### Performance Issues

- [ ] Check container resource limits
- [ ] Monitor CPU/memory usage
- [ ] Review database query performance
- [ ] Check for slow API endpoints
- [ ] Optimize database indexes

---

## Lab Data Verification

### SQL Injection Labs

- [ ] Lab 1.1 (UNION attack) flag: `FLAG{sqli_union_login_2024}`
- [ ] Lab 1.2 (String-based) flag: `FLAG{sqli_search_string_2024}`
- [ ] Lab 1.3 (Boolean blind) flag: `FLAG{sqli_blind_boolean_2024}`
- [ ] Lab 1.4 (Time-based) flag: `FLAG{sqli_time_based_2024}`
- [ ] Lab 1.5 (Limited input) flag: `FLAG{sqli_limited_input_2024}`

### Other Categories

- [ ] SSRF labs loaded
- [ ] CSRF labs loaded
- [ ] XSS labs loaded
- [ ] XXE labs loaded
- [ ] IDOR labs loaded
- [ ] RCE labs loaded
- [ ] Command Injection labs loaded

---

## Documentation Review

- [ ] Read SETUP.md
- [ ] Review LAB_DESCRIPTIONS.md
- [ ] Study SOLUTION_GUIDES.md
- [ ] Understand PROJECT_SUMMARY.md

---

## Performance Baseline

### Record Initial Metrics

- [ ] Frontend load time: **\_** ms
- [ ] API response time: **\_** ms
- [ ] Database query time: **\_** ms
- [ ] CPU usage (idle): **\_** %
- [ ] Memory usage: **\_** MB

### Performance Targets

- [ ] Page load < 2 seconds
- [ ] API response < 500ms
- [ ] Database query < 100ms
- [ ] CPU < 50% under load
- [ ] Memory < 2GB total

---

## Backup & Recovery

### Backup Procedure

- [ ] Backup database: `docker exec owasp-labs-db pg_dump -U labs_admin owasp_labs > backup.sql`
- [ ] Backup volumes: Copy Docker volumes
- [ ] Store backups securely
- [ ] Test restore procedure

### Recovery Testing

- [ ] Test database restore
- [ ] Verify data integrity
- [ ] Check all services recover
- [ ] Validate user data preserved

---

## Sign-Off

### Installation Complete

- [ ] All checks passed
- [ ] All services functioning
- [ ] Documentation reviewed
- [ ] Backups created
- [ ] Access verified

### Date Completed: ********\_********

### Completed By: ********\_********

### Notes:

```
_________________________________________________
_________________________________________________
_________________________________________________
```

---

## Quick Reference Commands

```bash
# Start platform
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild everything
docker-compose up -d --build

# Access database
docker exec -it owasp-labs-db psql -U labs_admin -d owasp_labs

# View running containers
docker-compose ps

# Remove all volumes (WARNING: deletes data)
docker-compose down -v

# Backup database
docker exec owasp-labs-db pg_dump -U labs_admin owasp_labs > backup.sql

# Restore database
docker exec -i owasp-labs-db psql -U labs_admin owasp_labs < backup.sql
```

---

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Guide](https://docs.docker.com/compose/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [React Documentation](https://react.dev/)

---

**Platform**: OWASP Vulnerable Labs  
**Version**: 1.0.0  
**Last Updated**: December 2024
