# 🛡️ OWASP Labs - Professional Security Training Platform

<div align="center">

[![GitHub stars](https://img.shields.io/github/stars/MoDarK-MK/OWASPLABs?style=flat-square&color=FFD700)](https://github.com/MoDarK-MK/OWASPLABs/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/MoDarK-MK/OWASPLABs?style=flat-square&color=00D9FF)](https://github.com/MoDarK-MK/OWASPLABs/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Node.js 18+](https://img.shields.io/badge/Node.js-18%2B-green?style=flat-square&logo=node.js)](https://nodejs.org)
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)](https://github.com/MoDarK-MK/OWASPLABs)

_A comprehensive, interactive security training platform designed for ethical hackers, penetration testers, and security enthusiasts_

[Features](#-features) • [Quick Start](#-quick-start) • [Installation](#-installation) • [Usage](#-usage) • [API Docs](#-api-documentation) • [Contributing](#-contributing)

</div>

---

## 🎯 Overview

**OWASP Labs** is a professional-grade cybersecurity training platform featuring 160+ intentionally vulnerable labs covering all OWASP Top 10 vulnerabilities. Learn offensive and defensive security techniques in a realistic, hands-on environment.

Perfect for:

- 🎓 Security students and trainees
- 👨‍💻 Ethical hackers and penetration testers
- 🏢 Organizations conducting internal security training
- 🔐 Security professionals staying current with vulnerabilities

---

## ✨ Features

### 🚀 Core Features

| Feature                    | Details                                 |
| -------------------------- | --------------------------------------- |
| **160+ Labs**              | Comprehensive coverage of OWASP Top 10  |
| **Real-world Scenarios**   | Realistic vulnerability simulations     |
| **Gamified Learning**      | Points, leaderboards, achievements      |
| **Progressive Difficulty** | 4 difficulty levels (Beginner → Master) |
| **Instant Feedback**       | Real-time flag validation               |
| **Hint System**            | Multi-level hints to guide learning     |
| **User Profiles**          | Progress tracking and statistics        |
| **Responsive UI**          | Works on desktop, tablet, mobile        |

### 🔴 Vulnerability Categories

```
├── SQL Injection (20 labs)
├── XSS - Cross-Site Scripting (20 labs)
├── CSRF - Cross-Site Request Forgery (20 labs)
├── IDOR - Insecure Direct Object Reference (20 labs)
├── SSRF - Server-Side Request Forgery (20 labs)
├── XXE - XML External Entity (20 labs)
├── RCE - Remote Code Execution (20 labs)
└── Command Injection (20 labs)
```

### 🎨 Technology Stack

**Backend:**

- Flask 2.3+ (Python)
- JWT Authentication
- RESTful API Architecture
- Mock In-Memory Database

**Frontend:**

- React 18+
- Tailwind CSS
- Real-time updates
- Modern dark theme UI

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- Node.js 18 or higher
- npm or yarn

### 30 Second Setup

```bash
# 1. Clone the repository
git clone https://github.com/MoDarK-MK/OWASPLABs.git
cd OWASPLABs

# 2. Install and run backend (Terminal 1)
cd backend
pip install flask flask-cors PyJWT
python app.py

# 3. Install and run frontend (Terminal 2)
cd frontend
npm install
npm start
```

**Access the platform:**

- Frontend: http://localhost:3000
- Backend API: http://localhost:5000
- Default credentials: `admin` / `admin123`

---

## 📋 Installation

### Detailed Backend Setup

```bash
cd backend

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate          # Linux/Mac
venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py
```

Server will start on http://127.0.0.1:5000

### Detailed Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start
```

Frontend will open at http://localhost:3000

---

## 💻 Usage

### 1. Login to the Platform

```
Username: admin
Password: admin123
```

### 2. Browse Available Labs

Navigate to the Dashboard to see all 160+ labs organized by category and difficulty.

### 3. Start a Lab

Click on any lab to view:

- Lab description
- Difficulty level
- Vulnerability explanation
- Points available

### 4. Solve the Challenge

Exploit the intentional vulnerability to find the flag. Format: `FLAG{...}`

### 5. Submit the Flag

Enter the flag and submit. You'll receive instant feedback and points!

### 6. Check Your Progress

View your statistics on the Profile page:

- Labs completed
- Total points earned
- Learning path progress

---

## 📡 API Documentation

### Authentication

**Login Endpoint:**

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**

```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

### Labs

**Get All Labs:**

```http
GET /api/labs
Authorization: Bearer {token}
```

**Get Specific Lab:**

```http
GET /api/labs/{lab_id}
Authorization: Bearer {token}
```

**Submit Flag:**

```http
POST /api/labs/{lab_id}/submit
Authorization: Bearer {token}
Content-Type: application/json

{
  "flag": "FLAG{sqli_basic}"
}
```

**Get Hint:**

```http
GET /api/labs/{lab_id}/hint?level=1
Authorization: Bearer {token}
```

### User

**Get Progress:**

```http
GET /api/user/progress
Authorization: Bearer {token}
```

**Get Profile:**

```http
GET /api/user/profile
Authorization: Bearer {token}
```

### Leaderboard

**Get Global Leaderboard:**

```http
GET /api/leaderboard?limit=100
```

---

## 📚 Lab Examples

### Lab 1: SQL Injection - Login Bypass

**Vulnerability:** Unvalidated user input in login query

**Objective:** Bypass authentication using SQL injection

**Hint:** Try using UNION SELECT in the username field

**Flag:** `FLAG{sqli_basic}`

### Lab 2: XSS - Stored Script

**Vulnerability:** Unsanitized input stored in database

**Objective:** Execute JavaScript in the search box

**Hint:** Use `<script>` tags or event handlers

**Flag:** `FLAG{xss_basic}`

### Lab 3: CSRF - Account Takeover

**Vulnerability:** Missing CSRF token validation

**Objective:** Change password without authorization

**Hint:** Create a form that auto-submits

**Flag:** `FLAG{csrf_basic}`

---

## 🛠️ Development

### Project Structure

```
OWASPLABs/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── requirements.txt       # Python dependencies
│   └── labs/                  # Lab implementations
├── frontend/
│   ├── src/
│   │   ├── App.jsx           # Main React component
│   │   ├── pages/            # Page components
│   │   ├── components/       # Reusable components
│   │   └── index.jsx         # Entry point
│   ├── package.json          # Node dependencies
│   └── tailwind.config.js    # Tailwind configuration
├── INSTALLATION.md           # Detailed setup guide
├── LAB_SOLUTIONS.md          # Complete solutions guide
└── README.md                 # This file
```

### Running Tests

```bash
# Backend
cd backend
python -m pytest

# Frontend
cd frontend
npm test
```

### Code Style

- **Python:** PEP 8
- **JavaScript:** Prettier + ESLint
- **SQL:** Standard SQL formatting

---

## 🔒 Security Notice

⚠️ **This platform is intentionally vulnerable for educational purposes.**

- **Never expose** this application to the public internet
- **Only use** in isolated educational environments
- **Change default** credentials before any public deployment
- **Use only** on local networks or inside VMs
- **For training** purposes only - educational use strictly

This platform demonstrates real vulnerabilities. Do not replicate these patterns in production code.

---

## 🤝 Contributing

We welcome contributions! Here's how to help:

### 1. Fork the Repository

```bash
git clone https://github.com/YOUR-USERNAME/OWASPLABs.git
cd OWASPLABs
git checkout -b feature/your-feature
```

### 2. Make Your Changes

```bash
# Make your modifications
git add .
git commit -m "feat: add new feature"
```

### 3. Push and Create Pull Request

```bash
git push origin feature/your-feature
```

### Contribution Guidelines

- ✅ Follow existing code style
- ✅ Add tests for new features
- ✅ Update documentation
- ✅ Keep commits atomic and descriptive

### Areas for Contribution

- 🐛 Bug fixes
- 📝 Documentation improvements
- 🎨 UI/UX enhancements
- 🧪 Additional test cases
- 🌍 Language support
- 📱 Mobile optimization

---

## 📖 Documentation

- [Installation Guide](./INSTALLATION.md) - Detailed setup instructions
- [Lab Solutions](./LAB_SOLUTIONS.md) - Complete step-by-step solutions
- [API Reference](#-api-documentation) - Full API documentation

---

## 🐛 Bug Reports

Found a bug? Please report it!

1. Go to [Issues](https://github.com/MoDarK-MK/OWASPLABs/issues)
2. Click "New Issue"
3. Describe the bug with:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Screenshots (if applicable)

---

## 📞 Support & Contact

- 📧 Email: [your-email@example.com]
- 💬 Discord: [Join our community]
- 🐦 Twitter: [@YourHandle]
- 🌐 Website: [your-website.com]

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 MoDarK-MK

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 🙏 Acknowledgments

- OWASP Project for security guidelines
- Security community for feedback and contributions
- All contributors who have helped improve this platform

---

## 📊 Project Statistics

| Metric                  | Value                 |
| ----------------------- | --------------------- |
| Total Labs              | 160+                  |
| Vulnerabilities Covered | 8                     |
| Max Points              | 16,000 XP             |
| Difficulty Levels       | 4                     |
| Contributors            | Open for contribution |
| Last Updated            | 2024                  |

---

<div align="center">

### ⭐ If you find this project helpful, please consider giving it a star!

[Star Repository](https://github.com/MoDarK-MK/OWASPLABs/stargazers) • [Report Issue](https://github.com/MoDarK-MK/OWASPLABs/issues) • [Request Feature](https://github.com/MoDarK-MK/OWASPLABs/discussions)

**Made with ❤️ for the security community**

</div>
