#!/bin/bash
# OWASP Labs Platform - Quick Reference Guide

echo "🛡️  OWASP Vulnerable Labs Platform - Quick Start"
echo "=================================================="
echo ""

# Check Docker
echo "✓ Checking Prerequisites..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose."
    exit 1
fi

echo "✓ Docker and Docker Compose found"
echo ""

# Show commands
echo "📚 Available Commands:"
echo ""
echo "1️⃣  START PLATFORM:"
echo "   docker-compose up -d"
echo ""

echo "2️⃣  VIEW LOGS:"
echo "   docker-compose logs -f"
echo "   docker-compose logs backend"
echo "   docker-compose logs frontend"
echo ""

echo "3️⃣  ACCESS SERVICES:"
echo "   Frontend:  http://localhost:3000"
echo "   Backend:   http://localhost:5000"
echo "   Database:  localhost:5432"
echo "   Redis:     localhost:6379"
echo ""

echo "4️⃣  STOP PLATFORM:"
echo "   docker-compose down"
echo ""

echo "5️⃣  RESET DATABASE:"
echo "   docker-compose down -v && docker-compose up -d"
echo ""

echo "6️⃣  ACCESS DATABASE:"
echo "   docker exec -it owasp-labs-db psql -U labs_admin -d owasp_labs"
echo ""

echo "7️⃣  VIEW ALL CONTAINERS:"
echo "   docker-compose ps"
echo ""

echo "8️⃣  REBUILD SERVICES:"
echo "   docker-compose up -d --build"
echo ""

echo "📝 DEFAULT CREDENTIALS:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""

echo "📖 DOCUMENTATION:"
echo "   • SETUP.md - Installation guide"
echo "   • LAB_DESCRIPTIONS.md - All labs"
echo "   • SOLUTION_GUIDES.md - Hints & solutions"
echo "   • PROJECT_SUMMARY.md - Project overview"
echo ""

echo "⚠️  IMPORTANT NOTES:"
echo "   • For educational use only"
echo "   • Never deploy to production"
echo "   • Change default credentials"
echo "   • Run on isolated networks"
echo ""

echo "Ready to start? Run:"
echo "   docker-compose up -d"
echo ""
