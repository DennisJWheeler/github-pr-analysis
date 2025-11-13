#!/bin/bash
# Quick Test Commands for GitHub PR Analysis

set -e

# Default to a well-known public repository for testing
REPO="${1:-microsoft/vscode}"

echo "🧪 GitHub PR Analysis - Test Commands"
echo "===================================="
echo "Repository: $REPO"
echo "Usage: $0 [owner/repo]"
echo "       (defaults to microsoft/vscode for testing)"
echo ""

# Function to check if docker compose is available
check_docker() {
    if command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
        echo "✅ Docker Compose found (standalone)"
    elif docker compose version &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
        echo "✅ Docker Compose found (built-in CLI)"
    else
        echo "❌ Docker Compose not found. Please install Docker and Docker Compose."
        exit 1
    fi
}

# Function to check if .env exists
check_env() {
    if [ ! -f .env ]; then
        echo "❌ .env file not found!"
        echo "   Create it with: GITHUB_TOKEN=your_token_here"
        exit 1
    fi
    echo "✅ .env file found"
}

echo "🔍 Pre-flight Checks"
echo "--------------------"
check_docker
check_env
echo ""

echo "📝 Available Test Commands"
echo "-------------------------"
echo ""

echo "1️⃣  VERIFY PERMISSIONS FIRST:"
echo "   ./verify-permissions.sh"
echo ""

echo "2️⃣  BUILD THE CONTAINER:"
echo "   $DOCKER_COMPOSE build"
echo ""

echo "3️⃣  SMALL TEST (Last 7 days):"
echo "   $DOCKER_COMPOSE run --rm github-pr-analysis analyze \\"
echo "     --days 7 \\"
echo "     --output-dir /app/output \\"
echo "     $REPO"
echo ""

echo "4️⃣  MEDIUM TEST (Last 30 days):"
echo "   $DOCKER_COMPOSE run --rm github-pr-analysis analyze \\"
echo "     --days 30 \\"
echo "     --output-dir /app/output \\"
echo "     $REPO"
echo ""

echo "5️⃣  FULL BASELINE (6 months - for CodeRabbit comparison):"
echo "   $DOCKER_COMPOSE run --rm github-pr-analysis analyze \\"
echo "     --days 180 \\"
echo "     --output-dir /app/output \\"
echo "     $REPO"
echo ""

echo "6️⃣  CHECK RESULTS:"
echo "   ls -la output/"
echo "   # Look for .csv and .md files"
echo ""

# Interactive menu
echo "🚀 Quick Actions"
echo "----------------"
echo ""
echo "What would you like to do?"
echo ""
echo "v) Verify permissions"
echo "b) Build container"
echo "t) Run small test (7 days)"
echo "m) Run medium test (30 days)"
echo "f) Run full baseline (180 days)"
echo "r) Check results"
echo "q) Quit"
echo ""

read -p "Choose an option [v/b/t/m/f/r/q]: " choice

case $choice in
    v|V)
        echo ""
        echo "🔍 Running permission verification..."
        ./verify-permissions.sh
        ;;
    b|B)
        echo ""
        echo "🏗️  Building container..."
        $DOCKER_COMPOSE build
        echo "✅ Container built successfully!"
        ;;
    t|T)
        echo ""
        echo "🧪 Running small test (7 days)..."
        $DOCKER_COMPOSE run --rm github-pr-analysis analyze \
            --days 7 \
            --output-dir /app/output \
            $REPO
        echo ""
        echo "✅ Test complete! Check output/ directory for results."
        ;;
    m|M)
        echo ""
        echo "📊 Running medium test (30 days)..."
        $DOCKER_COMPOSE run --rm github-pr-analysis analyze \
            --days 30 \
            --output-dir /app/output \
            $REPO
        echo ""
        echo "✅ Analysis complete! Check output/ directory for results."
        ;;
    f|F)
        echo ""
        echo "📈 Running FULL baseline analysis (180 days)..."
        echo "⏱️  This may take 1-3 hours depending on repository size..."
        echo ""
        read -p "Continue? [y/N]: " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            $DOCKER_COMPOSE run --rm github-pr-analysis analyze \
                --days 180 \
                --output-dir /app/output \
                $REPO
            echo ""
            echo "🎉 BASELINE COMPLETE!"
            echo "   Your CodeRabbit baseline metrics are ready."
            echo "   Check output/ directory for detailed reports."
        else
            echo "Operation cancelled."
        fi
        ;;
    r|R)
        echo ""
        echo "📁 Results in output/ directory:"
        echo "-------------------------------"
        if [ -d "output" ]; then
            ls -la output/
            echo ""
            echo "File types:"
            echo "  .csv files: Raw data for analysis"
            echo "  .md files:  Executive summary reports"
        else
            echo "❌ No output directory found. Run an analysis first."
        fi
        ;;
    q|Q)
        echo "👋 Goodbye!"
        ;;
    *)
        echo "❌ Invalid option. Please choose v, b, t, m, f, r, or q."
        ;;
esac

echo ""