#!/bin/bash

set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

REPO="${1:-microsoft/vscode}"
GITHUB_API="https://api.github.com"

echo "========================================="
echo "GitHub API Permission Verification"
echo "========================================="
echo ""
echo "Repository: $REPO"
echo "Date: $(date)"
echo ""

# Function to test API endpoint
test_endpoint() {
    local endpoint=$1
    local description=$2
    local auth_header=""
    
    if [ ! -z "$GITHUB_TOKEN" ]; then
        auth_header="-H \"Authorization: token $GITHUB_TOKEN\""
    fi
    
    echo -n "Testing $description... "
    
    response=$(eval curl -s -w "\n%{http_code}" $auth_header "$GITHUB_API$endpoint" 2>&1)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
        echo "✓ SUCCESS (200)"
        return 0
    elif [ "$http_code" = "401" ]; then
        echo "✗ FAILED (401 - Bad credentials)"
        return 1
    elif [ "$http_code" = "403" ]; then
        echo "✗ FAILED (403 - Forbidden)"
        return 1
    elif [ "$http_code" = "404" ]; then
        echo "✗ FAILED (404 - Not Found)"
        return 1
    else
        echo "? UNEXPECTED ($http_code)"
        return 2
    fi
}

# 1. Check token validity
echo "1. TOKEN VALIDATION"
echo "-------------------"
if [ -z "$GITHUB_TOKEN" ]; then
    echo "⚠ WARNING: No GITHUB_TOKEN found"
    echo "  - For public repos, the API will work but with lower rate limits"
    echo "  - Token is in .env but may be invalid"
    echo ""
else
    echo "Token found: ${GITHUB_TOKEN:0:7}..."
    
    # Test user endpoint
    user_response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" "$GITHUB_API/user")
    
    if echo "$user_response" | grep -q '"login"'; then
        username=$(echo "$user_response" | grep '"login"' | head -1 | cut -d'"' -f4)
        echo "✓ Token is VALID"
        echo "  Authenticated as: $username"
        
        # Check token scopes
        scopes=$(curl -sI -H "Authorization: token $GITHUB_TOKEN" "$GITHUB_API/user" | grep -i "x-oauth-scopes:" | cut -d':' -f2 | tr -d '\r')
        if [ ! -z "$scopes" ]; then
            echo "  Token scopes:$scopes"
        else
            echo "  Token type: Fine-grained PAT (no classic scopes)"
        fi
    else
        echo "✗ Token is INVALID"
        echo "  Error: $(echo "$user_response" | grep '"message"' | cut -d'"' -f4)"
        echo ""
        echo "  The token in .env appears to be expired or invalid."
        echo "  You will need to create a new token."
    fi
fi
echo ""

# 2. Check repository access
echo "2. REPOSITORY ACCESS"
echo "--------------------"
test_endpoint "/repos/$REPO" "Repository metadata"
echo ""

# 3. Check pull requests access
echo "3. PULL REQUESTS ACCESS"
echo "-----------------------"
test_endpoint "/repos/$REPO/pulls?state=all&per_page=1" "List pull requests"
test_endpoint "/repos/$REPO/pulls/1" "Get specific PR"
echo ""

# 4. Check reviews access
echo "4. REVIEWS ACCESS"
echo "-----------------"
test_endpoint "/repos/$REPO/pulls/1/reviews" "List PR reviews"
echo ""

# 5. Check comments access
echo "5. COMMENTS ACCESS"
echo "------------------"
test_endpoint "/repos/$REPO/pulls/1/comments" "List review comments"
test_endpoint "/repos/$REPO/issues/1/comments" "List issue comments"
echo ""

# 6. Check rate limits
echo "6. RATE LIMIT STATUS"
echo "--------------------"
if [ ! -z "$GITHUB_TOKEN" ]; then
    rate_info=$(curl -s -H "Authorization: token $GITHUB_TOKEN" "$GITHUB_API/rate_limit")
else
    rate_info=$(curl -s "$GITHUB_API/rate_limit")
fi

if echo "$rate_info" | grep -q '"core"'; then
    core_limit=$(echo "$rate_info" | grep -A3 '"core"' | grep '"limit"' | cut -d':' -f2 | cut -d',' -f1 | tr -d ' ')
    core_remaining=$(echo "$rate_info" | grep -A3 '"core"' | grep '"remaining"' | cut -d':' -f2 | cut -d',' -f1 | tr -d ' ')
    
    echo "Core API:"
    echo "  Limit: $core_limit requests/hour"
    echo "  Remaining: $core_remaining requests"
    
    if [ "$core_limit" = "60" ]; then
        echo "  ⚠ WARNING: Unauthenticated (60/hour limit)"
    elif [ "$core_limit" = "5000" ]; then
        echo "  ✓ Authenticated (5,000/hour limit)"
    fi
fi
echo ""

# 7. Repository analysis
echo "7. REPOSITORY ANALYSIS"
echo "----------------------"
repo_info=$(curl -s "$GITHUB_API/repos/$REPO")
if echo "$repo_info" | grep -q '"full_name"'; then
    visibility=$(echo "$repo_info" | grep '"visibility"' | cut -d'"' -f4)
    is_private=$(echo "$repo_info" | grep '"private"' | head -1 | cut -d':' -f2 | cut -d',' -f1 | tr -d ' ')
    default_branch=$(echo "$repo_info" | grep '"default_branch"' | cut -d'"' -f4)
    
    echo "Repository: $REPO"
    echo "  Visibility: $visibility"
    echo "  Private: $is_private"
    echo "  Default branch: $default_branch"
    
    # Get PR count
    prs_count=$(curl -s "$GITHUB_API/repos/$REPO/pulls?state=all&per_page=1" | grep -c '"number"')
    echo "  Has pull requests: $([ $prs_count -gt 0 ] && echo 'Yes' || echo 'Unknown')"
fi
echo ""

# 8. Summary and recommendations
echo "========================================="
echo "SUMMARY & RECOMMENDATIONS"
echo "========================================="
echo ""

if [ -z "$GITHUB_TOKEN" ] || ! curl -s -H "Authorization: token $GITHUB_TOKEN" "$GITHUB_API/user" | grep -q '"login"'; then
    echo "⚠ TOKEN STATUS: INVALID or MISSING"
    echo ""
    echo "ISSUE:"
    echo "  Your GitHub token is either missing, expired, or invalid."
    echo ""
    echo "IMPACT FOR PUBLIC REPOSITORY:"
    echo "  ✓ You CAN still analyze public repositories"
    echo "  ✓ All required endpoints are accessible without authentication"
    echo "  ✗ Rate limits are severely restricted (60 requests/hour vs 5,000)"
    echo "  ✗ Large repositories may fail due to rate limiting"
    echo ""
    echo "RECOMMENDATIONS:"
    echo "  1. Create a new GitHub Personal Access Token"
    echo "  2. Go to: https://github.com/settings/tokens"
    echo "  3. For PUBLIC repos only, select:"
    echo "     - public_repo (read public repositories)"
    echo "     OR for fine-grained tokens:"
    echo "     - Repository access: Public repositories (read-only)"
    echo "     - Pull requests: Read-only"
    echo "  4. Update your .env file with the new token"
    echo ""
    echo "MINIMAL PERMISSIONS NEEDED FOR PUBLIC REPO:"
    echo "  - Pull requests: Read access"
    echo "  - Issues: Read access (for issue comments)"
    echo "  - Metadata: Read access (automatically included)"
    echo ""
else
    echo "✓ TOKEN STATUS: VALID"
    echo ""
    echo "Your token is valid and should work for the analysis."
    echo ""
    echo "REPOSITORY STATUS:"
    echo "  - Repository: public"
    echo "  - Access: Full read access available"
    echo ""
    echo "NEXT STEPS:"
    echo "  1. Your setup is ready for analysis"
    echo "  2. Run: ./github-pr-analysis analyze owner/repo"
    echo "  3. Or with Docker: docker-compose run --rm github-pr-analysis analyze owner/repo"
    echo "  4. Or test with: ./verify-permissions.sh owner/repo"
    echo ""
fi

echo "For more information, see README.md"
echo ""
