# GitHub PR Analysis Tool

A comprehensive tool to analyze GitHub pull request metrics for evaluating the effectiveness of PR improvement tools including AI code review, static analysis, and automation tools.

## Features

- **Time-based Metrics**: Time to first review, time to merge, draft duration
- **Quality Metrics**: Review cycles, first-pass approval rates, human vs bot reviews
- **Tool Activity Tracking**: Configurable detection of comments, suggestions, and adoption patterns
- **Draft PR Handling**: Properly excludes draft time from metrics
- **Outlier Detection**: Statistical analysis to handle edge cases
- **Export Options**: CSV data export and markdown reports
- **Containerized**: Docker support for consistent execution

## Quick Start

### Using Docker (Recommended)

1. **Setup**
   ```bash
   # Clone or create the project directory
   cp .env.example .env
   # Edit .env and add your GitHub token
   # GITHUB_TOKEN=ghp_your_token_here
   ```

2. **Verify Setup**
   ```bash
   # Test your token and permissions (recommended first step)
   ./verify-permissions.sh
   ```

3. **Build and Test**
   ```bash
   # Build the container
   docker-compose build

   # Start with a small test
   docker-compose run --rm github-pr-analysis analyze \
     --days 7 \
     --output-dir /app/output \
     owner/repo

   # Full analysis after testing
   docker-compose run --rm github-pr-analysis analyze \
     --days 180 \
     --output-dir /app/output \
     owner/repo
   ```

4. **View Results**
   ```bash
   # Results will be in the ./output directory
   ls -la output/
   ```

### Using Go Directly

1. **Prerequisites**
   ```bash
   # Go 1.21 or later required
   go version
   ```

2. **Setup**
   ```bash
   # Install dependencies
   go mod download

   # Set GitHub token
   export GITHUB_TOKEN="your_token_here"
   ```

3. **Build and Run**
   ```bash
   # Build
   go build -o github-pr-analysis

   # Run analysis
   ./github-pr-analysis analyze owner/repo

   # With options
   ./github-pr-analysis analyze \
     --days 90 \
     --output-dir ./output \
     --csv \
     --report \
     owner/repo
   ```

## Configuration

### GitHub Token Setup

#### Option A: Classic Personal Access Token (Recommended)

1. **Create Token**
   - Visit: https://github.com/settings/tokens
   - Click **"Generate new token"** → **"Generate new token (classic)"**

2. **Configure Token**
   - **Note**: `PR Analysis Tool`
   - **Expiration**: 90 days (recommended)
   - **Select Scopes**:
     - ✅ `public_repo` - For public repositories only
     - ✅ `repo` - For private repositories (if needed)

3. **Copy Token** (⚠️ Copy immediately - you won't see it again!)
   - Token format: `ghp_1A2B3C4D5E6F...`

#### Option B: Fine-grained Token (Beta)
- Visit: https://github.com/settings/personal-access-tokens/fine-grained
- **Repository access**: Public repositories (read)
- **Permissions**: Pull requests (Read), Issues (Read), Metadata (Read)

#### Set Your Token
```bash
# Option 1: Environment variable
export GITHUB_TOKEN="ghp_your_token_here"

# Option 2: .env file (recommended)
echo "GITHUB_TOKEN=ghp_your_token_here" > .env
```

### Tool Configuration

Configure which PR improvement tools to analyze using YAML configuration files:

```bash
# Use the default built-in configuration (Dependabot only)
./github-pr-analysis analyze owner/repo

# Use a specific configuration file
./github-pr-analysis analyze --config configs/coderabbit-evaluation.yaml owner/repo

# Use multi-tool analysis
./github-pr-analysis analyze --config configs/multi-tool-comparison.yaml owner/repo
```

**Available Template Configurations:**
- `configs/basic-pr-analysis.yaml` - Basic PR metrics only
- `configs/coderabbit-evaluation.yaml` - CodeRabbit-focused analysis
- `configs/multi-tool-comparison.yaml` - Multiple tools (CodeRabbit, SonarQube, Dependabot, etc.)

**Custom Tool Configuration Example:**
```yaml
tools:
  - name: "your-tool"
    display_name: "Your Custom Tool"
    enabled: true
    category: "ai_review"
    usernames: ["your-bot-username", "tool[bot]"]
    suggestion_patterns: ["suggests", "recommends", "consider"]
    comment_patterns: ["analysis", "review"]
```

### Command Options

```
github-pr-analysis analyze [owner/repo] [flags]

Flags:
  -c, --config string     Configuration file (YAML) for tool definitions and metrics
  -t, --token string      GitHub personal access token (or set GITHUB_TOKEN env var)
  -d, --days int          Number of days back to analyze (default: all time)
  -o, --output-dir string Output directory for reports (default "./output")
      --csv               Export CSV data (default true)
      --report            Generate markdown report (default true)
  -h, --help              Help for analyze
```

## Output Files

The tool generates several output files:

### CSV Export
- **File**: `{repo}_pr_metrics_{timestamp}.csv`
- **Content**: Raw metrics data for further analysis
- **Columns**: All PR metrics including time-based, quality, and CodeRabbit data

### Markdown Report (Coming Soon)
- **File**: `{repo}_pr_analysis_{timestamp}.md`
- **Content**: Executive summary with key insights and recommendations
- **Sections**: Time metrics, quality indicators, CodeRabbit effectiveness

## Metrics Explained

### Time-Based Metrics
- **Time to First Review**: Hours from PR creation to first review submission
- **Time to Merge**: Hours from PR creation to merge (excluding draft time)
- **Draft Duration**: Time spent in draft status (tracked separately)

### Quality Metrics
- **Review Cycles**: Number of CHANGES_REQUESTED cycles before approval
- **First-Pass Approval**: PRs approved without any change requests
- **Human vs Bot Reviews**: Breakdown of review sources

### Tool Activity Metrics
- **Suggestions**: Tool-generated suggestions detected by configured patterns
- **Comments**: Total comments from configured tool usernames
- **Adoption**: Suggestions that were implemented (configurable tracking)
- **Per-Tool Breakdown**: Individual metrics for each configured tool (CodeRabbit, SonarQube, etc.)

### Size & Complexity
- **Lines Changed**: Additions + deletions
- **Files Changed**: Number of files modified
- **Large PRs**: PRs with >800 lines changed (tracked separately)

## Use Cases

### Baseline Establishment (Before Tool Implementation)
```bash
# Analyze 6 months of historical data to establish baseline metrics
docker-compose run --rm github-pr-analysis analyze \
  --config configs/basic-pr-analysis.yaml \
  --days 180 \
  --output-dir ./baseline \
  your-org/your-repo
```

### Real-World CodeRabbit Evaluation Example
```bash
# STEP 1: Establish 6-month baseline before deploying CodeRabbit
export GITHUB_TOKEN="your_token"
./github-pr-analysis analyze \
  --config configs/basic-pr-analysis.yaml \
  --days 180 \
  --output-dir ./baseline \
  mycompany/main-app

# STEP 2: After 3 months with CodeRabbit, measure impact
./github-pr-analysis analyze \
  --config configs/coderabbit-evaluation.yaml \
  --days 90 \
  --output-dir ./post-coderabbit \
  mycompany/main-app

# STEP 3: Compare the reports to see CodeRabbit's effectiveness!
# Key metrics to compare:
# - Time to first review (should decrease)
# - Time to merge (should decrease)
# - First-pass approval rate (should increase)
# - CodeRabbit suggestion adoption rate (track new metric)
```

### Tool Effectiveness Analysis (After Implementation)
```bash
# Analyze CodeRabbit impact
docker-compose run --rm github-pr-analysis analyze \
  --config configs/coderabbit-evaluation.yaml \
  --days 90 \
  --output-dir ./post-implementation \
  your-org/your-repo

# Multi-tool comparison analysis
docker-compose run --rm github-pr-analysis analyze \
  --config configs/multi-tool-comparison.yaml \
  --days 90 \
  --output-dir ./tool-comparison \
  your-org/your-repo
```

### Ongoing Monitoring & A/B Testing
```bash
# Weekly analysis with specific tool tracking
docker-compose run --rm github-pr-analysis analyze \
  --config configs/your-custom-config.yaml \
  --days 7 \
  --output-dir ./weekly \
  your-org/your-repo
```

## Best Practices

### Baseline Collection
- **Duration**: Collect 3-6 months of baseline data before deploying any PR improvement tools
- **Consistency**: Use same time periods and filters for before/after comparison
- **Segmentation**: Track different PR sizes separately for accurate comparison
- **Configuration**: Use basic-pr-analysis.yaml config for clean baseline without tool noise

### Tool Evaluation
- **Adoption Period**: Allow 3-6 months after deployment for team adaptation to new tools
- **Key Metrics**: Focus on time to first review, review cycles, and first-pass approval rates
- **Tool-Specific Tracking**: Configure usernames and patterns for each tool you want to evaluate
- **Quality Tracking**: Monitor post-merge defects and code quality improvements (requires manual tracking)
- **A/B Testing**: Compare different tools or configurations using separate analysis runs

### Statistical Analysis
- **Use Percentiles**: Prefer median (p50), p75, p90 over averages (less affected by outliers)
- **Handle Outliers**: PRs >800 lines or >30 days old should be analyzed separately
- **Filter Drafts**: Exclude draft time from time-based metrics for accuracy

## Development

### Docker Development Environment
```bash
# Interactive development container
docker-compose --profile dev run --rm dev

# Build and test
go build && go test ./...
```

### Adding Features
1. **New Tool Support**: Add tool configuration to YAML files with usernames and patterns
2. **New Metrics**: Update `PRMetrics` struct for additional data points
3. **Analysis Logic**: Implement logic in `AnalyzeToolActivity()` for new patterns
4. **Export Updates**: CSV export automatically includes new tool columns
5. **Report Generation**: Markdown reports automatically include configured tools

### Adding New Tools
1. Create or update a configuration file in `configs/` directory
2. Define tool usernames, suggestion patterns, and comment patterns
3. Enable the tool and set appropriate category
4. Run analysis - the tool will automatically be tracked in outputs

## Verification & Testing

### Before Running Analysis

**1. Verify Your Setup** (Recommended First Step)
```bash
# Test your token and repository access
./verify-permissions.sh
```

**2. Start Small**
```bash
# Test with just 1 day of recent data
./github-pr-analysis analyze --days 1 --token "$GITHUB_TOKEN" owner/repo
```

**3. Then Scale Up**
```bash
# 7-day test
./github-pr-analysis analyze --days 7 --token "$GITHUB_TOKEN" owner/repo

# Full baseline (6 months)
./github-pr-analysis analyze --days 180 --token "$GITHUB_TOKEN" owner/repo
```

## Troubleshooting

### Token Issues

**"Bad credentials" or 401 errors:**
```bash
# Test token directly
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# If that fails, create new token at:
# https://github.com/settings/tokens
```

**Environment variable not working:**
```bash
# Use token flag directly instead
./github-pr-analysis analyze --token "ghp_your_token" owner/repo

# Or explicitly source .env
source .env && ./github-pr-analysis analyze owner/repo
```

**Token expired:**
- GitHub tokens expire (check Settings → Developer Settings → Tokens)
- Create new token with same scopes
- Update `.env` file

### Rate Limits & Public Repositories

**Why you need a token for public repos:**
- **Without token**: 60 requests/hour (would take 100+ hours for large repos)
- **With token**: 5,000 requests/hour (completes in 1-2 hours)
- **Public repos don't require permissions**, just rate limit increases

**Rate limit errors:**
```bash
# Check current limits
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/rate_limit

# If rate limited, either:
# - Wait 1 hour for reset
# - Use --days flag to reduce scope
```

### Common Issues

**"Repository not found":**
- Verify repository name format: `owner/repo`
- Check if repository exists: `https://github.com/owner/repo`
- For private repos, ensure token has `repo` scope

**Environment variable issues:**
- File `.env` not found → Copy from `.env.example`
- Token not loaded → Use `source .env && command` or `--token` flag
- Wrong format → Should be `GITHUB_TOKEN=ghp_your_token_here`

**Analysis failures:**
- Start with `--days 1` to test basic functionality
- Check repository has pull requests
- Verify network connectivity to api.github.com

### Performance & Large Repositories

**Memory Usage**: Large repositories may require significant memory
**API Calls**: Each PR requires 3-4 API calls (PR + reviews + comments)
**Time Estimates**:
- Small repos (<100 PRs): Minutes
- Medium repos (100-1000 PRs): 15-60 minutes
- Large repos (1000+ PRs): 1-3 hours

**For very large repos:**
```bash
# Start with recent data
./github-pr-analysis analyze --days 30 owner/repo

# Then expand timeframe
./github-pr-analysis analyze --days 180 owner/repo
```

### Verification Tools

This repository includes helpful verification tools:

- **`verify-permissions.sh`** - Test GitHub API access and permissions
- **`TOKEN_SETUP.md`** - Step-by-step token creation guide
- **`test-commands.sh`** - Interactive testing menu

Run these before attempting full analysis of large repositories!

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request with clear description

## Support

For issues and questions:
1. Check existing GitHub Issues
2. Create new issue with reproduction steps
3. Include log output and configuration details