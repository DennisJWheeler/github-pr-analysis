# Configuration Templates

This directory contains pre-built configuration templates for different PR analysis scenarios. Choose the one that best matches your needs or use them as starting points for custom configurations.

## Available Templates

### 📊 `basic-pr-analysis.yaml`
**For: Teams getting started with PR metrics**
- Focuses on fundamental PR metrics
- Minimal tool detection (just common bots)
- Simple reporting
- Good baseline for any team

**Metrics tracked:**
- Time to first review
- Time to merge
- Review cycles
- First-pass approval rate
- PR size distribution

### 🤖 `coderabbit-evaluation.yaml`
**For: Teams evaluating CodeRabbit AI specifically**
- CodeRabbit-focused analysis
- Baseline vs post-deployment comparison
- AI suggestion tracking and adoption rates
- Industry benchmark comparisons

**Key features:**
- CodeRabbit suggestion detection
- Adoption rate analysis
- Before/after comparison metrics
- ROI calculation support

### 🔬 `multi-tool-comparison.yaml`
**For: Teams using multiple PR improvement tools**
- Comprehensive tool detection
- Cross-tool comparison analysis
- Category-based evaluation (AI, static analysis, dependency management)
- Advanced reporting

**Supported tools:**
- CodeRabbit, GitHub Copilot (AI review)
- SonarQube, Qodana (static analysis)
- Dependabot, Renovate (dependency management)

## Usage

### Quick Start
```bash
# Copy a template to use as your config
cp configs/basic-pr-analysis.yaml config.yaml

# Or specify config file directly
./github-pr-analysis analyze --config configs/coderabbit-evaluation.yaml owner/repo
```

### Customization

1. **Start with a template** that's closest to your needs
2. **Edit tool settings** to match your environment:
   ```yaml
   tools:
     - name: "your-tool"
       enabled: true
       usernames: ["your-bot-username"]
   ```
3. **Adjust thresholds** for your team:
   ```yaml
   settings:
     large_pr_lines: 600    # Adjust based on your team's standards
     stale_days: 7          # Adjust based on your review SLA
   ```
4. **Enable/disable metrics** based on what you need:
   ```yaml
   metrics:
     tool_suggestions: true   # Only if you have AI/analysis tools
     draft_duration: false    # If your team doesn't use draft PRs
   ```

## Configuration Structure

### Tool Definition
```yaml
- name: "tool-identifier"           # Unique identifier
  display_name: "Human Readable"   # Name for reports
  enabled: true                    # Whether to analyze this tool
  category: "ai_review"            # Tool category
  usernames:                       # Bot usernames to detect
    - "bot-name[bot]"
  suggestion_patterns:             # Text patterns for suggestions
    - "suggests:"
  comment_patterns:               # Text patterns for comments
    - "analysis:"
```

### Metric Categories

**Time Metrics:**
- `time_to_first_review` - Hours from PR creation to first review
- `time_to_merge` - Hours from creation to merge
- `draft_duration` - Time spent in draft status

**Quality Metrics:**
- `review_cycles` - Number of change request cycles
- `first_pass_approval` - PRs approved without changes
- `human_vs_bot_reviews` - Review source breakdown

**Tool-Specific:**
- `tool_suggestions` - AI/tool suggestions count
- `tool_adoption` - How many suggestions were used
- `tool_comments` - Total comments from tools

**Classification:**
- `classify_stale_prs` - Flag slow-moving PRs
- `classify_large_prs` - Flag oversized PRs
- `classify_bot_prs` - Flag automated PRs

### Settings

```yaml
settings:
  stale_days: 14          # Days without activity = stale
  large_pr_lines: 800     # Lines changed = large PR
  outlier_days: 30        # Days open = potential outlier
  use_percentiles: true   # Use median/percentiles vs means
  outlier_method: "iqr"   # Statistical method for outliers
```

## Examples by Use Case

### 🎯 **"Establish Baseline Metrics"**
Use: `basic-pr-analysis.yaml`
```bash
./github-pr-analysis analyze --config configs/basic-pr-analysis.yaml \
  --days 180 --output-dir baseline/ owner/repo
```

### 🤖 **"Evaluate CodeRabbit Impact"**
Use: `coderabbit-evaluation.yaml`
```bash
# Before CodeRabbit (baseline)
./github-pr-analysis analyze --config configs/coderabbit-evaluation.yaml \
  --days 180 --output-dir before-ai/ owner/repo

# After CodeRabbit (impact measurement)
./github-pr-analysis analyze --config configs/coderabbit-evaluation.yaml \
  --days 90 --output-dir after-ai/ owner/repo
```

### 🔬 **"Compare Multiple Tools"**
Use: `multi-tool-comparison.yaml`
```bash
./github-pr-analysis analyze --config configs/multi-tool-comparison.yaml \
  --days 90 --output-dir tool-comparison/ owner/repo
```

## Creating Custom Configs

1. **Copy existing template**: Start with closest match
2. **Modify tool detection**: Add your specific tools
3. **Adjust thresholds**: Match your team's standards
4. **Test with small dataset**: Use `--days 7` first
5. **Iterate**: Refine based on results

## Common Patterns

### Enterprise Setup
```yaml
# Disable public tools, enable enterprise ones
tools:
  - name: "enterprise-sonar"
    usernames: ["your-sonar-instance[bot]"]

  - name: "internal-ai-tool"
    usernames: ["internal-reviewer[bot]"]
```

### Research/Academic
```yaml
# Enable all metrics for comprehensive analysis
metrics:
  time_to_first_review: true
  time_to_merge: true
  draft_duration: true
  # ... enable everything

reporting:
  json_export: true  # For data science analysis
  csv_export: true
```

### Agile Teams
```yaml
settings:
  stale_days: 3        # Fast-moving sprints
  large_pr_lines: 200  # Small, frequent changes
  outlier_days: 7      # Short iteration cycles
```

Have questions? Check the main README.md or create an issue!