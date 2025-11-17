package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v56/github"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

// Configuration structures
type ToolConfig struct {
	Name               string   `yaml:"name"`
	DisplayName        string   `yaml:"display_name"`
	Enabled            bool     `yaml:"enabled"`
	Category           string   `yaml:"category"`
	Usernames          []string `yaml:"usernames"`
	SuggestionPatterns []string `yaml:"suggestion_patterns"`
	CommentPatterns    []string `yaml:"comment_patterns"`
}

type MetricsConfig struct {
	TimeToFirstReview    bool `yaml:"time_to_first_review"`
	TimeToMerge          bool `yaml:"time_to_merge"`
	DraftDuration        bool `yaml:"draft_duration"`
	ReviewCycles         bool `yaml:"review_cycles"`
	FirstPassApproval    bool `yaml:"first_pass_approval"`
	HumanVsBotReviews    bool `yaml:"human_vs_bot_reviews"`
	ToolSuggestions      bool `yaml:"tool_suggestions"`
	ToolAdoption         bool `yaml:"tool_adoption"`
	ToolComments         bool `yaml:"tool_comments"`
	SizeAnalysis         bool `yaml:"size_analysis"`
	OutlierDetection     bool `yaml:"outlier_detection"`
	ClassifyStalePRs     bool `yaml:"classify_stale_prs"`
	ClassifyLargePRs     bool `yaml:"classify_large_prs"`
	ClassifyBotPRs       bool `yaml:"classify_bot_prs"`
}

type SettingsConfig struct {
	StaleDays              int      `yaml:"stale_days"`
	LargePRLines           int      `yaml:"large_pr_lines"`
	OutlierDays            int      `yaml:"outlier_days"`
	UsePercentiles         bool     `yaml:"use_percentiles"`
	OutlierMethod          string   `yaml:"outlier_method"`
	APIDelayMs             int      `yaml:"api_delay_ms"`
	MaxRetries             int      `yaml:"max_retries"`
	IgnoreUsersForTiming   []string `yaml:"ignore_users_for_timing"`
}

type ReportingConfig struct {
	CSVExport           bool `yaml:"csv_export"`
	MarkdownReport      bool `yaml:"markdown_report"`
	JSONExport          bool `yaml:"json_export"`
	ExecutiveSummary    bool `yaml:"executive_summary"`
	TimeMetrics         bool `yaml:"time_metrics"`
	QualityMetrics      bool `yaml:"quality_metrics"`
	ToolAnalysis        bool `yaml:"tool_analysis"`
	OutlierAnalysis     bool `yaml:"outlier_analysis"`
	Recommendations     bool `yaml:"recommendations"`
	BaselineComparison  bool `yaml:"baseline_comparison"`
	MultiToolComparison bool `yaml:"multi_tool_comparison"`
}

type Config struct {
	ProjectName string            `yaml:"project_name"`
	Description string            `yaml:"description"`
	Tools       []ToolConfig      `yaml:"tools"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	Settings    SettingsConfig    `yaml:"settings"`
	Reporting   ReportingConfig   `yaml:"reporting"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(filename string) (*Config, error) {
	// Default config if no file specified
	if filename == "" {
		return getDefaultConfig(), nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// getDefaultConfig returns a basic default configuration
func getDefaultConfig() *Config {
	return &Config{
		ProjectName: "PR Analysis",
		Description: "Generic PR analysis with basic tool detection",
		Tools: []ToolConfig{
			{
				Name:        "dependabot",
				DisplayName: "Dependabot",
				Enabled:     true,
				Category:    "dependency_management",
				Usernames:   []string{"dependabot[bot]", "dependabot"},
			},
		},
		Metrics: MetricsConfig{
			TimeToFirstReview: true,
			TimeToMerge:       true,
			ReviewCycles:      true,
			FirstPassApproval: true,
			SizeAnalysis:      true,
			ClassifyStalePRs:  true,
			ClassifyLargePRs:  true,
			ClassifyBotPRs:    true,
		},
		Settings: SettingsConfig{
			StaleDays:      14,
			LargePRLines:   800,
			OutlierDays:    30,
			UsePercentiles: true,
			OutlierMethod:  "iqr",
			APIDelayMs:     100,
			MaxRetries:     3,
			IgnoreUsersForTiming: []string{
				"dependabot[bot]", "dependabot",
				"github-actions[bot]", "github-actions",
				"renovate[bot]", "renovate",
				"coderabbitai", "coderabbit[bot]", "coderabbit",
				"sonar-qube[bot]", "sonarcloud[bot]",
				"qodana[bot]", "jetbrains[bot]",
			},
		},
		Reporting: ReportingConfig{
			CSVExport:        true,
			MarkdownReport:   true,
			ExecutiveSummary: true,
			TimeMetrics:      true,
			QualityMetrics:   true,
			Recommendations:  true,
		},
	}
}

// ToolMetrics holds metrics for a specific tool
type ToolMetrics struct {
	ToolName    string `json:"tool_name"`
	Suggestions int    `json:"suggestions"`
	Adopted     int    `json:"adopted"`
	Comments    int    `json:"comments"`
}

// PRMetrics holds all metrics for a single pull request
type PRMetrics struct {
	Number       int       `json:"number"`
	Title        string    `json:"title"`
	Author       string    `json:"author"`
	CreatedAt    time.Time `json:"created_at"`
	MergedAt     *time.Time `json:"merged_at,omitempty"`
	ClosedAt     *time.Time `json:"closed_at,omitempty"`
	Draft        bool      `json:"draft"`
	State        string    `json:"state"`
	Additions    int       `json:"additions"`
	Deletions    int       `json:"deletions"`
	ChangedFiles int       `json:"changed_files"`
	Commits      int       `json:"commits"`

	// Time-based metrics (in hours)
	TimeToFirstReview *float64 `json:"time_to_first_review_hours,omitempty"`
	TimeToMerge       *float64 `json:"time_to_merge_hours,omitempty"`
	DraftDuration     *float64 `json:"draft_duration_hours,omitempty"`
	ReviewCycles      int      `json:"review_cycles"`

	// Review metrics
	FirstPassApproval bool `json:"first_pass_approval"`
	TotalReviews      int  `json:"total_reviews"`
	HumanReviews      int  `json:"human_reviews"`
	BotReviews        int  `json:"bot_reviews"`

	// Tool-specific metrics (generic)
	ToolMetrics map[string]ToolMetrics `json:"tool_metrics"`

	// Derived metrics
	TotalLinesChanged int `json:"total_lines_changed"`

	// Classification flags
	IsStale    bool `json:"is_stale"`
	IsOutlier  bool `json:"is_outlier"`
	IsLargePR  bool `json:"is_large_pr"`
	IsBotPR    bool `json:"is_bot_pr"`
}

// StatisticalSummary holds statistical analysis of metrics
type StatisticalSummary struct {
	Count      int     `json:"count"`
	Mean       float64 `json:"mean"`
	Median     float64 `json:"median"`
	P75        float64 `json:"p75"`
	P90        float64 `json:"p90"`
	StdDev     float64 `json:"std_dev"`
	Min        float64 `json:"min"`
	Max        float64 `json:"max"`
	OutlierMin float64 `json:"outlier_min"`
	OutlierMax float64 `json:"outlier_max"`
}

// EdgeCaseAnalyzer handles outlier detection and classification
type EdgeCaseAnalyzer struct {
	StaleDays         int
	LargePRThreshold  int
	OutlierDaysThreshold int
}

// NewEdgeCaseAnalyzer creates a new edge case analyzer with default thresholds
func NewEdgeCaseAnalyzer() *EdgeCaseAnalyzer {
	return &EdgeCaseAnalyzer{
		StaleDays:         14,  // PRs with no activity for 14+ days
		LargePRThreshold:  800, // PRs with 800+ lines changed
		OutlierDaysThreshold: 30, // PRs open for 30+ days
	}
}

// ClassifyPR adds classification flags to a PR using configuration
func (e *EdgeCaseAnalyzer) ClassifyPR(pr *PRMetrics, config *Config) {
	// Check if stale (no recent activity and still open)
	pr.IsStale = pr.State == "open" &&
		time.Since(pr.CreatedAt).Hours() > float64(e.StaleDays * 24)

	// Check if large PR
	pr.IsLargePR = pr.TotalLinesChanged > e.LargePRThreshold

	// Check if outlier by time (open too long)
	pr.IsOutlier = time.Since(pr.CreatedAt).Hours() > float64(e.OutlierDaysThreshold * 24)

	// Check if bot PR using configured tools
	pr.IsBotPR = false
	for _, tool := range config.Tools {
		if tool.Enabled && isToolUser(pr.Author, tool.Usernames) {
			pr.IsBotPR = true
			break
		}
	}
}

// CalculateStatistics computes statistical summary for a slice of float64 values
func CalculateStatistics(values []float64) StatisticalSummary {
	if len(values) == 0 {
		return StatisticalSummary{}
	}

	// Sort values for percentile calculations
	sorted := make([]float64, len(values))
	copy(sorted, values)

	// Simple bubble sort (good enough for our use case)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Calculate basic statistics
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	// Calculate standard deviation
	sumSquaredDiffs := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquaredDiffs += diff * diff
	}
	stdDev := 0.0
	if len(values) > 1 {
		variance := sumSquaredDiffs / float64(len(values) - 1)
		stdDev = math.Sqrt(variance)
	}

	// Percentiles
	median := percentile(sorted, 50)
	p75 := percentile(sorted, 75)
	p90 := percentile(sorted, 90)

	// Outlier thresholds using IQR method
	q1 := percentile(sorted, 25)
	q3 := percentile(sorted, 75)
	iqr := q3 - q1
	outlierMin := q1 - 1.5*iqr
	outlierMax := q3 + 1.5*iqr

	return StatisticalSummary{
		Count:      len(values),
		Mean:       mean,
		Median:     median,
		P75:        p75,
		P90:        p90,
		StdDev:     stdDev,
		Min:        sorted[0],
		Max:        sorted[len(sorted)-1],
		OutlierMin: outlierMin,
		OutlierMax: outlierMax,
	}
}

// percentile calculates the given percentile from sorted values
func percentile(sortedValues []float64, p float64) float64 {
	if len(sortedValues) == 0 {
		return 0
	}
	if len(sortedValues) == 1 {
		return sortedValues[0]
	}

	index := (p / 100.0) * float64(len(sortedValues) - 1)
	lower := int(index)
	upper := lower + 1

	if upper >= len(sortedValues) {
		return sortedValues[len(sortedValues)-1]
	}

	weight := index - float64(lower)
	return sortedValues[lower]*(1-weight) + sortedValues[upper]*weight
}

// FilterOutliers removes statistical outliers from metrics slice
func FilterOutliers(metrics []*PRMetrics, field string) []*PRMetrics {
	values := extractFloatField(metrics, field)
	if len(values) == 0 {
		return metrics
	}

	stats := CalculateStatistics(values)
	var filtered []*PRMetrics

	for i, pr := range metrics {
		value := values[i]
		if value >= stats.OutlierMin && value <= stats.OutlierMax {
			filtered = append(filtered, pr)
		} else {
			pr.IsOutlier = true
		}
	}

	return filtered
}

// extractFloatField extracts float values from PRMetrics for statistical analysis
func extractFloatField(metrics []*PRMetrics, field string) []float64 {
	var values []float64
	for _, pr := range metrics {
		switch field {
		case "time_to_first_review":
			if pr.TimeToFirstReview != nil {
				values = append(values, *pr.TimeToFirstReview)
			}
		case "time_to_merge":
			if pr.TimeToMerge != nil {
				values = append(values, *pr.TimeToMerge)
			}
		case "total_lines_changed":
			values = append(values, float64(pr.TotalLinesChanged))
		case "review_cycles":
			values = append(values, float64(pr.ReviewCycles))
		}
	}
	return values
}

// Analyzer handles GitHub PR analysis
type Analyzer struct {
	client   *github.Client
	ctx      context.Context
	repoName string
	owner    string
	repo     string
	config   *Config
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer(token, repoName string, config *Config) (*Analyzer, error) {
	ctx := context.Background()

	// Parse repository name
	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("repository name must be in format 'owner/repo'")
	}

	// Create OAuth2 token source
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	// Create GitHub client
	client := github.NewClient(tc)

	return &Analyzer{
		client:   client,
		ctx:      ctx,
		repoName: repoName,
		owner:    parts[0],
		repo:     parts[1],
		config:   config,
	}, nil
}

// DateRange represents a time window for filtering PRs
type DateRange struct {
	Start *time.Time
	End   *time.Time
}

// GetPullRequests fetches pull requests from the repository
func (a *Analyzer) GetPullRequests(state string, dateRange *DateRange) ([]*github.PullRequest, error) {
	opt := &github.PullRequestListOptions{
		State:     state,
		Sort:      "created",
		Direction: "desc",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	var allPRs []*github.PullRequest
	var stopFetching bool

	for {
		prs, resp, err := a.client.PullRequests.List(a.ctx, a.owner, a.repo, opt)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch pull requests: %w", err)
		}

		// Filter by date range if specified
		var filteredPRs []*github.PullRequest
		for _, pr := range prs {
			if pr.CreatedAt == nil {
				continue
			}

			createdAt := *pr.CreatedAt

			// Check if PR is before start date (too old)
			if dateRange != nil && dateRange.Start != nil && createdAt.Before(*dateRange.Start) {
				// Since PRs are sorted by creation date (desc), we can stop fetching
				stopFetching = true
				break
			}

			// Check if PR is after end date (too new)
			if dateRange != nil && dateRange.End != nil && createdAt.After(*dateRange.End) {
				continue
			}

			// PR is within the date range
			filteredPRs = append(filteredPRs, pr)
		}

		allPRs = append(allPRs, filteredPRs...)

		// Stop fetching if we've gone past the start date or no more pages
		if stopFetching || resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	if dateRange != nil {
		if dateRange.Start != nil && dateRange.End != nil {
			log.Printf("Found %d pull requests between %s and %s\n",
				len(allPRs),
				dateRange.Start.Format("2006-01-02"),
				dateRange.End.Format("2006-01-02"))
		} else if dateRange.Start != nil {
			log.Printf("Found %d pull requests after %s\n",
				len(allPRs),
				dateRange.Start.Format("2006-01-02"))
		} else if dateRange.End != nil {
			log.Printf("Found %d pull requests before %s\n",
				len(allPRs),
				dateRange.End.Format("2006-01-02"))
		}
	} else {
		log.Printf("Found %d pull requests (all time)\n", len(allPRs))
	}

	return allPRs, nil
}

// AnalyzePRTimeline extracts timing metrics from a PR
func (a *Analyzer) AnalyzePRTimeline(pr *github.PullRequest) (*float64, *float64, *float64, error) {
	// Get reviews for time analysis
	reviews, _, err := a.client.PullRequests.ListReviews(a.ctx, a.owner, a.repo, pr.GetNumber(), nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get reviews: %w", err)
	}

	var timeToFirstReview *float64
	var timeToMerge *float64
	var draftDuration *float64

	// Time to first review (excluding ignored bot users)
	if len(reviews) > 0 {
		var firstReviewTime *time.Time
		for _, review := range reviews {
			if review.SubmittedAt != nil && review.User != nil {
				// Skip reviews from ignored users (bots)
				reviewerUsername := review.User.GetLogin()
				if isUserIgnoredForTiming(reviewerUsername, a.config.Settings.IgnoreUsersForTiming) {
					continue
				}

				reviewTime := review.SubmittedAt.Time
				if firstReviewTime == nil || reviewTime.Before(*firstReviewTime) {
					firstReviewTime = &reviewTime
				}
			}
		}
		if firstReviewTime != nil && pr.CreatedAt != nil {
			hours := firstReviewTime.Sub(pr.CreatedAt.Time).Hours()
			timeToFirstReview = &hours
		}
	}

	// Time to merge
	if pr.MergedAt != nil && pr.CreatedAt != nil {
		hours := pr.MergedAt.Time.Sub(pr.CreatedAt.Time).Hours()
		timeToMerge = &hours
	}

	// Draft duration (placeholder - would need timeline API for exact timing)
	if pr.GetDraft() {
		// For current draft PRs, calculate time since creation
		hours := time.Since(pr.CreatedAt.Time).Hours()
		draftDuration = &hours
	}

	return timeToFirstReview, timeToMerge, draftDuration, nil
}

// AnalyzeReviewCycles counts review cycles and determines first-pass approval
func (a *Analyzer) AnalyzeReviewCycles(pr *github.PullRequest) (int, bool, error) {
	reviews, _, err := a.client.PullRequests.ListReviews(a.ctx, a.owner, a.repo, pr.GetNumber(), nil)
	if err != nil {
		return 0, false, fmt.Errorf("failed to get reviews: %w", err)
	}

	reviewCycles := 0
	firstPassApproval := false

	// Count CHANGES_REQUESTED reviews
	for _, review := range reviews {
		if review.GetState() == "CHANGES_REQUESTED" {
			reviewCycles++
		}
	}

	// Check for first-pass approval
	if len(reviews) > 0 {
		hasChangesRequested := false
		hasApproval := false

		for _, review := range reviews {
			if review.GetState() == "CHANGES_REQUESTED" {
				hasChangesRequested = true
			}
			if review.GetState() == "APPROVED" {
				hasApproval = true
			}
		}

		firstPassApproval = hasApproval && !hasChangesRequested
	}

	return reviewCycles, firstPassApproval, nil
}

// AnalyzeToolActivity analyzes tool activity based on configuration
func (a *Analyzer) AnalyzeToolActivity(pr *github.PullRequest) (map[string]ToolMetrics, error) {
	// Get review comments
	reviewComments, _, err := a.client.PullRequests.ListComments(a.ctx, a.owner, a.repo, pr.GetNumber(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get review comments: %w", err)
	}

	// Get issue comments
	issueComments, _, err := a.client.Issues.ListComments(a.ctx, a.owner, a.repo, pr.GetNumber(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get issue comments: %w", err)
	}

	toolMetrics := make(map[string]ToolMetrics)

	// Initialize metrics for enabled tools
	for _, tool := range a.config.Tools {
		if tool.Enabled {
			toolMetrics[tool.Name] = ToolMetrics{
				ToolName:    tool.Name,
				Suggestions: 0,
				Adopted:     0, // Placeholder for now
				Comments:    0,
			}
		}
	}

	// Check review comments
	for _, comment := range reviewComments {
		username := comment.GetUser().GetLogin()
		body := strings.ToLower(comment.GetBody())

		for _, tool := range a.config.Tools {
			if !tool.Enabled {
				continue
			}

			if isToolUser(username, tool.Usernames) {
				metrics := toolMetrics[tool.Name]
				metrics.Comments++

				// Look for suggestions based on configured patterns
				for _, pattern := range tool.SuggestionPatterns {
					if strings.Contains(body, strings.ToLower(pattern)) {
						metrics.Suggestions++
						break // Count only once per comment
					}
				}

				toolMetrics[tool.Name] = metrics
			}
		}
	}

	// Check issue comments
	for _, comment := range issueComments {
		username := comment.GetUser().GetLogin()

		for _, tool := range a.config.Tools {
			if !tool.Enabled {
				continue
			}

			if isToolUser(username, tool.Usernames) {
				metrics := toolMetrics[tool.Name]
				metrics.Comments++
				toolMetrics[tool.Name] = metrics
			}
		}
	}

	return toolMetrics, nil
}

// AnalyzeReviewsBreakdown categorizes reviews by human vs bot
func (a *Analyzer) AnalyzeReviewsBreakdown(pr *github.PullRequest) (int, int, int, error) {
	reviews, _, err := a.client.PullRequests.ListReviews(a.ctx, a.owner, a.repo, pr.GetNumber(), nil)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to get reviews: %w", err)
	}

	totalReviews := len(reviews)
	botReviews := 0
	humanReviews := 0

	botUsers := []string{"coderabbitai", "coderabbit", "coderabbit[bot]", "dependabot", "github-actions"}

	for _, review := range reviews {
		if isCodeRabbitUser(review.GetUser().GetLogin(), botUsers) {
			botReviews++
		} else {
			humanReviews++
		}
	}

	return totalReviews, humanReviews, botReviews, nil
}

// AnalyzeSinglePR analyzes a single pull request and returns metrics
func (a *Analyzer) AnalyzeSinglePR(pr *github.PullRequest) (*PRMetrics, error) {
	timeToFirstReview, timeToMerge, draftDuration, err := a.AnalyzePRTimeline(pr)
	if err != nil {
		return nil, fmt.Errorf("timeline analysis failed: %w", err)
	}

	reviewCycles, firstPassApproval, err := a.AnalyzeReviewCycles(pr)
	if err != nil {
		return nil, fmt.Errorf("review cycles analysis failed: %w", err)
	}

	toolMetrics, err := a.AnalyzeToolActivity(pr)
	if err != nil {
		return nil, fmt.Errorf("tool analysis failed: %w", err)
	}

	totalReviews, humanReviews, botReviews, err := a.AnalyzeReviewsBreakdown(pr)
	if err != nil {
		return nil, fmt.Errorf("reviews breakdown failed: %w", err)
	}

	// Create PR metrics struct
	prMetrics := &PRMetrics{
		Number:       pr.GetNumber(),
		Title:        pr.GetTitle(),
		Author:       pr.GetUser().GetLogin(),
		CreatedAt:    pr.GetCreatedAt().Time,
		MergedAt:     timePtr(pr.GetMergedAt().Time),
		ClosedAt:     timePtr(pr.GetClosedAt().Time),
		Draft:        pr.GetDraft(),
		State:        pr.GetState(),
		Additions:    pr.GetAdditions(),
		Deletions:    pr.GetDeletions(),
		ChangedFiles: pr.GetChangedFiles(),
		Commits:      pr.GetCommits(),

		TimeToFirstReview: timeToFirstReview,
		TimeToMerge:       timeToMerge,
		DraftDuration:     draftDuration,
		ReviewCycles:      reviewCycles,

		FirstPassApproval: firstPassApproval,
		TotalReviews:      totalReviews,
		HumanReviews:      humanReviews,
		BotReviews:        botReviews,

		ToolMetrics: toolMetrics,

		TotalLinesChanged: pr.GetAdditions() + pr.GetDeletions(),
	}

	// Apply edge case classification
	edgeAnalyzer := NewEdgeCaseAnalyzer()
	edgeAnalyzer.ClassifyPR(prMetrics, a.config)

	return prMetrics, nil
}

// AnalyzeRepository analyzes all PRs in the repository
func (a *Analyzer) AnalyzeRepository(dateRange *DateRange) ([]*PRMetrics, error) {
	prs, err := a.GetPullRequests("all", dateRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get pull requests: %w", err)
	}

	var metrics []*PRMetrics
	for i, pr := range prs {
		log.Printf("Analyzing PR #%d (%d/%d)", pr.GetNumber(), i+1, len(prs))

		prMetrics, err := a.AnalyzeSinglePR(pr)
		if err != nil {
			log.Printf("Warning: Error analyzing PR #%d: %v", pr.GetNumber(), err)
			continue
		}

		metrics = append(metrics, prMetrics)
	}

	log.Printf("Successfully analyzed %d pull requests", len(metrics))
	return metrics, nil
}

// ExportCSV exports metrics to CSV format
func ExportCSV(metrics []*PRMetrics, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header - include dynamic tool columns
	header := []string{
		"number", "title", "author", "created_at", "merged_at", "closed_at",
		"draft", "state", "additions", "deletions", "changed_files", "commits",
		"time_to_first_review_hours", "time_to_merge_hours", "draft_duration_hours",
		"review_cycles", "first_pass_approval", "total_reviews", "human_reviews", "bot_reviews",
		"total_lines_changed", "is_stale", "is_outlier", "is_large_pr", "is_bot_pr",
	}

	// Add tool-specific columns based on metrics data
	toolColumns := make(map[string]bool)
	for _, m := range metrics {
		for toolName := range m.ToolMetrics {
			if !toolColumns[toolName] {
				header = append(header, fmt.Sprintf("%s_suggestions", toolName))
				header = append(header, fmt.Sprintf("%s_adopted", toolName))
				header = append(header, fmt.Sprintf("%s_comments", toolName))
				toolColumns[toolName] = true
			}
		}
	}

	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write data
	for _, m := range metrics {
		row := []string{
			strconv.Itoa(m.Number),
			m.Title,
			m.Author,
			m.CreatedAt.Format(time.RFC3339),
			formatTimePtr(m.MergedAt),
			formatTimePtr(m.ClosedAt),
			strconv.FormatBool(m.Draft),
			m.State,
			strconv.Itoa(m.Additions),
			strconv.Itoa(m.Deletions),
			strconv.Itoa(m.ChangedFiles),
			strconv.Itoa(m.Commits),
			formatFloatPtr(m.TimeToFirstReview),
			formatFloatPtr(m.TimeToMerge),
			formatFloatPtr(m.DraftDuration),
			strconv.Itoa(m.ReviewCycles),
			strconv.FormatBool(m.FirstPassApproval),
			strconv.Itoa(m.TotalReviews),
			strconv.Itoa(m.HumanReviews),
			strconv.Itoa(m.BotReviews),
			strconv.Itoa(m.TotalLinesChanged),
			strconv.FormatBool(m.IsStale),
			strconv.FormatBool(m.IsOutlier),
			strconv.FormatBool(m.IsLargePR),
			strconv.FormatBool(m.IsBotPR),
		}

		// Add tool-specific data in same order as headers
		for toolName := range toolColumns {
			if toolMetric, exists := m.ToolMetrics[toolName]; exists {
				row = append(row, strconv.Itoa(toolMetric.Suggestions))
				row = append(row, strconv.Itoa(toolMetric.Adopted))
				row = append(row, strconv.Itoa(toolMetric.Comments))
			} else {
				row = append(row, "0", "0", "0") // Default values if tool not present
			}
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	log.Printf("Exported metrics to %s", filename)
	return nil
}

// GenerateMarkdownReport creates a comprehensive markdown analysis report
func GenerateMarkdownReport(metrics []*PRMetrics, repoName, outputFile string, dateRange *DateRange) error {
	if len(metrics) == 0 {
		return fmt.Errorf("no metrics provided for report generation")
	}

	// Calculate statistics for various metrics
	timeToFirstReviewValues := extractFloatField(metrics, "time_to_first_review")
	timeToMergeValues := extractFloatField(metrics, "time_to_merge")
	totalLinesChangedValues := extractFloatField(metrics, "total_lines_changed")
	reviewCyclesValues := extractFloatField(metrics, "review_cycles")

	timeToFirstReviewStats := CalculateStatistics(timeToFirstReviewValues)
	timeToMergeStats := CalculateStatistics(timeToMergeValues)
	totalLinesChangedStats := CalculateStatistics(totalLinesChangedValues)
	reviewCyclesStats := CalculateStatistics(reviewCyclesValues)

	// Calculate categorical counts
	totalPRs := len(metrics)
	mergedPRs := 0
	draftPRs := 0
	openPRs := 0
	stalePRs := 0
	largePRs := 0
	botPRs := 0
	firstPassApprovals := 0
	prsWithTools := make(map[string]int)
	totalToolSuggestions := make(map[string]int)
	totalToolComments := make(map[string]int)

	for _, pr := range metrics {
		if pr.MergedAt != nil {
			mergedPRs++
		}
		if pr.Draft {
			draftPRs++
		}
		if pr.State == "open" {
			openPRs++
		}
		if pr.IsStale {
			stalePRs++
		}
		if pr.IsLargePR {
			largePRs++
		}
		if pr.IsBotPR {
			botPRs++
		}
		if pr.FirstPassApproval {
			firstPassApprovals++
		}

		// Count tool activity
		for toolName, toolMetric := range pr.ToolMetrics {
			if toolMetric.Comments > 0 {
				prsWithTools[toolName]++
			}
			totalToolSuggestions[toolName] += toolMetric.Suggestions
			totalToolComments[toolName] += toolMetric.Comments
		}
	}

	// Calculate percentages
	firstPassApprovalRate := 0.0
	if mergedPRs > 0 {
		firstPassApprovalRate = float64(firstPassApprovals) / float64(mergedPRs) * 100
	}

	// Calculate average tool activity
	avgToolSuggestions := make(map[string]float64)
	avgToolComments := make(map[string]float64)
	if totalPRs > 0 {
		for toolName := range totalToolSuggestions {
			avgToolSuggestions[toolName] = float64(totalToolSuggestions[toolName]) / float64(totalPRs)
			avgToolComments[toolName] = float64(totalToolComments[toolName]) / float64(totalPRs)
		}
	}

	// Generate tool analysis section
	toolAnalysisSection := ""
	if len(prsWithTools) > 0 {
		for toolName := range prsWithTools {
			toolAnalysisSection += fmt.Sprintf(`
### %s Analysis
- **PRs with %s Comments:** %d (%.1f%% of total)
- **Average %s Suggestions per PR:** %.1f
- **Average %s Comments per PR:** %.1f
- **Total %s Suggestions:** %d
- **Total %s Comments:** %d
`,
				strings.Title(toolName),
				strings.Title(toolName), prsWithTools[toolName], float64(prsWithTools[toolName])/float64(totalPRs)*100,
				strings.Title(toolName), avgToolSuggestions[toolName],
				strings.Title(toolName), avgToolComments[toolName],
				strings.Title(toolName), totalToolSuggestions[toolName],
				strings.Title(toolName), totalToolComments[toolName])
		}
	} else {
		toolAnalysisSection = "No tool activity detected in the analyzed PRs."
	}

	// Build date range description
	dateRangeDesc := "All time"
	if dateRange != nil {
		if dateRange.Start != nil && dateRange.End != nil {
			dateRangeDesc = fmt.Sprintf("%s to %s",
				dateRange.Start.Format("2006-01-02"),
				dateRange.End.Format("2006-01-02"))
		} else if dateRange.Start != nil {
			dateRangeDesc = fmt.Sprintf("After %s",
				dateRange.Start.Format("2006-01-02"))
		} else if dateRange.End != nil {
			dateRangeDesc = fmt.Sprintf("Before %s",
				dateRange.End.Format("2006-01-02"))
		}
	}

	// Generate report content
	report := fmt.Sprintf(`# GitHub PR Analysis Report

**Generated:** %s
**Repository:** %s
**Analysis Period:** %s (%d pull requests)

## Executive Summary

- **Total PRs Analyzed:** %d
- **Merged PRs:** %d
- **Currently Open:** %d
- **Draft PRs:** %d
- **Stale PRs (>14 days):** %d
- **Large PRs (>800 lines):** %d
- **Bot PRs:** %d

## Time-Based Metrics

### Time to First Review
- **Count:** %d PRs with reviews
- **Median:** %.1f hours
- **75th Percentile:** %.1f hours
- **90th Percentile:** %.1f hours
- **Average:** %.1f hours

### Time to Merge
- **Count:** %d merged PRs
- **Median:** %.1f hours
- **75th Percentile:** %.1f hours
- **90th Percentile:** %.1f hours
- **Average:** %.1f hours

## Quality Metrics

### Review Process
- **First-Pass Approval Rate:** %.1f%% (%d of %d merged PRs)
- **Average Review Cycles:** %.1f
- **Median Review Cycles:** %.1f

### PR Size Analysis
- **Median Lines Changed:** %.0f
- **75th Percentile Lines Changed:** %.0f
- **90th Percentile Lines Changed:** %.0f
- **Large PRs (>800 lines):** %d (%.1f%% of total)

## Tool Activity Analysis

%s

## Outlier Analysis

### Time Outliers
- **Outlier Threshold (Time to First Review):** >%.1f hours
- **Outlier Threshold (Time to Merge):** >%.1f hours

### Size Outliers
- **Large PR Threshold:** >%.0f lines changed
- **Size Outlier Threshold:** >%.0f lines changed

## Key Insights & Recommendations

### Baseline Metrics (Pre-AI Implementation)
This analysis establishes your baseline performance before CodeRabbit deployment:

**Time Performance:**
- Median time to first review: **%.1f hours**
- Median time to merge: **%.1f hours**
- First-pass approval rate: **%.1f%%**

**Quality Indicators:**
- Average review cycles: **%.1f**
- Large PRs (>800 lines): **%d PRs (%.1f%%)**
- Stale PRs: **%d PRs**

### Targets for CodeRabbit Impact

**Expected Improvements with AI:**
1. **Time to First Review:** Target 30-50%% reduction (goal: %.1f-%.1f hours)
2. **First-Pass Approval Rate:** Target +15-20%% improvement (goal: %.1f-%.1f%%)
3. **Review Cycles:** Target 20-30%% reduction (goal: %.1f cycles)

**Quality Monitoring:**
- Track post-merge defects for PRs analyzed in this period
- Monitor if large PRs decrease with AI guidance
- Watch for changes in human reviewer engagement

### Next Steps

1. **Deploy CodeRabbit** on this repository
2. **Baseline Period:** Allow 3-6 months for team adoption and learning
3. **Re-analyze:** Run this tool again with same time periods for comparison
4. **Key Metrics to Watch:**
   - Time to first review (should improve dramatically)
   - CodeRabbit suggestion adoption rate (target: 40-60%%)
   - Human reviewer focus shift to complex architectural issues

### Statistical Notes

- **Percentile Metrics:** This report uses percentiles (p50, p75, p90) rather than averages to minimize outlier impact
- **Outlier Detection:** PRs flagged as outliers are tracked separately but included in overall counts
- **Edge Cases:** Stale, large, and bot PRs are classified for separate analysis

### Data Quality

- **Coverage:** %d%% of PRs have review data
- **Completeness:** %d%% of merged PRs have timing data
- **Bot Activity:** %.1f%% of PRs are from bots (tracked separately)

---

*Report generated by GitHub PR Analysis Tool*
*For questions or improvements, see project documentation*
`,
		time.Now().Format("2006-01-02 15:04:05 MST"),
		repoName,
		dateRangeDesc,
		totalPRs,
		// Executive summary
		totalPRs, mergedPRs, openPRs, draftPRs, stalePRs, largePRs, botPRs,
		// Time to first review
		timeToFirstReviewStats.Count, timeToFirstReviewStats.Median, timeToFirstReviewStats.P75, timeToFirstReviewStats.P90, timeToFirstReviewStats.Mean,
		// Time to merge
		timeToMergeStats.Count, timeToMergeStats.Median, timeToMergeStats.P75, timeToMergeStats.P90, timeToMergeStats.Mean,
		// Quality metrics
		firstPassApprovalRate, firstPassApprovals, mergedPRs,
		reviewCyclesStats.Mean, reviewCyclesStats.Median,
		// PR size
		totalLinesChangedStats.Median, totalLinesChangedStats.P75, totalLinesChangedStats.P90,
		largePRs, float64(largePRs)/float64(totalPRs)*100,
		// Tool Analysis (dynamic)
		toolAnalysisSection,
		// Outliers
		timeToFirstReviewStats.OutlierMax, timeToMergeStats.OutlierMax,
		float64(800), totalLinesChangedStats.OutlierMax,
		// Baseline insights
		timeToFirstReviewStats.Median, timeToMergeStats.Median, firstPassApprovalRate,
		// Quality
		reviewCyclesStats.Mean, largePRs, float64(largePRs)/float64(totalPRs)*100, stalePRs,
		// Targets
		timeToFirstReviewStats.Median*0.5, timeToFirstReviewStats.Median*0.7,
		firstPassApprovalRate+15, firstPassApprovalRate+20,
		reviewCyclesStats.Mean*0.7,
		// Data quality
		int(float64(timeToFirstReviewStats.Count)/float64(totalPRs)*100),
		int(float64(timeToMergeStats.Count)/float64(totalPRs)*100),
		float64(botPRs)/float64(totalPRs)*100,
	)

	// Write report to file
	if err := os.WriteFile(outputFile, []byte(report), 0644); err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}

	log.Printf("Generated markdown report: %s", outputFile)
	return nil
}

// Helper functions
func isToolUser(username string, toolUsernames []string) bool {
	username = strings.ToLower(username)
	for _, toolUser := range toolUsernames {
		if strings.Contains(username, strings.ToLower(toolUser)) {
			return true
		}
	}
	return false
}

// Legacy function for compatibility during transition
func isCodeRabbitUser(username string, botUsers []string) bool {
	return isToolUser(username, botUsers)
}

// isUserIgnoredForTiming checks if a username should be ignored for timing calculations
func isUserIgnoredForTiming(username string, ignoreUsers []string) bool {
	username = strings.ToLower(username)
	for _, ignoreUser := range ignoreUsers {
		if strings.ToLower(ignoreUser) == username {
			return true
		}
	}
	return false
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func formatFloatPtr(f *float64) string {
	if f == nil {
		return ""
	}
	return fmt.Sprintf("%.2f", *f)
}

// CLI Commands
var rootCmd = &cobra.Command{
	Use:   "github-pr-analysis",
	Short: "GitHub PR Analysis Tool for CodeRabbit Evaluation",
	Long:  "Analyze GitHub pull requests to establish baselines and evaluate AI code review tools like CodeRabbit.",
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [owner/repo]",
	Short: "Analyze pull requests in a repository",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("token")
		if token == "" {
			token = os.Getenv("GITHUB_TOKEN")
			if token == "" {
				return fmt.Errorf("GitHub token is required. Set --token flag or GITHUB_TOKEN environment variable")
			}
		}

		configFile, _ := cmd.Flags().GetString("config")
		days, _ := cmd.Flags().GetInt("days")
		startDateStr, _ := cmd.Flags().GetString("start-date")
		endDateStr, _ := cmd.Flags().GetString("end-date")

		// Parse date range
		var dateRange *DateRange
		if startDateStr != "" || endDateStr != "" || days > 0 {
			dateRange = &DateRange{}

			// Parse start date
			if startDateStr != "" {
				startDate, err := time.Parse("2006-01-02", startDateStr)
				if err != nil {
					return fmt.Errorf("invalid start-date format. Use YYYY-MM-DD: %w", err)
				}
				dateRange.Start = &startDate
			}

			// Parse end date
			if endDateStr != "" {
				endDate, err := time.Parse("2006-01-02", endDateStr)
				if err != nil {
					return fmt.Errorf("invalid end-date format. Use YYYY-MM-DD: %w", err)
				}
				// Set end date to end of day
				endOfDay := endDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
				dateRange.End = &endOfDay
			}

			// Handle legacy days parameter (if no start/end date specified)
			if days > 0 && startDateStr == "" && endDateStr == "" {
				startDate := time.Now().AddDate(0, 0, -days)
				dateRange.Start = &startDate
			}

			// Validate date range
			if dateRange.Start != nil && dateRange.End != nil && dateRange.Start.After(*dateRange.End) {
				return fmt.Errorf("start-date cannot be after end-date")
			}
		}

		outputDir, _ := cmd.Flags().GetString("output-dir")
		generateCSV, _ := cmd.Flags().GetBool("csv")
		generateReport, _ := cmd.Flags().GetBool("report")

		// Load configuration
		config, err := LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		log.Printf("Loaded configuration: %s", config.ProjectName)
		if config.Description != "" {
			log.Printf("Description: %s", config.Description)
		}

		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Create analyzer with config
		analyzer, err := NewAnalyzer(token, args[0], config)
		if err != nil {
			return fmt.Errorf("failed to create analyzer: %w", err)
		}

		// Analyze repository
		metrics, err := analyzer.AnalyzeRepository(dateRange)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		if len(metrics) == 0 {
			log.Println("No pull requests found to analyze")
			return nil
		}

		// Generate outputs
		timestamp := time.Now().Format("20060102_150405")
		repoSafe := strings.ReplaceAll(args[0], "/", "_")

		if generateCSV {
			csvFile := filepath.Join(outputDir, fmt.Sprintf("%s_pr_metrics_%s.csv", repoSafe, timestamp))
			if err := ExportCSV(metrics, csvFile); err != nil {
				return fmt.Errorf("failed to export CSV: %w", err)
			}
		}

		if generateReport {
			mdFile := filepath.Join(outputDir, fmt.Sprintf("%s_pr_analysis_%s.md", repoSafe, timestamp))
			if err := GenerateMarkdownReport(metrics, args[0], mdFile, dateRange); err != nil {
				return fmt.Errorf("failed to generate report: %w", err)
			}
		}

		log.Println("Analysis complete!")
		return nil
	},
}

func init() {
	analyzeCmd.Flags().StringP("config", "c", "", "Configuration file (YAML) for tool definitions and metrics")
	analyzeCmd.Flags().StringP("token", "t", "", "GitHub personal access token (or set GITHUB_TOKEN env var)")
	analyzeCmd.Flags().IntP("days", "d", 0, "Number of days back to analyze (default: all time)")
	analyzeCmd.Flags().String("start-date", "", "Start date for analysis (YYYY-MM-DD format)")
	analyzeCmd.Flags().String("end-date", "", "End date for analysis (YYYY-MM-DD format)")
	analyzeCmd.Flags().StringP("output-dir", "o", "./output", "Output directory for reports")
	analyzeCmd.Flags().Bool("csv", true, "Export CSV data")
	analyzeCmd.Flags().Bool("report", true, "Generate markdown report")

	rootCmd.AddCommand(analyzeCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}