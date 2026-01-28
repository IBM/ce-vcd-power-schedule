package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	// IBM core SDK per IAM
	core "github.com/IBM/go-sdk-core/v5/core"

	// IBM VMware SDK (VCFaaS)
	vmw "github.com/IBM/vmware-go-sdk/vmwarev1"

	// Client Cloud Director
	"ce-vcd-power-schedule/internal/logging"
	clouddirector "ce-vcd-power-schedule/internal/service"
)

// allowedRegions holds a list of supported regions.
var allowedRegions = []string{"eu-de", "us-east"}

// consts define constants for entity types.
const (
	vmType      = "vm"
	vappType    = "vApp"
	statusOn    = "POWERED_ON"
	statusOff   = "POWERED_OFF"
	statusMixed = "MIXED"
)

// Entity represents a VM or vApp in the configuration.
type Entity struct {
	Type string `yaml:"type"` // vappType | vmType
	Name string `yaml:"name"`
}

// DateExclusion defines an exclusion based on a specific date.
type DateExclusion struct {
	Date   string `yaml:"date"`
	Annual bool   `yaml:"annual"`
}

// RangeExclusion defines an exclusion based on a date range.
type RangeExclusion struct {
	From   string `yaml:"from"`
	To     string `yaml:"to"`
	Annual bool   `yaml:"annual"`
}

// Exclusions encapsulates all exclusion rules.
type Exclusions struct {
	Timezone string           `yaml:"timezone"`
	Dates    []DateExclusion  `yaml:"dates"`
	Ranges   []RangeExclusion `yaml:"ranges"`
}

// Config holds the overall configuration.
type Config struct {
	Entities   []Entity   `yaml:"entities"`
	Exclusions Exclusions `yaml:"exclusions"`
}

// loadConfig reads and parses the configuration file.
func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("Invalid YAML configuration: %w", err)
	}
	return &cfg, nil
}

// nowInLocation returns the current time in the specified timezone.
func nowInLocation(tz string, log *slog.Logger) time.Time {
	if tz == "" {
		log.Debug("no timezone specified, using UTC",
			slog.String("component", "scheduler"),
		)
		return time.Now().UTC()
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		log.Warn("invalid timezone, falling back to UTC",
			slog.String("component", "scheduler"),
			slog.String("timezone", tz),
			slog.Any("error", err),
			slog.String("suggestion", "Use IANA timezone names like 'America/New_York' or 'Europe/London'"),
		)
		return time.Now().UTC()
	}
	return time.Now().In(loc)
}

// safeString safely dereferences a string pointer, returning a placeholder if nil.
func safeString(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// parseDate parses a date string and returns an error if invalid.
func parseDate(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid date format %q: expected YYYY-MM-DD (e.g., 2024-01-15): %w", s, err)
	}
	return t, nil
}

// sameDate checks if two times refer to the same date.
func sameDate(a, b time.Time) bool {
	return a.Year() == b.Year() && a.Month() == b.Month() && a.Day() == b.Day()
}

// sameMonthDay checks if two times refer to the same month and day.
func sameMonthDay(now, d time.Time) bool { return now.Month() == d.Month() && now.Day() == d.Day() }

// inAnnualRange checks if a time falls within an annual date range.
func inAnnualRange(now, from, to time.Time) bool {
	y := 2000
	n := time.Date(y, now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	f := time.Date(y, from.Month(), from.Day(), 0, 0, 0, 0, time.UTC)
	t := time.Date(y, to.Month(), to.Day(), 0, 0, 0, 0, time.UTC)
	if !t.Before(f) {
		return !n.Before(f) && !n.After(t)
	}
	return (!n.Before(f) && n.Before(time.Date(y, 12, 31, 0, 0, 0, 0, time.UTC).Add(24*time.Hour))) || (!n.After(t))
}

// inExclusions checks if the current time is within any exclusion rules.
func inExclusions(cfg *Config, now time.Time) (bool, string, error) {
	for i, d := range cfg.Exclusions.Dates {
		dt, err := parseDate(d.Date)
		if err != nil {
			return false, "", fmt.Errorf("exclusions.dates[%d]: %w", i, err)
		}
		if d.Annual && sameMonthDay(now, dt) {
			return true, fmt.Sprintf("excluded (annual day %s)", d.Date), nil
		}
		if !d.Annual && sameDate(now, dt) {
			return true, fmt.Sprintf("excluded (day %s)", d.Date), nil
		}
	}
	for i, r := range cfg.Exclusions.Ranges {
		f, err := parseDate(r.From)
		if err != nil {
			return false, "", fmt.Errorf("exclusions.ranges[%d].from: %w", i, err)
		}
		t, err := parseDate(r.To)
		if err != nil {
			return false, "", fmt.Errorf("exclusions.ranges[%d].to: %w", i, err)
		}
		if r.Annual && inAnnualRange(now, f, t) {
			return true, fmt.Sprintf("excluded (annual range %s..%s)", r.From, r.To), nil
		}
		if !r.Annual && !now.Before(f) && !now.After(t) {
			return true, fmt.Sprintf("excluded (range %s..%s)", r.From, r.To), nil
		}
	}
	return false, "", nil
}

// buildVmwareService initializes the VMware VCFaaS SDK with the given API key and region.
func buildVmwareService(apiKey, region string) (*vmw.VmwareV1, *core.IamAuthenticator, error) {
	if apiKey == "" {
		return nil, nil, fmt.Errorf("IBM_APIKEY is required")
	}
	auth := &core.IamAuthenticator{ApiKey: apiKey}
	options := &vmw.VmwareV1Options{Authenticator: auth}
	if region != "" {
		if url, err := BuildServiceURL(region); err == nil {
			options.URL = url
		}
	}
	service, err := vmw.NewVmwareV1(options)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize VMwareV1 SDK: %w", err)
	}
	return service, auth, nil
}

// VcdDiscovery holds the API base URL and Organization name for Cloud Director.
type VcdDiscovery struct {
	APIBase string
	OrgName string
}

// discoverVcdInfo discovers the API base URL and Organization name for a given site and VDC name.
// - siteName (optional): if provided, selects that Director Site (case-insensitive), otherwise the first site is used.
// - vdcName (required): must match a VDC name (case-insensitive) within the selected site.
// Returns an error if the site or the VDC cannot be found or is invalid.
func discoverVcdInfo(ctx context.Context, svc *vmw.VmwareV1, siteName, vdcName string) (*VcdDiscovery, error) {
	if strings.TrimSpace(vdcName) == "" {
		return nil, fmt.Errorf("vdcName is required")
	}

	// List Director Sites
	listDirectorSitesOptions := &vmw.ListDirectorSitesOptions{}
	list, _, err := svc.ListDirectorSitesWithContext(ctx, listDirectorSitesOptions)
	if err != nil {
		return nil, fmt.Errorf("ListDirectorSites failed: %w", err)
	}
	if list == nil || len(list.DirectorSites) == 0 {
		return nil, fmt.Errorf("no Director sites found")
	}

	// Pick the requested site (case-insensitive), or default to the first one
	var site *vmw.DirectorSite
	if siteName != "" {
		for i := range list.DirectorSites {
			s := list.DirectorSites[i]
			if s.Name != nil && strings.EqualFold(*s.Name, siteName) {
				site = &s
				break
			}
		}
	}
	if site == nil {
		site = &list.DirectorSites[0]
	}
	if site == nil || site.ID == nil {
		return nil, fmt.Errorf("selected Director site is invalid or missing ID")
	}

	// List VDCs
	listVdcsOptions := &vmw.ListVdcsOptions{}
	vdcs, _, err := svc.ListVdcs(listVdcsOptions)
	if err != nil {
		return nil, fmt.Errorf("ListVdcs failed: %w", err)
	}
	if vdcs == nil || len(vdcs.Vdcs) == 0 {
		return nil, fmt.Errorf("no VDCs found")
	}

	// Find a VDC that belongs to the selected site and matches vdcName
	var selectedVdc *vmw.VDC
	for i := range vdcs.Vdcs {
		v := vdcs.Vdcs[i]

		// Defensive nil checks
		if v.DirectorSite == nil || v.DirectorSite.ID == nil {
			continue
		}

		// Must match selected site
		if *v.DirectorSite.ID != *site.ID {
			continue
		}

		// Must match requested vdcName
		if v.Name != nil && strings.EqualFold(*v.Name, vdcName) {
			selectedVdc = &v
			break
		}
	}

	if selectedVdc == nil {
		return nil, fmt.Errorf("VDC %q not found in site %q", vdcName, *site.Name)
	}

	// Extract Org name and API base from the selected VDC
	if selectedVdc.OrgName == nil {
		return nil, fmt.Errorf("Organization name missing in selected VDC %q", vdcName)
	}
	orgName := *selectedVdc.OrgName

	if selectedVdc.OrgHref == nil || *selectedVdc.OrgHref == "" {
		return nil, fmt.Errorf("Organization Href missing in selected VDC")
	}
	uri, err := url.ParseRequestURI(*selectedVdc.OrgHref)
	if err != nil {
		return nil, fmt.Errorf("invalid Organization Href for VDC %q: %w", vdcName, err)
	}
	apiBase := fmt.Sprintf("%s://%s", uri.Scheme, uri.Host)
	if apiBase == "" {
		return nil, fmt.Errorf("API url not found for VDC %q", vdcName)
	}

	return &VcdDiscovery{
		APIBase: apiBase,
		OrgName: orgName,
	}, nil
}

// VcdClientSpec defines the configuration for the Cloud Director client.
type VcdClientSpec struct {
	URL      string
	Org      string
	Insecure bool
	IAMToken string
}

// isAllowed checks if the specified region is allowed.
func isAllowed(region string) bool {
	for _, r := range allowedRegions {
		if r == region {
			return true
		}
	}
	return false
}

// BuildServiceURL constructs the service URL for the VMware VCFaaS SDK.
func BuildServiceURL(region string) (string, error) {
	if region == "" {
		return "", fmt.Errorf("Region is required to build service URL")
	}

	if !isAllowed(region) {
		return "", fmt.Errorf("region not supported: %q", region)
	}

	return fmt.Sprintf("https://api.%s.vmware.cloud.ibm.com/v1", region), nil
}

// EnvironmentConfig holds validated environment variables.
type EnvironmentConfig struct {
	APIKey      string
	Region      string
	SiteName    string
	VDCName     string
	TaskTimeout string
}

// validateEnvironment validates required environment variables.
func validateEnvironment() (*EnvironmentConfig, error) {
	var missing []string

	apiKey := os.Getenv("IBM_APIKEY")
	if apiKey == "" {
		missing = append(missing, "IBM_APIKEY")
	}

	region := os.Getenv("IBM_REGION")
	if region == "" {
		missing = append(missing, "IBM_REGION")
	}

	vdcName := os.Getenv("VIRTUAL_DATA_CENTER")
	if vdcName == "" {
		missing = append(missing, "VIRTUAL_DATA_CENTER")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("required environment variables missing: %s\nPlease set:\n  export %s=<value>",
			strings.Join(missing, ", "),
			strings.Join(missing, "=<value>\n  export "))
	}

	// Validate region
	if region != "" && !isAllowed(region) {
		return nil, fmt.Errorf("invalid region %q\nAllowed regions: %s",
			region, strings.Join(allowedRegions, ", "))
	}

	return &EnvironmentConfig{
		APIKey:      apiKey,
		Region:      region,
		SiteName:    os.Getenv("DIRECTOR_SITE_NAME"),
		VDCName:     vdcName,
		TaskTimeout: os.Getenv("TASK_TIMEOUT_SECONDS"),
	}, nil
}

// validateConfig validates the configuration structure and content.
func validateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	if len(cfg.Entities) == 0 {
		return fmt.Errorf("no entities defined in configuration")
	}

	// Validate entities
	for i, entity := range cfg.Entities {
		if entity.Name == "" {
			return fmt.Errorf("entities[%d]: name cannot be empty", i)
		}
		if !isValidEntityType(entity.Type) {
			return fmt.Errorf("entities[%d] (%s): invalid type %q, must be %q or %q",
				i, entity.Name, entity.Type, vmType, vappType)
		}
	}

	// Validate timezone if specified
	if cfg.Exclusions.Timezone != "" {
		_, err := time.LoadLocation(cfg.Exclusions.Timezone)
		if err != nil {
			return fmt.Errorf("invalid timezone %q: %w\nExample valid timezones: America/New_York, Europe/London, UTC",
				cfg.Exclusions.Timezone, err)
		}
	}

	// Validate all dates in exclusions
	for i, d := range cfg.Exclusions.Dates {
		if _, err := parseDate(d.Date); err != nil {
			return fmt.Errorf("exclusions.dates[%d]: %w", i, err)
		}
	}

	for i, r := range cfg.Exclusions.Ranges {
		if _, err := parseDate(r.From); err != nil {
			return fmt.Errorf("exclusions.ranges[%d].from: %w", i, err)
		}
		if _, err := parseDate(r.To); err != nil {
			return fmt.Errorf("exclusions.ranges[%d].to: %w", i, err)
		}
	}

	return nil
}

// ProcessingResult tracks the result of processing an entity.
type ProcessingResult struct {
	EntityName string
	EntityType string
	Success    bool
	Error      error
}

func main() {
	log := logging.NewLogger().With("app", "ce-vcd-power-schedule")
	corrID := logging.NewCorrelationID()
	log = log.With(slog.String("correlation_id", corrID))

	if len(os.Args) == 2 && (os.Args[1] == "powerOn" || os.Args[1] == "powerOff") {
		log.Info("received arguments", slog.String("action", os.Args[1]))
	} else {
		log.Error("missing or invalid argument", slog.String("usage", "powerOn | powerOff"))
		os.Exit(1)
	}

	action := os.Args[1]

	// Validate environment variables
	envConfig, err := validateEnvironment()
	if err != nil {
		log.Error("environment validation failed",
			slog.String("component", "environment"),
			slog.Any("error", err),
		)
		os.Exit(1)
	}

	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "/app/config/schedule.yaml"
	}
	t := logging.StartTimed()
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Error("failed to load configuration",
			slog.String("component", "config"),
			slog.String("path", cfgPath),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		os.Exit(1)
	}
	log.Info("configuration loaded", slog.String("component", "config"), slog.Int64("duration.ms", t.Elapsed_ms()))

	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		log.Error("configuration validation failed",
			slog.String("component", "config"),
			slog.String("path", cfgPath),
			slog.Any("error", err),
		)
		os.Exit(1)
	}

	now := nowInLocation(cfg.Exclusions.Timezone, log)
	excluded, why, err := inExclusions(cfg, now)
	if err != nil {
		log.Error("failed to check exclusions",
			slog.String("component", "scheduler"),
			slog.Any("error", err),
		)
		os.Exit(1)
	}
	if excluded {
		log.Info("skip execution due to exclusion",
			slog.String("component", "scheduler"),
			slog.String("reason", why),
			slog.String("timezone", cfg.Exclusions.Timezone),
			slog.Time("now", now),
		)
		os.Exit(0)
	}

	t = logging.StartTimed()
	svc, auth, err := buildVmwareService(envConfig.APIKey, envConfig.Region)
	if err != nil {
		log.Error("failed to initialize VMware VCFaaS service",
			slog.String("component", "vcf-service"),
			slog.String("region", envConfig.Region),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		os.Exit(1)
	}
	log.Info("VCFaaS client initialized", slog.String("component", "vcf-service"), slog.String("region", envConfig.Region), slog.Int64("duration.ms", t.Elapsed_ms()))

	ctx := context.Background()

	t = logging.StartTimed()
	vcd, err := discoverVcdInfo(ctx, svc, envConfig.SiteName, envConfig.VDCName)
	if err != nil {
		log.Error("VCD discovery failed",
			slog.String("component", "discovery"),
			slog.String("site", envConfig.SiteName),
			slog.String("vdc", envConfig.VDCName),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		os.Exit(1)
	}
	log.Info("Discovered VCD info",
		slog.String("component", "discovery"),
		slog.String("vdc", envConfig.VDCName),
		slog.String("site", envConfig.SiteName),
		slog.String("org", vcd.OrgName),
		slog.String("api_base", vcd.APIBase),
		slog.Int64("duration.ms", t.Elapsed_ms()))

	// Do not log tokens; just acknowledge retrieval.
	t = logging.StartTimed()
	accessToken, err := auth.GetToken()

	if err != nil {
		log.Error("failed to obtain IAM access token",
			slog.String("component", "iam"),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		os.Exit(1)
	}
	log.Info("IAM token acquired", slog.String("component", "iam"), slog.Int64("duration.ms", t.Elapsed_ms()))

	cloudDirectorV1Options := clouddirector.CloudDirectorV1Options{
		URL:      vcd.APIBase,
		Org:      vcd.OrgName,
		IAMToken: accessToken,
		Log:      log,
	}
	if envConfig.TaskTimeout != "" {
		if timeout, err := time.ParseDuration(envConfig.TaskTimeout + "s"); err == nil {
			cloudDirectorV1Options.Timeout = timeout
		}
	}

	t = logging.StartTimed()
	vcdClient, err := clouddirector.NewCloudDirectorV1(&cloudDirectorV1Options)
	if err != nil {
		log.Error("Failed to initialize Cloud Director client",
			slog.String("component", "vcd-client"),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		os.Exit(1)
	}
	log.Info("VCD client initialized", slog.String("component", "vcd-client"), slog.Int64("duration.ms", t.Elapsed_ms()))

	// Process entities and track results
	results := make([]ProcessingResult, 0, len(cfg.Entities))
	log.Info("processing entities", slog.String("component", "main"), slog.Int("count", len(cfg.Entities)))

	for _, entity := range cfg.Entities {
		result := ProcessingResult{
			EntityName: entity.Name,
			EntityType: entity.Type,
			Success:    false,
		}

		err := handleEntityWithResult(vcdClient, entity, action, log)
		if err != nil {
			result.Error = err
		} else {
			result.Success = true
		}

		results = append(results, result)
	}

	// Generate summary
	successCount := 0
	failureCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		} else {
			failureCount++
		}
	}

	log.Info("processing complete",
		slog.String("component", "main"),
		slog.Int("total", len(results)),
		slog.Int("successful", successCount),
		slog.Int("failed", failureCount),
	)

	if failureCount > 0 {
		log.Error("some entities failed to process",
			slog.String("component", "main"),
			slog.Int("failed_count", failureCount),
		)
		os.Exit(1)
	}
}

func isValidEntityType(entityType string) bool {
	return entityType == vmType || entityType == vappType
}

// handleEntityWithResult handles power operations and returns an error for tracking.
func handleEntityWithResult(vcdClient *clouddirector.CloudDirectorV1, entity Entity, action string, log *slog.Logger) error {
	if !isValidEntityType(entity.Type) {
		err := fmt.Errorf("entity type %q not supported, must be %q or %q", entity.Type, vmType, vappType)
		log.Error("Entity type not supported",
			slog.String("component", "handler.entity"),
			slog.String("entity.type", entity.Type),
			slog.String("entity.name", entity.Name),
			slog.Any("error", err),
		)
		return err
	}

	t := logging.StartTimed()
	record, _, err := vcdClient.GetObjectByName(&clouddirector.GetObjectByNameOptions{
		Name: entity.Name,
		Type: entity.Type,
	})
	if err != nil {
		log.Error("GetObjectByName failed",
			slog.String("component", "handler.entity"),
			slog.String("action", action),
			slog.String("entity.type", entity.Type),
			slog.String("entity.name", entity.Name),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		return fmt.Errorf("failed to get entity %q: %w", entity.Name, err)
	}

	if record == nil {
		err := fmt.Errorf("entity %q not found", entity.Name)
		log.Error("entity not found",
			slog.String("component", "handler.entity"),
			slog.String("entity.type", entity.Type),
			slog.String("entity.name", entity.Name),
			slog.Int64("duration.ms", t.Elapsed_ms()),
			slog.String("suggestion", "Check that the entity exists in VCD and the name is correct"),
		)
		return err
	}

	// Validate required fields
	if record.Href == nil || *record.Href == "" {
		err := fmt.Errorf("entity %q has no href", entity.Name)
		log.Error("entity has invalid href",
			slog.String("component", "handler.entity"),
			slog.String("entity.type", entity.Type),
			slog.String("entity.name", entity.Name),
			slog.Any("error", err),
		)
		return err
	}

	log.Info("entity located",
		slog.String("component", "handler.entity"),
		slog.String("entity.type", entity.Type),
		slog.String("entity.name", entity.Name),
		slog.String("status", safeString(record.Status)),
		slog.Int64("duration.ms", t.Elapsed_ms()),
	)

	task, err := performAction(action, entity, record, vcdClient, log)

	if err != nil {
		log.Error(fmt.Sprintf("%s %s failed", action, entity.Type),
			slog.String("component", "handler.entity"),
			slog.String("entity.name", entity.Name),
			slog.String("entity.type", entity.Type),
			slog.String("action", action),
			slog.String("status", safeString(record.Status)),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		return fmt.Errorf("action %s failed for %s %q: %w", action, entity.Type, entity.Name, err)
	}

	if task == nil {
		// No task means no action was needed (e.g., already powered off)
		log.Info(fmt.Sprintf("%s %s - no action needed", entity.Type, action),
			slog.String("component", "handler.entity"),
			slog.String("entity.name", entity.Name),
			slog.String("entity.type", entity.Type),
			slog.String("action", action),
			slog.String("status", safeString(record.Status)),
		)
		return nil
	}

	log.Info(fmt.Sprintf("%s %s task started", action, entity.Type),
		slog.String("component", "handler.entity"),
		slog.String("entity.name", entity.Name),
		slog.String("entity.type", entity.Type),
		slog.String("action", action),
		slog.String("task.id", safeString(task.ID)),
	)

	wait := logging.StartTimed()
	err = vcdClient.WaitTaskCompletion(task)
	if err != nil {
		log.Error(fmt.Sprintf("%s %s task failed", action, entity.Type),
			slog.String("component", "handler.entity"),
			slog.String("entity.name", entity.Name),
			slog.String("entity.type", entity.Type),
			slog.String("action", action),
			slog.String("task.id", safeString(task.ID)),
			slog.Any("error", err),
			slog.Int64("duration.ms", wait.Elapsed_ms()),
		)
		return fmt.Errorf("task failed for %s %q: %w", entity.Type, entity.Name, err)
	}

	log.Info(fmt.Sprintf("%s %s successfully", entity.Type, action),
		slog.String("component", "handler.entity"),
		slog.String("entity.name", entity.Name),
		slog.String("entity.type", entity.Type),
		slog.String("action", action),
		slog.String("task.id", safeString(task.ID)),
		slog.Int64("duration.ms", wait.Elapsed_ms()),
	)
	return nil
}

// handleEntity handles power operations for VMs and vApps.
func handleEntity(vcdClient *clouddirector.CloudDirectorV1, entity Entity, action string, log *slog.Logger) {
	if !isValidEntityType(entity.Type) {
		log.Error("Entity type not supported",
			slog.String("component", "handler.entity"),
			slog.String("entity.type", entity.Type),
			slog.String("entity.name", entity.Name),
		)
		return
	}
	t := logging.StartTimed()
	record, _, err := vcdClient.GetObjectByName(&clouddirector.GetObjectByNameOptions{
		Name: entity.Name,
		Type: entity.Type,
	})
	if err != nil {
		log.Error("GetObjectByName failed",
			slog.String("component", "handler.entity"),
			slog.String("action", action),
			slog.String("entity.type", entity.Type),
			slog.String("entity.name", entity.Name),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		return
	}
	if record == nil {
		log.Error("entity not found",
			slog.String("component", "handler.entity"),
			slog.String("entity.type", entity.Type),
			slog.String("entity.name", entity.Name),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		return
	}
	log.Info("entity located",
		slog.String("component", "handler.entity"),
		slog.String("entity.type", entity.Type),
		slog.String("entity.name", entity.Name),
		slog.String("status", *record.Status),
		slog.Int64("duration.ms", t.Elapsed_ms()),
	)

	task, err := performAction(action, entity, record, vcdClient, log)

	if err != nil {
		log.Error(fmt.Sprintf("%s %s failed", action, entity.Type),
			slog.String("component", "handler.entity"),
			slog.String("entity.name", entity.Name),
			slog.String("entity.type", entity.Type),
			slog.String("action", action),
			slog.String("status", *record.Status),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		return
	}
	if task == nil {
		// No task means no action was needed (e.g., already powered off)
		return
	}

	log.Info(fmt.Sprintf("%s %s task started", action, entity.Type),
		slog.String("component", "handler.entity"),
		slog.String("entity.name", entity.Name),
		slog.String("entity.type", entity.Type),
		slog.String("action", action),
		slog.String("task.id", *task.ID),
	)

	wait := logging.StartTimed()
	err = vcdClient.WaitTaskCompletion(task)
	if err != nil {
		log.Error(fmt.Sprintf("%s %s task failed", action, entity.Type),
			slog.String("component", "handler.entity"),
			slog.String("entity.name", entity.Name),
			slog.String("entity.type", entity.Type),
			slog.String("action", action),
			slog.String("task.id", *task.ID),
			slog.Any("error", err),
			slog.Int64("duration.ms", wait.Elapsed_ms()),
		)
		return
	}
	log.Info(fmt.Sprintf("%s %s successfully", entity.Type, action),
		slog.String("component", "handler.entity"),
		slog.String("entity.name", entity.Name),
		slog.String("entity.type", entity.Type),
		slog.String("action", action),
		slog.String("task.id", *task.ID),
		slog.Int64("duration.ms", wait.Elapsed_ms()),
	)
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}

func performAction(action string, entity Entity, record *clouddirector.Record, vcdClient *clouddirector.CloudDirectorV1, log *slog.Logger) (task *clouddirector.Task, err error) {
	switch action {
	case "powerOff":
		allowedStates := []string{statusOn, statusMixed}
		if record.Status != nil && !contains(allowedStates, *record.Status) {
			log.Warn(fmt.Sprintf("%s is not powered on or partially running; no action needed", entity.Type),
				slog.String("component", "handler.entity"),
				slog.String("entity.name", entity.Name),
				slog.String("entity.type", entity.Type),
				slog.String("action", action),
				slog.String("status", *record.Status),
			)
			return nil, nil
		}
		switch entity.Type {
		case vmType:
			// Power off VM
			task, _, err = vcdClient.PowerOffVM(&clouddirector.ObjectRefOptions{
				Href: *record.Href,
			})
		case vappType:
			// Undeploy vApp
			task, _, err = vcdClient.UndeployvApp(&clouddirector.ObjectRefOptions{
				Href: *record.Href,
			})
		}
	case "powerOn":
		allowedStates := []string{statusOff, statusMixed}
		if record.Status != nil && !contains(allowedStates, *record.Status) {
			log.Warn(fmt.Sprintf("%s is not powered off or partially running; no action needed", entity.Type),
				slog.String("component", "handler.entity"),
				slog.String("entity.name", entity.Name),
				slog.String("entity.type", entity.Type),
				slog.String("action", action),
				slog.String("status", *record.Status),
			)
			return nil, nil
		}
		switch entity.Type {
		case vmType:
			// Power on VM
			task, _, err = vcdClient.PowerOnVM(&clouddirector.ObjectRefOptions{
				Href: *record.Href,
			})
		case vappType:
			// Deploy vApp
			task, _, err = vcdClient.DeployvApp(&clouddirector.ObjectRefOptions{
				Href: *record.Href,
			})
		}
	default:
		err = fmt.Errorf("Unsupported action")
		return nil, err
	}
	return task, err

}
