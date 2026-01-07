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
	vmType    = "vm"
	vappType  = "vApp"
	statusOn  = "POWERED_ON"
	statusOff = "POWERED_OFF"
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
func nowInLocation(tz string) time.Time {
	if tz == "" {
		return time.Now().UTC()
	}
	loc, err := time.LoadLocation(tz)
	if err == nil {
		return time.Now().In(loc)
	}
	return time.Now().UTC()
}

// parseDateOrPanic parses a date string and panics on error.
func parseDateOrPanic(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(fmt.Errorf("Invalid date %q: %w", s, err))
	}
	return t
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
func inExclusions(cfg *Config, now time.Time) (bool, string) {
	for _, d := range cfg.Exclusions.Dates {
		dt := parseDateOrPanic(d.Date)
		if d.Annual && sameMonthDay(now, dt) {
			return true, fmt.Sprintf("excluded (annual day %s)", d.Date)
		}
		if !d.Annual && sameDate(now, dt) {
			return true, fmt.Sprintf("excluded (day %s)", d.Date)
		}
	}
	for _, r := range cfg.Exclusions.Ranges {
		f := parseDateOrPanic(r.From)
		t := parseDateOrPanic(r.To)
		if r.Annual && inAnnualRange(now, f, t) {
			return true, fmt.Sprintf("excluded (annual range %s..%s)", r.From, r.To)
		}
		if !r.Annual && !now.Before(f) && !now.After(t) {
			return true, fmt.Sprintf("excluded (range %s..%s)", r.From, r.To)
		}
	}
	return false, ""
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

	// Find a VDC that belongs to the selected site and (optionally) matches vdcName
	var selectedVdc *vmw.VDC
	for i := range vdcs.Vdcs {
		v := vdcs.Vdcs[i]

		// Defensive nil checks + single membership check
		if v.DirectorSite == nil || v.DirectorSite.ID == nil {
			continue
		}
		if *v.DirectorSite.ID != *site.ID {
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

func main() {
	log := logging.NewLogger().With("app", "ce-vcd-power-schedule")
	corrID := logging.NewCorrelationID()
	log = log.With(slog.String("correlation_id", corrID))

	if len(os.Args) == 2 && (os.Args[1] == "powerOn" || os.Args[1] == "powerOff") {
		log.Info("received arguments", slog.String("action", os.Args[1]))
	} else {
		log.Error("missing or invalid argument", slog.String("usage", "powerOn | powerOff"))
		return
	}

	action := os.Args[1]

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
		return
	}
	log.Info("configuration loaded", slog.String("component", "config"), slog.Int64("duration.ms", t.Elapsed_ms()))

	now := nowInLocation(cfg.Exclusions.Timezone)
	if excluded, why := inExclusions(cfg, now); excluded {
		log.Info("skip execution due to exclusion",
			slog.String("component", "scheduler"),
			slog.String("reason", why),
			slog.String("timezone", cfg.Exclusions.Timezone),
			slog.Time("now", now),
		)
		return
	}

	apiKey := os.Getenv("IBM_APIKEY")
	region := os.Getenv("IBM_REGION")
	siteName := os.Getenv("DIRECTOR_SITE_NAME")
	vdcName := os.Getenv("VIRTUAL_DATA_CENTER")

	t = logging.StartTimed()
	svc, auth, err := buildVmwareService(apiKey, region)
	if err != nil {
		log.Error("failed to initialize VMware VCFaaS service",
			slog.String("component", "vcf-service"),
			slog.String("region", region),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		return
	}
	log.Info("VCFaaS client initialized", slog.String("component", "vcf-service"), slog.String("region", region), slog.Int64("duration.ms", t.Elapsed_ms()))

	ctx := context.Background()

	t = logging.StartTimed()
	vcd, err := discoverVcdInfo(ctx, svc, siteName, vdcName)
	if err != nil {
		log.Error("VCD discovery failed",
			slog.String("component", "discovery"),
			slog.String("site", siteName),
			slog.String("vdc", vdcName),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		return
	}
	log.Info("Discovered VCD info",
		slog.String("component", "discovery"),
		slog.String("vdc", vdcName),
		slog.String("site", siteName),
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
		return
	}
	log.Info("IAM token acquired", slog.String("component", "iam"), slog.Int64("duration.ms", t.Elapsed_ms()))

	cloudDirectorV1Options := clouddirector.CloudDirectorV1Options{
		URL:      vcd.APIBase,
		Org:      vcd.OrgName,
		IAMToken: accessToken,
		Log:      log,
	}

	t = logging.StartTimed()
	vcdClient, err := clouddirector.NewCloudDirectorV1(&cloudDirectorV1Options)
	if err != nil {
		log.Error("Failed to initialize Cloud Director client",
			slog.String("component", "vcd-client"),
			slog.Any("error", err),
			slog.Int64("duration.ms", t.Elapsed_ms()),
		)
		return
	}
	log.Info("VCD client initialized", slog.String("component", "vcd-client"), slog.Int64("duration.ms", t.Elapsed_ms()))

	for _, entity := range cfg.Entities {
		handleEntity(vcdClient, entity, action, log)
	}
}

func isValidEntityType(entityType string) bool {
	return entityType == vmType || entityType == vappType
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

func performAction(action string, entity Entity, record *clouddirector.Record, vcdClient *clouddirector.CloudDirectorV1, log *slog.Logger) (task *clouddirector.Task, err error) {
	switch action {
	case "powerOff":
		if record.Status != nil && *record.Status != statusOn {
			log.Warn(fmt.Sprintf("%s is not powered on; no action needed", entity.Type),
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
		if record.Status != nil && *record.Status != statusOff {
			log.Warn(fmt.Sprintf("%s is not powered off; no action needed", entity.Type),
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
