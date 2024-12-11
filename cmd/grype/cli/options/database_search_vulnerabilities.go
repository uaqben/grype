package options

import (
	"fmt"
	"time"

	"github.com/araddon/dateparse"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
)

type DBSearchVulnerabilities struct {
	VulnerabilityIDs []string `yaml:"vulnerability-ids" json:"vulnerability-ids" mapstructure:"vulnerability-ids"`
	IncludeAliases   bool     `yaml:"include-aliases" json:"include-aliases" mapstructure:"include-aliases"`
	UseVulnIDFlag    bool     `yaml:"-" json:"-" mapstructure:"-"`

	PublishedAfter string `yaml:"published-after" json:"published-after" mapstructure:"published-after"`
	ModifiedAfter  string `yaml:"modified-after" json:"modified-after" mapstructure:"modified-after"`

	Specs v6.VulnerabilitySpecifiers `yaml:"-" json:"-" mapstructure:"-"`
}

func (c *DBSearchVulnerabilities) AddFlags(flags clio.FlagSet) {
	if c.UseVulnIDFlag {
		flags.StringArrayVarP(&c.VulnerabilityIDs, "vuln", "", "only show results for the given vulnerability ID (for v6+ schemas only)")
	}
	flags.BoolVarP(&c.IncludeAliases, "include-aliases", "", "search for vulnerability aliases (for v6+ schemas only)")
	flags.StringVarP(&c.PublishedAfter, "published-after", "", "only show vulnerabilities originally published after the given date (format: YYYY-MM-DD) (for v6+ schemas only)")
	flags.StringVarP(&c.ModifiedAfter, "modified-after", "", "only show vulnerabilities originally published or modified since the given date (format: YYYY-MM-DD) (for v6+ schemas only)")
}

func (c *DBSearchVulnerabilities) PostLoad() error {
	handleTimeOption := func(val string, flag string) (*time.Time, error) {
		if val == "" {
			return nil, nil
		}
		parsed, err := dateparse.ParseIn(val, time.UTC)
		if err != nil {
			return nil, fmt.Errorf("invalid date format for %s=%q: %w", flag, val, err)
		}
		return &parsed, nil
	}

	if c.PublishedAfter != "" && c.ModifiedAfter != "" {
		return fmt.Errorf("only one of --published-after or --modified-after can be set")
	}

	var publishedAfter, modifiedAfter *time.Time
	var err error
	publishedAfter, err = handleTimeOption(c.PublishedAfter, "published-after")
	if err != nil {
		return fmt.Errorf("invalid date format for published-after field: %w", err)
	}
	modifiedAfter, err = handleTimeOption(c.ModifiedAfter, "modified-after")
	if err != nil {
		return fmt.Errorf("invalid date format for modified-after field: %w", err)
	}

	var specs []v6.VulnerabilitySpecifier
	for _, vulnID := range c.VulnerabilityIDs {
		specs = append(specs, v6.VulnerabilitySpecifier{
			Name:           vulnID,
			PublishedAfter: publishedAfter,
			ModifiedAfter:  modifiedAfter,
			IncludeAliases: c.IncludeAliases,
		})
	}

	c.Specs = specs

	return nil
}
