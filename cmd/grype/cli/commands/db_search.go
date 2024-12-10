package commands

import (
	"fmt"
	"github.com/anchore/clio"
	"github.com/araddon/dateparse"
	"github.com/olekukonko/tablewriter"
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"
	"strings"
	"time"
)

type DBSearchOutputOptions struct {
	Output    string   `yaml:"output" json:"output" mapstructure:"output"`
	Allowable []string `yaml:"-" json:"-" mapstructure:"-"`
}

type DBSearchVulnerabilitySelectorOptions struct {
	VulnerabilityIDs []string `yaml:"vulnerability-ids" json:"vulnerability-ids" mapstructure:"vulnerability-ids"`
	IncludeFlag      bool     `yaml:"-" json:"-" mapstructure:"-"`
}

type DBSearchTimeboxOptions struct {
	PublishedAfter string `yaml:"published-after" json:"published-after" mapstructure:"published-after"`
	publishedAfter *time.Time

	ModifiedAfter string `yaml:"modified-after" json:"modified-after" mapstructure:"modified-after"`
	modifiedAfter *time.Time
}

func (c *DBSearchOutputOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&c.Output, "output", "o", "format to display results (available=[table, json])")
}

func (c *DBSearchTimeboxOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&c.PublishedAfter, "published-after", "", "only show vulnerabilities originally published after the given date (format: YYYY-MM-DD) (for v6+ schemas only)")
	flags.StringVarP(&c.ModifiedAfter, "modified-after", "", "only show vulnerabilities originally published or modified since the given date (format: YYYY-MM-DD) (for v6+ schemas only)")
}

func (c *DBSearchVulnerabilitySelectorOptions) AddFlags(flags clio.FlagSet) {
	if c.IncludeFlag {
		flags.StringArrayVarP(&c.VulnerabilityIDs, "vuln", "", "only show results for the given vulnerability ID (for v6+ schemas only)")
	}
}

func DBSearch(app clio.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search",
		Short: "search the DB for vulnerabilities or affected packages",
	}

	cmd.AddCommand(
		DBSearchPackages(app),
		DBSearchVulnerabilities(app),
	)

	return cmd
}

func (c *DBSearchTimeboxOptions) PostLoad() error {
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

	var err error
	if c.publishedAfter, err = handleTimeOption(c.PublishedAfter, "published-after"); err != nil {
		return err
	}
	if c.modifiedAfter, err = handleTimeOption(c.ModifiedAfter, "modified-after"); err != nil {
		return err
	}

	return nil
}

func (c *DBSearchOutputOptions) PostLoad() error {
	if len(c.Allowable) > 0 {
		if !strset.New(c.Allowable...).Has(c.Output) {
			return fmt.Errorf("invalid output format: %s (expected one of: %s)", c.Output, strings.Join(c.Allowable, ", "))
		}
	}
	return nil
}

func commonTableWriterOptions(table *tablewriter.Table) {
	table.SetAutoWrapText(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetAutoFormatHeaders(true)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)
}
