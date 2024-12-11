package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal/bus"
)

type dbSearchVulnerabilityOptions struct {
	Format        options.DBSearchFormat          `yaml:",inline" mapstructure:",squash"`
	Vulnerability options.DBSearchVulnerabilities `yaml:",inline" mapstructure:",squash"`

	DBOptions `yaml:",inline" mapstructure:",squash"`
}

func DBSearchVulnerabilities(app clio.Application) *cobra.Command {
	opts := &dbSearchVulnerabilityOptions{
		Format: options.DBSearchFormat{
			Output: tableOutputFormat,
			Allowable: []string{
				tableOutputFormat,
				jsonOutputFormat,
			},
		},
		Vulnerability: options.DBSearchVulnerabilities{
			UseVulnIDFlag: false, // we input this through the args
		},
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	return app.SetupCommand(&cobra.Command{
		Use:     "vuln ID...",
		Aliases: []string{"vulnerability", "vulnerabilities", "vulns"},
		Short:   "get information regarding vulnerabilities from the db",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("must specify at least one vulnerability ID")
			}
			opts.Vulnerability.VulnerabilityIDs = args
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) (err error) {
			return runDBSearchVulnerabilities(*opts)
		},
	}, opts)
}

func runDBSearchVulnerabilities(opts dbSearchVulnerabilityOptions) error {
	if opts.Experimental.DBv6 {
		return runNewDBSearchVulnerabilities(opts)
	}
	return errors.New("this command only supports the v6+ database schemas")
}

func runNewDBSearchVulnerabilities(opts dbSearchVulnerabilityOptions) error {
	client, err := distribution.NewClient(opts.DB.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	c, err := installation.NewCurator(opts.DB.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	reader, err := c.Reader()
	if err != nil {
		return fmt.Errorf("unable to get providers: %w", err)
	}

	rows, err := dbsearch.Vulnerabilities(reader, opts.Vulnerability.Specs)
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		return errors.New("no vulnerabilities found")
	}

	sb := &strings.Builder{}
	err = presentDBSearchVulnerabilities(opts.Format.Output, rows, sb)
	bus.Report(sb.String())
	return err
}

func presentDBSearchVulnerabilities(outputFormat string, structuredRows []dbsearch.VulnerabilityRow, output io.Writer) error {
	if len(structuredRows) == 0 {
		// TODO: show a message that no results were found?
		return nil
	}

	switch outputFormat {
	case tableOutputFormat:
		rows := renderDBSearchVulnerabilitiesTableRows(structuredRows)

		table := tablewriter.NewWriter(output)
		commonTableWriterOptions(table)

		table.SetHeader([]string{"ID", "Provider", "Severity"})
		table.AppendBulk(rows)
		table.Render()
	case jsonOutputFormat:
		enc := json.NewEncoder(output)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(structuredRows); err != nil {
			return fmt.Errorf("failed to encode diff information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
	return nil
}

func renderDBSearchVulnerabilitiesTableRows(structuredRows []dbsearch.VulnerabilityRow) [][]string {
	var rows [][]string
	for _, rr := range structuredRows {
		// get the first severity value (which is ranked highest)
		var sev string
		if len(rr.Severities) > 0 {
			s := rr.Severities[0]
			var source string
			if s.Source != "" {
				source = fmt.Sprintf(" from %s", s.Source)
			}
			sev = fmt.Sprintf("%s%s", s.Value, source)
		}

		rows = append(rows, []string{rr.ID, rr.Provider, sev})
	}
	return rows
}
