package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"io"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/internal/bus"
)

type dbSearchVulnerabilityOptions struct {
	DBSearchOutputOptions                `yaml:",inline" mapstructure:",squash"`
	DBSearchTimeboxOptions               `yaml:",inline" mapstructure:",squash"`
	DBSearchVulnerabilitySelectorOptions `yaml:",inline" mapstructure:",squash"`

	DBOptions `yaml:",inline" mapstructure:",squash"`
}

func DBSearchVulnerabilities(app clio.Application) *cobra.Command {
	opts := &dbSearchVulnerabilityOptions{
		DBSearchOutputOptions: DBSearchOutputOptions{
			Output: tableOutputFormat,
			Allowable: []string{
				tableOutputFormat,
				jsonOutputFormat,
			},
		},
		DBSearchVulnerabilitySelectorOptions: DBSearchVulnerabilitySelectorOptions{
			IncludeFlag: false, // we input this through the args
		},
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	return app.SetupCommand(&cobra.Command{
		Use:     "vuln ID",
		Aliases: []string{"vulnerability", "vulnerabilities", "vulns"},
		Short:   "get information regarding vulnerabilities from the db",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("must specify at least one vulnerability ID")
			}
			opts.VulnerabilityIDs = args
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) (err error) {
			return runDBSearchVulnerabilities(*opts)
		},
	}, opts)
}

func runDBSearchVulnerabilities(opts dbSearchVulnerabilityOptions) error {
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
	// TODO: refactor this in terms of search function pattern described in #2132 (in other words, the store should not be directly accessed here)

	affectedPkgs, err := reader.GetAffectedPackages(nil, &v6.GetAffectedPackageOptions{
		PreloadOS:            true,
		PreloadPackage:       true,
		PreloadPackageCPEs:   false,
		PreloadVulnerability: true,
		PreloadBlob:          true,
		Distro:               nil,
		Vulnerability: &v6.VulnerabilitySpecifier{
			//Name:           vulnerabilityID,
			PublishedAfter: opts.publishedAfter,
			ModifiedAfter:  opts.modifiedAfter,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to get affected packages: %w", err)
	}

	affectedCPEs, err := reader.GetAffectedCPEs(nil, &v6.GetAffectedCPEOptions{
		PreloadCPE:           true,
		PreloadVulnerability: true,
		PreloadBlob:          true,
		Vulnerability: &v6.VulnerabilitySpecifier{
			//Name:           vulnerabilityID,
			PublishedAfter: opts.publishedAfter,
			ModifiedAfter:  opts.modifiedAfter,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to get affected cpes: %w", err)
	}

	rows := dbsearch.NewAffectedPackageRows(affectedPkgs, affectedCPEs)

	if len(rows) == 0 {
		return errors.New("no vulnerabilities found")
	}

	sb := &strings.Builder{}
	err = presentDBSearchVulnerabilities(opts.Output, rows, sb)
	bus.Report(sb.String())
	return err
}

func presentDBSearchVulnerabilities(outputFormat string, structuredRows []dbsearch.AffectedPackageTableRow, output io.Writer) error {
	if len(structuredRows) == 0 {
		// TODO: show a message that no results were found?
		return nil
	}

	switch outputFormat {
	case tableOutputFormat:
		rows := renderDBSearchVulnerabilitiesTableRows(structuredRows)

		table := tablewriter.NewWriter(output)
		commonTableWriterOptions(table)

		table.SetHeader([]string{"ID", "Package", "Ecosystem", "Namespace", "Version Constraint"})
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

func renderDBSearchVulnerabilitiesTableRows(structuredRows []dbsearch.AffectedPackageTableRow) [][]string {
	var rows [][]string
	for _, rr := range structuredRows {
		var pkgOrCPE, ecosystem string
		if rr.Package != nil {
			pkgOrCPE = rr.Package.Name
			ecosystem = rr.Package.Ecosystem
		} else if rr.CPE != nil {
			pkgOrCPE = rr.CPE.String()
			ecosystem = rr.CPE.TargetSoftware
		}

		namespace := rr.Vulnerability.Provider
		if rr.OS != nil {
			namespace = fmt.Sprintf("%s:%s", rr.OS.Family, rr.OS.Version)
		}

		var ranges []string
		for _, ra := range rr.Detail.Ranges {
			ranges = append(ranges, ra.Version.Constraint)
		}
		rangeStr := strings.Join(ranges, " || ")
		rows = append(rows, []string{rr.Vulnerability.ID, pkgOrCPE, ecosystem, namespace, rangeStr})
	}
	return rows
}
