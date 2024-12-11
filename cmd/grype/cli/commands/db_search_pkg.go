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
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

type dbSearchPackageOptions struct {
	Format        options.DBSearchFormat          `yaml:",inline" mapstructure:",squash"`
	Vulnerability options.DBSearchVulnerabilities `yaml:",inline" mapstructure:",squash"`
	Package       options.DBSearchPackages        `yaml:",inline" mapstructure:",squash"`
	OS            options.DBSearchOSs             `yaml:",inline" mapstructure:",squash"`

	DBOptions `yaml:",inline" mapstructure:",squash"`
}

func DBSearchPackages(app clio.Application) *cobra.Command {
	opts := &dbSearchPackageOptions{
		Format: options.DBSearchFormat{
			Output: tableOutputFormat,
			Allowable: []string{
				tableOutputFormat,
				jsonOutputFormat,
			},
		},
		Vulnerability: options.DBSearchVulnerabilities{
			UseVulnIDFlag: true,
		},
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	return app.SetupCommand(&cobra.Command{
		Use:     "pkg PURL|CPE|NAME...",
		Aliases: []string{"package", "packages", "pkgs"},
		Short:   "get information regarding packages affected by vulnerabilities from the db",
		Args: func(_ *cobra.Command, args []string) error {
			opts.Package.Names = args
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) (err error) {
			if len(opts.Vulnerability.VulnerabilityIDs) == 0 {
				// TODO: we can relax this over time, but for now make it required
				return fmt.Errorf("must specify at least one vulnerability ID")
			}
			return runDBSearchPackages(*opts)
		},
	}, opts)
}

func runDBSearchPackages(opts dbSearchPackageOptions) error {
	if opts.Experimental.DBv6 {
		return newDBSearchPackages(opts)
	}
	return legacyDBSearchPackages(opts)
}

func newDBSearchPackages(opts dbSearchPackageOptions) error {
	client, err := distribution.NewClient(opts.DB.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	curator, err := installation.NewCurator(opts.DB.ToCuratorConfig(), client)
	if err != nil {
		return fmt.Errorf("unable to create curator: %w", err)
	}

	reader, err := curator.Reader()
	if err != nil {
		return fmt.Errorf("unable to get providers: %w", err)
	}

	rows, err := dbsearch.AffectedPackages(reader, dbsearch.AffectedPackagesOptions{
		Vulnerability: opts.Vulnerability.Specs,
		Package:       opts.Package.PkgSpecs,
		CPE:           opts.Package.CPESpecs,
		OS:            opts.OS.Specs,
	})
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		return errors.New("no affected packages found")
	}

	sb := &strings.Builder{}
	err = presentDBSearchPackages(opts.Format.Output, rows, sb)
	bus.Report(sb.String())
	return err
}

func presentDBSearchPackages(outputFormat string, structuredRows []dbsearch.AffectedPackageTableRow, output io.Writer) error {
	if len(structuredRows) == 0 {
		// TODO: show a message that no results were found?
		return nil
	}

	switch outputFormat {
	case tableOutputFormat:
		rows := renderDBSearchPackagesTableRows(structuredRows)

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

func renderDBSearchPackagesTableRows(structuredRows []dbsearch.AffectedPackageTableRow) [][]string {
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// all legacy processing below ////////////////////////////////////////////////////////////////////////////////////////

func legacyDBSearchPackages(opts dbSearchPackageOptions) error {
	vulnerabilityIDs := opts.Vulnerability.VulnerabilityIDs

	log.Debug("loading DB")
	str, status, err := grype.LoadVulnerabilityDB(opts.DB.ToLegacyCuratorConfig(), opts.DB.AutoUpdate)
	err = validateDBLoad(err, status)
	if err != nil {
		return err
	}
	defer log.CloseAndLogError(str, status.Location)

	var vulnerabilities []vulnerability.Vulnerability
	for _, vulnerabilityID := range vulnerabilityIDs {
		vulns, err := str.Get(vulnerabilityID, "")
		if err != nil {
			return fmt.Errorf("unable to get vulnerability %q: %w", vulnerabilityID, err)
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	if len(vulnerabilities) == 0 {
		return errors.New("no affected packages found")
	}

	sb := &strings.Builder{}
	err = presentLegacyDBSearchPackages(opts.Format.Output, vulnerabilities, sb)
	bus.Report(sb.String())

	return err
}

func presentLegacyDBSearchPackages(outputFormat string, vulnerabilities []vulnerability.Vulnerability, output io.Writer) error {
	if vulnerabilities == nil {
		return nil
	}

	switch outputFormat {
	case tableOutputFormat:
		rows := [][]string{}
		for _, v := range vulnerabilities {
			rows = append(rows, []string{v.ID, v.PackageName, v.Namespace, v.Constraint.String()})
		}

		table := tablewriter.NewWriter(output)
		commonTableWriterOptions(table)

		table.SetHeader([]string{"ID", "Package Name", "Namespace", "Version Constraint"})
		table.AppendBulk(rows)
		table.Render()
	case jsonOutputFormat:
		enc := json.NewEncoder(output)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(vulnerabilities); err != nil {
			return fmt.Errorf("failed to encode diff information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
	return nil
}
