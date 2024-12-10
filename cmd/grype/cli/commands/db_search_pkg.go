package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/cpe"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"io"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/commands/internal/dbsearch"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

type DBSearchPackageSelectorOptions struct {
	Package   []string               `yaml:"package" json:"package" mapstructure:"package"`
	Ecosystem string                 `yaml:"ecosystem" json:"ecosystem" mapstructure:"ecosystem"`
	NameSpecs []*v6.PackageSpecifier `yaml:"-" json:"-" mapstructure:"-"`
	CPESpecs  []*v6.PackageSpecifier `yaml:"-" json:"-" mapstructure:"-"`
}

type DBSearchDistroSelectorOptions struct {
	Distro string              `yaml:"distro" json:"distro" mapstructure:"distro"`
	Spec   *v6.DistroSpecifier `yaml:"-" json:"-" mapstructure:"-"`
}

func (o *DBSearchDistroSelectorOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Distro, "distro", "", "distro to search for")
}

func (o *DBSearchDistroSelectorOptions) PostLoad() error {
	if o.Distro == "" {
		o.Spec = v6.AnyDistroSpecified
		return nil
	}

	// parse name@version from the distro string
	// version could be a codename, major version, major.minor version, or major.minior.patch version
	parts := strings.Split(o.Distro, "@")
	switch len(parts) {
	case 1:
		if strings.Contains(parts[0], ":") {
			return errors.New("invalid distro name@version provided")
		}

		o.Spec = &v6.DistroSpecifier{Name: strings.TrimSpace(parts[0])}
	case 2:
		version := strings.TrimSpace(parts[1])
		name := strings.TrimSpace(parts[0])
		if len(version) == 0 {
			return errors.New("invalid distro version provided")
		}

		// parse the version (major.minor.patch, major.minor, major, codename)

		// if starts with a number, then it is a version
		startVersion := version[0]
		if startVersion >= '0' && startVersion <= '9' {
			versionParts := strings.Split(parts[1], ".")
			var major, minor string
			switch len(versionParts) {
			case 1:
				major = versionParts[0]
			case 2:
				major = versionParts[0]
				minor = versionParts[1]
			case 3:
				return fmt.Errorf("invalid distro version provided: patch version ignored: %q", version)
			default:
				return fmt.Errorf("invalid distro version provided: %q", version)
			}

			o.Spec = &v6.DistroSpecifier{Name: name, MajorVersion: major, MinorVersion: minor}

			return nil
		}

		// is codename / label
		// TODO: pick one! not both
		o.Spec = &v6.DistroSpecifier{Name: name, Codename: version, LabelVersion: version}

	default:
		return fmt.Errorf("invalid distro name@version: %q", o.Distro)
	}
	if o.Spec != nil {
		o.Spec.AllowMultiple = true
	}

	return nil
}

func (o *DBSearchPackageSelectorOptions) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&o.Package, "package", "", "name, purl, or CPE of a package to search for")
	flags.StringVarP(&o.Ecosystem, "ecosystem", "", "ecosystem of the package to search within")
}

func (o *DBSearchPackageSelectorOptions) PostLoad() error {
	if len(o.Package) == 0 {
		return nil
	}
	for _, p := range o.Package {
		switch {
		case strings.HasPrefix(p, "cpe:"):
			c, err := cpe.NewAttributes(p)
			if err != nil {
				return fmt.Errorf("invalid CPE from %q: %w", o.Package, err)
			}
			o.CPESpecs = append(o.CPESpecs, &v6.PackageSpecifier{CPE: &c})
		case strings.HasPrefix(p, "pkg:"):
			if o.Ecosystem != "" {
				return errors.New("cannot specify both package URL and ecosystem")
			}

			purl, err := packageurl.FromString(p)
			if err != nil {
				return fmt.Errorf("invalid package URL from %q: %w", o.Package, err)
			}

			o.NameSpecs = append(o.NameSpecs, &v6.PackageSpecifier{Name: purl.Name, Type: purl.Type}) // TODO: map this to correct DB types

		default:
			o.NameSpecs = append(o.NameSpecs, &v6.PackageSpecifier{Name: p, Type: o.Ecosystem})

		}
	}
	return nil
}

type dbSearchPackageOptions struct {
	DBSearchOutputOptions                `yaml:",inline" mapstructure:",squash"`
	DBSearchTimeboxOptions               `yaml:",inline" mapstructure:",squash"`
	DBSearchVulnerabilitySelectorOptions `yaml:",inline" mapstructure:",squash"`
	DBSearchPackageSelectorOptions       `yaml:",inline" mapstructure:",squash"`
	DBSearchDistroSelectorOptions        `yaml:",inline" mapstructure:",squash"`

	DBOptions `yaml:",inline" mapstructure:",squash"`
}

func DBSearchPackages(app clio.Application) *cobra.Command {
	opts := &dbSearchPackageOptions{
		DBSearchOutputOptions: DBSearchOutputOptions{
			Output: tableOutputFormat,
			Allowable: []string{
				tableOutputFormat,
				jsonOutputFormat,
			},
		},
		DBSearchVulnerabilitySelectorOptions: DBSearchVulnerabilitySelectorOptions{
			IncludeFlag: true,
		},
		DBOptions: *dbOptionsDefault(app.ID()),
	}

	return app.SetupCommand(&cobra.Command{
		Use:     "pkg",
		Aliases: []string{"package", "packages", "pkgs"},
		Short:   "get information regarding packages affected by vulnerabilities from the db",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) (err error) {
			if len(opts.VulnerabilityIDs) == 0 {
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
	vulnerabilityIDs := opts.VulnerabilityIDs
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
	// TODO: refactor this in terms of search function pattern described in #2132 (in other words, the store should not be directly accessed here)

	var allAffectedPkgs []v6.AffectedPackageHandle
	var allAffectedCPEs []v6.AffectedCPEHandle

	pkgSpecs := opts.NameSpecs
	if len(pkgSpecs) == 0 {
		pkgSpecs = []*v6.PackageSpecifier{nil}
	}

	cpeCpes := opts.CPESpecs
	if len(cpeCpes) == 0 {
		cpeCpes = []*v6.PackageSpecifier{nil}
	}

	for _, vulnerabilityID := range vulnerabilityIDs {

		for i := range pkgSpecs {
			pkgSpec := pkgSpecs[i]

			log.WithFields("vuln", vulnerabilityID, "pkg", pkgSpec).Debug("searching for affected packages")

			affectedPkgs, err := reader.GetAffectedPackages(pkgSpec, &v6.GetAffectedPackageOptions{
				PreloadOS:            true,
				PreloadPackage:       true,
				PreloadPackageCPEs:   false,
				PreloadVulnerability: true,
				PreloadBlob:          true,
				Distro:               opts.DBSearchDistroSelectorOptions.Spec,
				Vulnerability: &v6.VulnerabilitySpecifier{
					Name:           vulnerabilityID,
					PublishedAfter: opts.publishedAfter,
					ModifiedAfter:  opts.modifiedAfter,
				},
			})
			if err != nil {
				return fmt.Errorf("unable to get affected packages for %q: %w", vulnerabilityID, err)
			}

			allAffectedPkgs = append(allAffectedPkgs, affectedPkgs...)
		}

		for i := range cpeCpes {
			c := cpeCpes[i]
			var searchCPE *cpe.Attributes
			if c != nil {
				searchCPE = c.CPE
			}

			log.WithFields("vuln", vulnerabilityID, "cpe", searchCPE).Debug("searching for affected packages")

			if opts.DBSearchDistroSelectorOptions.Spec == v6.AnyDistroSpecified {
				affectedCPEs, err := reader.GetAffectedCPEs(searchCPE, &v6.GetAffectedCPEOptions{
					PreloadCPE:           true,
					PreloadVulnerability: true,
					PreloadBlob:          true,
					Vulnerability: &v6.VulnerabilitySpecifier{
						Name:           vulnerabilityID,
						PublishedAfter: opts.publishedAfter,
						ModifiedAfter:  opts.modifiedAfter,
					},
				})
				if err != nil {
					return fmt.Errorf("unable to get affected cpes for %q: %w", vulnerabilityID, err)
				}

				allAffectedCPEs = append(allAffectedCPEs, affectedCPEs...)
			}

			if c != nil {
				affectedPkgs, err := reader.GetAffectedPackages(c, &v6.GetAffectedPackageOptions{
					PreloadOS:            true,
					PreloadPackage:       true,
					PreloadPackageCPEs:   false,
					PreloadVulnerability: true,
					PreloadBlob:          true,
					Distro:               opts.DBSearchDistroSelectorOptions.Spec,
					Vulnerability: &v6.VulnerabilitySpecifier{
						Name:           vulnerabilityID,
						PublishedAfter: opts.publishedAfter,
						ModifiedAfter:  opts.modifiedAfter,
					},
				})
				if err != nil {
					return fmt.Errorf("unable to get affected packages by CPE for %q: %w", vulnerabilityID, err)
				}
				allAffectedPkgs = append(allAffectedPkgs, affectedPkgs...)

			}

		}
		//}
	}

	rows := dbsearch.NewAffectedPackageRows(allAffectedPkgs, allAffectedCPEs)

	if len(rows) == 0 {
		return errors.New("no affected packages found")
	}

	sb := &strings.Builder{}
	err = presentDBSearchPackages(opts.Output, rows, sb)
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
	vulnerabilityIDs := opts.VulnerabilityIDs
	if opts.modifiedAfter != nil || opts.publishedAfter != nil {
		return fmt.Errorf("date filtering is only available for v6+ schemas")
	}

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
	err = presentLegacyDBSearchPackages(opts.Output, vulnerabilities, sb)
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
