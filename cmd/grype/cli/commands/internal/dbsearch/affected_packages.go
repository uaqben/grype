package dbsearch

import (
	"encoding/json"
	"fmt"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

type AffectedPackageTableRow struct {
	Vulnerability VulnerabilityRow       `json:"vulnerability"`
	OS            *OS                    `json:"os,omitempty"`
	Package       *Package               `json:"package,omitempty"`
	CPE           *v6.Cpe                `json:"cpe,omitempty"`
	Detail        v6.AffectedPackageBlob `json:"detail"`
}

func (r AffectedPackageTableRow) MarshalJSON() ([]byte, error) {
	var c string
	if r.CPE != nil {
		c = r.CPE.String()
	}
	return json.Marshal(&struct {
		Vulnerability VulnerabilityRow       `json:"vulnerability"`
		OS            *OS                    `json:"os,omitempty"`
		Package       *Package               `json:"package,omitempty"`
		CPE           string                 `json:"cpe,omitempty"`
		Detail        v6.AffectedPackageBlob `json:"detail"`
	}{
		Vulnerability: r.Vulnerability,
		OS:            r.OS,
		Package:       r.Package,
		CPE:           c,
		Detail:        r.Detail,
	})
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OS struct {
	Family  string `json:"family"`
	Version string `json:"version"`
}

func newAffectedPackageRows(affectedPkgs []v6.AffectedPackageHandle, affectedCPEs []v6.AffectedCPEHandle) (rows []AffectedPackageTableRow) {
	for _, pkg := range affectedPkgs {
		var detail v6.AffectedPackageBlob
		if pkg.BlobValue != nil {
			detail = *pkg.BlobValue
		}
		if pkg.Vulnerability == nil {
			// TODO: handle better
			log.Errorf("affected package record missing vulnerability: %+v", pkg)
			continue
		}
		rows = append(rows, AffectedPackageTableRow{
			Vulnerability: newVulnerabilityRow(*pkg.Vulnerability),
			OS:            toOS(pkg.OperatingSystem),
			Package:       toPackage(pkg.Package),
			Detail:        detail,
		})
	}

	for _, ac := range affectedCPEs {
		var detail v6.AffectedPackageBlob
		if ac.BlobValue != nil {
			detail = *ac.BlobValue
		}
		if ac.Vulnerability == nil {
			// TODO: handle better
			log.Errorf("affected CPE record missing vulnerability: %+v", ac)
			continue
		}

		rows = append(rows, AffectedPackageTableRow{
			Vulnerability: newVulnerabilityRow(*ac.Vulnerability),
			CPE:           ac.CPE,
			Detail:        detail,
		})
	}
	return rows
}

func toPackage(pkg *v6.Package) *Package {
	if pkg == nil {
		return nil
	}
	return &Package{
		Name:      pkg.Name,
		Ecosystem: pkg.Type,
	}
}

func toOS(os *v6.OperatingSystem) *OS {
	if os == nil {
		return nil
	}
	version := os.VersionNumber()
	if version == "" {
		version = os.Version()
	}

	return &OS{
		Family:  os.Name,
		Version: version,
	}
}

type AffectedPackagesOptions struct {
	Vulnerability v6.VulnerabilitySpecifiers
	Package       v6.PackageSpecifiers
	CPE           v6.PackageSpecifiers
	OS            v6.OSSpecifiers
}

func AffectedPackages(reader v6.Reader, criteria AffectedPackagesOptions) ([]AffectedPackageTableRow, error) {
	var allAffectedPkgs []v6.AffectedPackageHandle
	var allAffectedCPEs []v6.AffectedCPEHandle

	pkgSpecs := criteria.Package
	cpeSpecs := criteria.CPE
	osSpecs := criteria.OS
	vulnSpecs := criteria.Vulnerability

	if len(pkgSpecs) == 0 {
		pkgSpecs = []*v6.PackageSpecifier{nil}
	}

	if len(cpeSpecs) == 0 {
		cpeSpecs = []*v6.PackageSpecifier{nil}
	}

	for i := range pkgSpecs {
		pkgSpec := pkgSpecs[i]

		log.WithFields("vuln", vulnSpecs, "pkg", pkgSpec, "os", osSpecs).Debug("searching for affected packages")

		affectedPkgs, err := reader.GetAffectedPackages(pkgSpec, &v6.GetAffectedPackageOptions{
			PreloadOS:            true,
			PreloadPackage:       true,
			PreloadPackageCPEs:   false,
			PreloadVulnerability: true,
			PreloadBlob:          true,
			OSs:                  osSpecs,
			Vulnerabilities:      vulnSpecs,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to get affected packages for %s: %w", vulnSpecs, err)
		}

		allAffectedPkgs = append(allAffectedPkgs, affectedPkgs...)
	}

	if osSpecs.IsAny() {
		for i := range cpeSpecs {
			cpeSpec := cpeSpecs[i]
			var searchCPE *cpe.Attributes
			if cpeSpec != nil {
				searchCPE = cpeSpec.CPE
			}

			log.WithFields("vuln", vulnSpecs, "cpe", cpeSpec).Debug("searching for affected packages")

			affectedCPEs, err := reader.GetAffectedCPEs(searchCPE, &v6.GetAffectedCPEOptions{
				PreloadCPE:           true,
				PreloadVulnerability: true,
				PreloadBlob:          true,
				Vulnerabilities:      vulnSpecs,
			})
			if err != nil {
				return nil, fmt.Errorf("unable to get affected cpes for %s: %w", vulnSpecs, err)
			}

			allAffectedCPEs = append(allAffectedCPEs, affectedCPEs...)
		}
	}

	return newAffectedPackageRows(allAffectedPkgs, allAffectedCPEs), nil
}
