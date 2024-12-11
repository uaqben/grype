package dbsearch

import (
	"fmt"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
)

type VulnerabilityRow struct {
	v6.VulnerabilityBlob `json:",inline"`
	Provider             string     `json:"provider"`
	Status               string     `json:"status"`
	PublishedDate        *time.Time `json:"published_date"`
	ModifiedDate         *time.Time `json:"modified_date"`
	WithdrawnDate        *time.Time `json:"withdrawn_date"`
}

func newVulnerabilityRows(vulns ...v6.VulnerabilityHandle) (rows []VulnerabilityRow) {
	for _, vuln := range vulns {
		rows = append(rows, newVulnerabilityRow(vuln))
	}
	return rows
}

func newVulnerabilityRow(vuln v6.VulnerabilityHandle) VulnerabilityRow {
	var blob v6.VulnerabilityBlob
	if vuln.BlobValue != nil {
		blob = *vuln.BlobValue
	}
	return VulnerabilityRow{
		VulnerabilityBlob: blob,
		Provider:          vuln.Provider.ID,
		Status:            vuln.Status,
		PublishedDate:     vuln.PublishedDate,
		ModifiedDate:      vuln.ModifiedDate,
		WithdrawnDate:     vuln.WithdrawnDate,
	}
}

func Vulnerabilities(reader v6.Reader, vulnSpecs v6.VulnerabilitySpecifiers) ([]VulnerabilityRow, error) {
	// TODO: maybe refactor this in terms of search function pattern described in #2132 (in other words, the store should not be directly accessed here)

	var vulns []v6.VulnerabilityHandle
	for i := range vulnSpecs {
		vulnSpec := vulnSpecs[i]
		vs, err := reader.GetVulnerabilities(&vulnSpec, &v6.GetVulnerabilityOptions{
			Preload: true,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to get vulnerabilities: %w", err)
		}

		vulns = append(vulns, vs...)
	}

	return newVulnerabilityRows(vulns...), nil
}
