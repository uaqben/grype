package options

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/cpe"
)

type DBSearchPackages struct {
	Names     []string             `yaml:"names" json:"names" mapstructure:"names"`
	Ecosystem string               `yaml:"ecosystem" json:"ecosystem" mapstructure:"ecosystem"`
	PkgSpecs  v6.PackageSpecifiers `yaml:"-" json:"-" mapstructure:"-"`
	CPESpecs  v6.PackageSpecifiers `yaml:"-" json:"-" mapstructure:"-"`
}

func (o *DBSearchPackages) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Ecosystem, "ecosystem", "", "ecosystem of the package to search within (for v6+ schemas only)")
}

func (o *DBSearchPackages) PostLoad() error {
	if len(o.Names) == 0 {
		return nil
	}
	for _, p := range o.Names {
		switch {
		case strings.HasPrefix(p, "cpe:"):
			c, err := cpe.NewAttributes(p)
			if err != nil {
				return fmt.Errorf("invalid CPE from %q: %w", o.Names, err)
			}
			s := &v6.PackageSpecifier{CPE: &c}
			o.CPESpecs = append(o.CPESpecs, s)
			o.PkgSpecs = append(o.PkgSpecs, s)
		case strings.HasPrefix(p, "pkg:"):
			if o.Ecosystem != "" {
				return errors.New("cannot specify both package URL and ecosystem")
			}

			purl, err := packageurl.FromString(p)
			if err != nil {
				return fmt.Errorf("invalid package URL from %q: %w", o.Names, err)
			}

			o.PkgSpecs = append(o.PkgSpecs, &v6.PackageSpecifier{Name: purl.Name, Type: purl.Type}) // TODO: map this to correct DB types

		default:
			o.PkgSpecs = append(o.PkgSpecs, &v6.PackageSpecifier{Name: p, Type: o.Ecosystem})
			o.CPESpecs = append(o.CPESpecs, &v6.PackageSpecifier{
				CPE: &cpe.Attributes{Part: "a", Product: p},
			})
		}
	}
	return nil
}
