package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

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
