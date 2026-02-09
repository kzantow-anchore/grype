package commands

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/internal/log"
)

type dbDiffOptions struct {
	Output                  string `yaml:"output" json:"output" mapstructure:"output"`
	options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	From                    options.Database
	To                      options.Database
}

var _ clio.FlagAdder = (*dbDiffOptions)(nil)

func (d *dbDiffOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[text, json])")
}

func DBDiff(app clio.Application) *cobra.Command {
	opts := &dbDiffOptions{
		Output:          textOutputFormat,
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
	}

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff the current database against another",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// DB commands should not opt into the low-pass check filter
			opts.DB.MaxUpdateCheckFrequency = 0
			return disableUI(app)(cmd, args)
		},
		Args: cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBDiff(*opts)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden                   *dbDiffOptions `json:"-" yaml:"-" mapstructure:"-"`
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DatabaseCommand: &opts.DatabaseCommand})
}

func runDBDiff(opts dbDiffOptions) error {
	start := time.Now()

	clientCfg := opts.ToClientConfig()
	curatorCfg := opts.ToCuratorConfig()

	fromDir := opts.From.Dir
	if fromDir == "" {
		fromDir = curatorCfg.DBRootDir
	}

	client, err := distribution.NewClient(distribution.Config{
		ID:                 clientCfg.ID,
		LatestURL:          clientCfg.LatestURL,
		CACert:             clientCfg.CACert,
		RequireUpdateCheck: clientCfg.RequireUpdateCheck,
		CheckTimeout:       clientCfg.CheckTimeout,
		UpdateTimeout:      clientCfg.UpdateTimeout,
	})
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	c, err := installation.NewCurator(curatorCfg, client)

	reader, err := c.Reader()
	if err != nil {
		return err
	}

	p := db.NewVulnerabilityProvider(reader)
	defer log.CloseAndLogError(p, "database")

	var vulns2 []vulnerability.Vulnerability
	var err2 error
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		// FIXME remove this:
		if vulns2 == nil {
			return
		}

		client, err := distribution.NewClient(distribution.Config{
			ID:                 clio.Identification{},
			LatestURL:          "",
			CACert:             "",
			RequireUpdateCheck: false,
			CheckTimeout:       0,
			UpdateTimeout:      0,
		})
		if err != nil {
			err2 = fmt.Errorf("unable to create distribution client: %w", err)
			return
		}

		tmpdir, err := os.MkdirTemp("", "grype-db-diff-")
		if err != nil {
			err2 = err
			return
		}

		c, err := installation.NewCurator(installation.Config{
			DBRootDir:               tmpdir,
			Debug:                   false,
			ValidateAge:             false,
			ValidateChecksum:        false,
			MaxAllowedBuiltAge:      0,
			UpdateCheckMaxFrequency: 0,
		}, client)

		reader, err := c.Reader()
		if err != nil {
			err2 = err
			return
		}

		p := db.NewVulnerabilityProvider(reader)
		defer log.CloseAndLogError(p, "database")

		vulns2, err = p.FindVulnerabilities() // search.ByPackageName("*"))
		if err != nil {
			err2 = err
			return
		}
	}()

	vulns, err := p.FindVulnerabilities() // search.ByPackageName("*"))
	if err != nil {
		return err
	}

	wg.Wait()

	if err2 != nil {
		return err
	}

	log.Warnf("found %v vulns in %v", len(vulns), time.Since(start))

	return nil
}

type dbDiffJSON struct {
	CurrentDB       *db.Description       `json:"currentDB"`
	CandidateDB     *distribution.Archive `json:"candidateDB"`
	UpdateAvailable bool                  `json:"updateAvailable"`
}
