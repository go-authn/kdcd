// SPDX-License-Identifier: BSD-3-Clause

// Command kdcd is a Kerberos KDC daemon for one realm, built on the library
// github.com/go-authn/kdc.
//
//	kdcd check --config /etc/kdcd/kdcd.hcl
//	kdcd       --config /etc/kdcd/kdcd.hcl
//
// The program lives at cmd/kdcd so that `go install` names it kdcd: MIT's KDC
// is krb5kdc and Heimdal's is kdc, and neither is called kdcd.
//
//	go install github.com/go-authn/kdcd/cmd/kdcd@latest
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// osExit is replaceable so that a test can see the status main would exit with.
var osExit = os.Exit

func main() {
	if err := RootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "kdcd:", err)
		osExit(1)
	}
}

// version is the module version Go stamped into the binary, "devel" for a
// build from a working tree.
func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "devel"
}

// RootCmd is the command tree, driven by tests through SetArgs, SetOut and
// SetErr.
func RootCmd() *cobra.Command {
	var configPath string
	root := &cobra.Command{
		Use:           "kdcd",
		Short:         "a Kerberos KDC for one realm",
		Long:          "kdcd serves AS and TGS requests for one realm over UDP and TCP, and optionally mints a TGT for a caller that authenticated a person elsewhere (a passkey login), over mutual TLS.",
		Version:       version(),
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDaemon(cmd, configPath)
		},
	}
	root.SetVersionTemplate("kdcd {{.Version}}\n")
	root.PersistentFlags().StringVar(&configPath, "config", "", "the configuration file (HCL)")
	root.AddCommand(&cobra.Command{
		Use:          "check",
		Short:        "validate the configuration and print what it serves",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := load(configPath)
			if err != nil {
				return err
			}
			defer rt.Close()
			fmt.Fprint(cmd.OutOrStdout(), rt.Summary())
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	})
	return root
}

// load reads and builds a configuration, everything short of listening.
func load(path string) (*Runtime, error) {
	if path == "" {
		return nil, fmt.Errorf("--config is required")
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return Build(cfg)
}

// runDaemon serves until the context ends, SIGINT or SIGTERM arrives, or a
// socket fails.
func runDaemon(cmd *cobra.Command, configPath string) error {
	rt, err := load(configPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
	logf := func(format string, args ...any) { logger.Info(fmt.Sprintf(format, args...)) }
	d, err := Start(rt, logf)
	if err != nil {
		rt.Close()
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "kdcd %s: realm %s, kdc on %s (tcp and udp)\n", version(), rt.Cfg.Realm, d.KDCAddr())
	if a := d.MintAddr(); a != "" {
		fmt.Fprintf(out, "kdcd: mint on https://%s/mint (mutual TLS)\n", a)
	}
	if a := d.KKDCPAddr(); a != "" {
		fmt.Fprintf(out, "kdcd: kkdcp on http://%s%s (MS-KKDCP, behind a TLS proxy)\n", a, rt.Cfg.KKDCP.Path)
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-d.Err():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Shutdown(sctx); err != nil && serveErr == nil {
		serveErr = err
	}
	return serveErr
}
