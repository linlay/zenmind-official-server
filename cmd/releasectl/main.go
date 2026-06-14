package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/linlay/zenmind-official-server/internal/release"
)

const (
	defaultDBPath      = "/docker/zenmind-official-server/data/data.sqlite"
	defaultReleaseRoot = "/docker/zenmind-releases"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "releasectl: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: releasectl upsert [flags]")
	}

	switch os.Args[1] {
	case "upsert":
		return runUpsert(os.Args[2:])
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func runUpsert(args []string) error {
	flags := flag.NewFlagSet("upsert", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	var opts release.UpsertFileOptions
	flags.StringVar(&opts.DBPath, "db", env("SQLITE_DB_PATH", env("INSTALLER_DB_PATH", defaultDBPath)), "SQLite database path")
	flags.StringVar(&opts.ReleaseRoot, "release-root", env("RELEASE_ROOT", defaultReleaseRoot), "release file root")
	flags.StringVar(&opts.Key, "key", "", "installer key: mac or windows")
	flags.StringVar(&opts.Version, "version", "", "installer version")
	flags.StringVar(&opts.Source, "source", "", "source installer file")
	flags.StringVar(&opts.FileName, "filename", "", "canonical release filename")
	flags.BoolVar(&opts.Replace, "replace", false, "replace target file when existing content differs")
	if err := flags.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	installer, err := release.UpsertFile(ctx, opts)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(installer)
}

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
