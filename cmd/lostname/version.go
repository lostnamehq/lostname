package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
)

// VersionInfo is the JSON output of `lostname version --json` (docs/schemas/version.schema.json). It is read from the
// build information Go stamps into every binary, so the release build needs no extra flag and stays reproducible.
type VersionInfo struct {
	Schema   string `json:"schema"`
	Version  string `json:"version"`  // the tag for a release or `go install ...@vX.Y.Z`, "(devel)" for a local build
	Commit   string `json:"commit"`   // the git commit, empty when the build had no VCS information
	Modified bool   `json:"modified"` // true when the tree had uncommitted changes: not a release build
	Go       string `json:"go"`       // the Go toolchain that built it
}

func versionOf(bi *debug.BuildInfo, ok bool) VersionInfo {
	v := VersionInfo{Schema: "lostname.version/v0", Version: "(devel)"}
	if !ok || bi == nil {
		return v
	}
	if bi.Main.Version != "" {
		v.Version = bi.Main.Version
	}
	v.Go = bi.GoVersion
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			v.Commit = s.Value
		case "vcs.modified":
			v.Modified = s.Value == "true"
		}
	}
	return v
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the version as JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	v := versionOf(debug.ReadBuildInfo())
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			fmt.Fprintln(stderr, "lostname version:", err)
			return exitUsage
		}
		return exitPass
	}
	line := "lostname " + v.Version
	if v.Commit != "" {
		line += " (commit " + v.Commit
		if v.Modified {
			line += ", modified"
		}
		line += ")"
	}
	if v.Go != "" {
		line += " " + v.Go
	}
	fmt.Fprintln(stdout, line)
	return exitPass
}
