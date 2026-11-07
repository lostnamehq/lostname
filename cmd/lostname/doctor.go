package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"lostname.be/lostname/internal/config"
	"lostname.be/lostname/internal/probe"
	"lostname.be/lostname/internal/zone"
)

// runDoctor is the preflight (plan v0.1): is this machine, network path and configuration fit to give verdicts? It
// sends only the interception probes (to documentation addresses where no server can exist) and reads local files;
// it never queries a provider and never posts to an endpoint. Exit 0 when every check passes, 1 when one fails, 2
// when the network path is intercepted, so no verdict over it can be trusted.
func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file (JSON); defaults apply to anything it leaves out")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	failed, intercepted := false, false
	report := func(ok bool, what string) {
		mark := "ok  "
		if !ok {
			mark, failed = "FAIL", true
		}
		fmt.Fprintf(stdout, "%s %s\n", mark, what)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		report(false, "configuration: "+err.Error())
		return exitFindings
	}
	report(true, "configuration loads and validates")

	timeout := config.Seconds(cfg.Probe.Timeout)
	for _, c := range []struct{ family, addr string }{{"IPv4", cfg.Probe.Canary}, {"IPv6", cfg.Probe.CanaryV6}} {
		if got := probe.Answered(c.addr, timeout); len(got) > 0 {
			intercepted = true
			fmt.Fprintf(stdout, "FAIL %s path intercepted: the probe address %s answered over %v; no verdict over it "+
				"can be trusted: run from a path without DNS interception\n", c.family, c.addr, got)
		} else {
			report(true, c.family+" path not intercepted (probe "+c.addr+")")
		}
	}

	for _, z := range cfg.Watch.Zones {
		if _, err := zone.ReadFile(z.ZoneFile, z.Origin); err != nil {
			report(false, "watch zone "+z.Origin+": "+err.Error())
		} else {
			report(true, "watch zone "+z.Origin+" reads")
		}
	}
	for _, c := range cfg.Watch.Catalogs {
		cz, err := zone.ReadFile(c.CatalogFile, c.Origin)
		var members []string
		if err == nil {
			members, err = zone.CatalogMembers(cz)
		}
		if err != nil {
			report(false, "watch catalog "+c.Origin+": "+err.Error())
			continue
		}
		report(true, fmt.Sprintf("watch catalog %s reads: %d member(s)", c.Origin, len(members)))
		for _, m := range members {
			f := filepath.Join(c.ZoneDir, trimDot(m)+".zone")
			if _, err := os.Stat(f); err != nil {
				report(false, "catalog member "+m+": no zone file "+f)
			}
		}
	}
	if f := cfg.Watch.ZoneID.SaltFile; f != "" {
		salt, err := os.ReadFile(f)
		report(err == nil && len(salt) >= 16, "zone label salt file "+f+" is readable and at least 16 bytes")
	}
	if f := cfg.Watch.State; f != "" {
		tmp, err := os.CreateTemp(filepath.Dir(f), ".lostname-doctor-*")
		if err == nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
		report(err == nil, "state file directory "+filepath.Dir(f)+" is writable")
	}
	switch {
	case failed:
		fmt.Fprintln(stdout, "doctor: not ready")
		return exitFindings
	case intercepted:
		fmt.Fprintln(stdout, "doctor: not ready (intercepted path)")
		return exitNoVerdict
	}
	fmt.Fprintln(stdout, "doctor: ready")
	return exitPass
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
