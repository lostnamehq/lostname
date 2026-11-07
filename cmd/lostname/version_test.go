package main

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
)

// The version comes from Go's build information: a release build names its tag and commit, a local build says
// "(devel)", and a build from a dirty tree says so.
func TestVersionOf(t *testing.T) {
	release := &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Path: "lostname.be/lostname", Version: "v0.1.0"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "6c4bdd93"}, {Key: "vcs.modified", Value: "false"}}}
	for _, c := range []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
		want VersionInfo
	}{
		{"release", release, true, VersionInfo{"lostname.version/v0", "v0.1.0", "6c4bdd93", false, "go1.27.3"}},
		{"no build info", nil, false, VersionInfo{"lostname.version/v0", "(devel)", "", false, ""}},
		{"local, dirty", &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "(devel)"},
			Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc"}, {Key: "vcs.modified", Value: "true"}}},
			true, VersionInfo{"lostname.version/v0", "(devel)", "abc", true, "go1.27.3"}},
	} {
		if got := versionOf(c.bi, c.ok); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestVersionAndHelpCommands(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-version"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitPass || !strings.HasPrefix(out.String(), "lostname ") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out.String(), errb.String())
		}
	}
	for _, args := range [][]string{{"help"}, {"--help"}, {"-help"}, {"-h"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitPass || out.String() != usage+"\n" || errb.Len() != 0 {
			t.Errorf("%v: exit %d, stderr %q", args, code, errb.String())
		}
	}
	var out, errb bytes.Buffer
	if code := run([]string{"version", "extra"}, &out, &errb); code != exitUsage {
		t.Errorf("version with an argument: exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(usage, "lostname version") || !strings.Contains(usage, "lostname help") {
		t.Error("the usage text must list version and help")
	}
}

func TestVersionJSONFollowsItsSchema(t *testing.T) {
	mustValidate(t, "version.schema.json", runCLI(t, "version", "--json"))
}
