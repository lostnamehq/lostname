// Package sarif writes findings as SARIF 2.1.0 (OASIS), the format the code-scanning views of GitHub and GitLab read
// (model AU-1). Output is deterministic: no timestamps, results in the order given, rules sorted by id.
//
// Zone records carry no line numbers yet, so every result points at the zone file with region line 1, and names the
// owner and type as a logical location.
package sarif

import (
	"encoding/json"
	"io"
	"runtime/debug"
	"sort"
)

const (
	Schema  = "https://json.schemastore.org/sarif-2.1.0.json"
	Version = "2.1.0"
	infoURI = "https://lostname.be/"
	helpURI = "https://github.com/lostnamehq/lostname/blob/main/docs/model.md"
)

// Result is one finding.
type Result struct {
	RuleID  string
	Level   string // error, warning or note
	Message string
	URI     string // the artifact, for example the zone file
	Logical string // owner name and type, for example "www.example.test. CNAME"
}

// Notice is a message about the run itself, such as a question that got no authoritative answer.
type Notice struct {
	Level   string
	Message string
}

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool        tool         `json:"tool"`
	Invocations []invocation `json:"invocations"`
	Results     []result     `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID               string  `json:"id"`
	ShortDescription message `json:"shortDescription"`
	HelpURI          string  `json:"helpUri"`
}

type invocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	Notifications       []notification `json:"toolExecutionNotifications"`
}

type notification struct {
	Level   string  `json:"level"`
	Message message `json:"message"`
}

type message struct {
	Text string `json:"text"`
}

type result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   message    `json:"message"`
	Locations []location `json:"locations"`
}

type location struct {
	Physical physical  `json:"physicalLocation"`
	Logical  []logical `json:"logicalLocations,omitempty"`
}

type physical struct {
	Artifact artifact `json:"artifactLocation"`
	Region   region   `json:"region"`
}

type artifact struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}

type logical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
}

// ToolVersion is the module version this binary was built from: the tag for `go install ...@vX.Y.Z`, "(devel)" for
// a local build.
func ToolVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}

// Write writes one run. complete is false when the tool could not reach a verdict (a parity run with gaps); the
// notices say why.
func Write(w io.Writer, results []Result, notices []Notice, complete bool, describe func(ruleID string) string) error {
	seen := map[string]bool{}
	var rules []rule
	out := make([]result, 0, len(results))
	for _, r := range results {
		if !seen[r.RuleID] {
			seen[r.RuleID] = true
			rules = append(rules, rule{ID: r.RuleID, ShortDescription: message{describe(r.RuleID)}, HelpURI: helpURI})
		}
		loc := location{Physical: physical{Artifact: artifact{URI: r.URI}, Region: region{StartLine: 1}}}
		if r.Logical != "" {
			loc.Logical = []logical{{FullyQualifiedName: r.Logical}}
		}
		out = append(out, result{RuleID: r.RuleID, Level: r.Level, Message: message{r.Message},
			Locations: []location{loc}})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	if rules == nil {
		rules = []rule{}
	}
	notes := make([]notification, 0, len(notices))
	for _, n := range notices {
		notes = append(notes, notification{Level: n.Level, Message: message{n.Message}})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log{Schema: Schema, Version: Version, Runs: []run{{
		Tool:        tool{Driver: driver{Name: "lostname", Version: ToolVersion(), InformationURI: infoURI, Rules: rules}},
		Invocations: []invocation{{ExecutionSuccessful: complete, Notifications: notes}},
		Results:     out,
	}}})
}
