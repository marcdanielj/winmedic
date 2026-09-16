package main

import (
	"fmt"
	"io"
	"strings"
)

// Status is how a single check came out. The ordering matters: reports sort
// worst-first, because the failure is what someone opened the tool to find.
type Status int

const (
	StatusOK Status = iota
	StatusWarn
	StatusFail
	StatusSkip
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusWarn:
		return "warn"
	case StatusFail:
		return "FAIL"
	default:
		return "skip"
	}
}

// Check is one question asked and answered.
//
// Advice is the field that earns this tool's existence. Windows' own
// diagnostics are generally accurate and useless in the same breath: they
// report a condition and leave the reader to work out the consequence. Every
// non-OK result here has to say what it breaks and what to do, or the check
// should not have been written.
type Check struct {
	Name    string   `json:"name"`
	Status  Status   `json:"-"`
	State   string   `json:"status"`
	Summary string   `json:"summary"`
	Advice  string   `json:"advice,omitempty"`
	Detail  []string `json:"detail,omitempty"`
}

func ok(name, summary string, detail ...string) Check {
	return Check{Name: name, Status: StatusOK, State: "ok", Summary: summary, Detail: detail}
}

func warn(name, summary, advice string, detail ...string) Check {
	return Check{Name: name, Status: StatusWarn, State: "warn", Summary: summary, Advice: advice, Detail: detail}
}

func fail(name, summary, advice string, detail ...string) Check {
	return Check{Name: name, Status: StatusFail, State: "fail", Summary: summary, Advice: advice, Detail: detail}
}

func skip(name, why string) Check {
	return Check{Name: name, Status: StatusSkip, State: "skip", Summary: why}
}

// Report is the outcome of one run.
type Report struct {
	Target string  `json:"target,omitempty"`
	Checks []Check `json:"checks"`
}

// Verdict is the single worst status in the report, which is what an exit code
// and a glance should both key off.
func (r Report) Verdict() Status {
	worst := StatusOK
	for _, c := range r.Checks {
		if c.Status == StatusSkip {
			continue
		}
		if c.Status > worst {
			worst = c.Status
		}
	}
	return worst
}

// ExitCode lets this be used from a script: 0 healthy, 1 warnings, 2 broken.
func (r Report) ExitCode() int {
	switch r.Verdict() {
	case StatusFail:
		return 2
	case StatusWarn:
		return 1
	}
	return 0
}

// Write renders the report. Failures print their advice indented underneath, so
// the fix sits next to the problem instead of in a legend at the bottom.
func (r Report) Write(w io.Writer) {
	width := 0
	for _, c := range r.Checks {
		if len(c.Name) > width {
			width = len(c.Name)
		}
	}

	fmt.Fprintln(w)
	for _, c := range r.Checks {
		fmt.Fprintf(w, "  %-*s  %-4s  %s\n", width, c.Name, c.Status, c.Summary)
		for _, d := range c.Detail {
			fmt.Fprintf(w, "  %-*s        %s\n", width, "", d)
		}
		if c.Advice != "" {
			for _, line := range strings.Split(c.Advice, "\n") {
				fmt.Fprintf(w, "  %-*s        -> %s\n", width, "", line)
			}
		}
	}

	fmt.Fprintln(w)
	switch r.Verdict() {
	case StatusOK:
		fmt.Fprintln(w, "  all clear")
	case StatusWarn:
		fmt.Fprintln(w, "  working, but something needs attention")
	case StatusFail:
		fmt.Fprintln(w, "  broken - see the arrows above for what to fix")
	}
	fmt.Fprintln(w)
}
