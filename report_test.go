package main

import (
	"bytes"
	"strings"
	"testing"
)

// The exit code is how this gets used from a script, so the worst check has to
// drive it - an "ok" alongside a "fail" must not read as success.
func TestExitCodeTakesTheWorstStatus(t *testing.T) {
	for _, c := range []struct {
		name   string
		checks []Check
		want   int
	}{
		{"all ok", []Check{ok("a", "fine"), ok("b", "fine")}, 0},
		{"one warn", []Check{ok("a", "fine"), warn("b", "hmm", "do this")}, 1},
		{"one fail among ok", []Check{ok("a", "fine"), fail("b", "broken", "fix this"), ok("c", "fine")}, 2},
		{"fail outranks warn", []Check{warn("a", "hmm", "x"), fail("b", "broken", "y")}, 2},
		{"skips are ignored", []Check{ok("a", "fine"), skip("b", "not applicable")}, 0},
		{"nothing checked", nil, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := (Report{Checks: c.checks}).ExitCode(); got != c.want {
				t.Errorf("exit code = %d, want %d", got, c.want)
			}
		})
	}
}

// Advice is the reason this tool exists. If it does not reach the output, a
// failing check is just Windows' own unhelpful diagnostics with nicer spacing.
func TestAdviceIsPrintedUnderTheFailure(t *testing.T) {
	var buf bytes.Buffer
	Report{Checks: []Check{
		fail("clock", "7m14s ahead of the domain controller", "Run: w32tm /resync"),
	}}.Write(&buf)

	out := buf.String()
	for _, want := range []string{"clock", "FAIL", "7m14s", "w32tm /resync", "broken"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestMultiLineAdviceKeepsItsShape(t *testing.T) {
	var buf bytes.Buffer
	Report{Checks: []Check{fail("dns", "no DC found", "line one\nline two")}}.Write(&buf)
	out := buf.String()
	if strings.Count(out, "-> ") != 2 {
		t.Errorf("each advice line should be marked, got:\n%s", out)
	}
}

func TestHealthyReportSaysSo(t *testing.T) {
	var buf bytes.Buffer
	Report{Checks: []Check{ok("clock", "in sync"), ok("dns", "found 2 DCs")}}.Write(&buf)
	if !strings.Contains(buf.String(), "all clear") {
		t.Errorf("a healthy report should say so:\n%s", buf.String())
	}
}
