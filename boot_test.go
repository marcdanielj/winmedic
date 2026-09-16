package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func loadSample(t *testing.T) ([]Boot, []Culprit) {
	t.Helper()
	b, err := os.ReadFile("testdata/boot-sample.xml")
	if err != nil {
		t.Fatal(err)
	}
	boots, culprits, err := parseBootEvents(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return boots, culprits
}

// wevtutil emits a bare sequence of <Event> elements with no root, which is not
// a well-formed document. Parsing must cope with that, not choke on it.
func TestParsesRootlessEventStream(t *testing.T) {
	boots, culprits := loadSample(t)
	if len(boots) != 3 {
		t.Fatalf("got %d boot records, want 3", len(boots))
	}
	if len(culprits) != 3 {
		t.Fatalf("got %d culprits, want 3", len(culprits))
	}
}

func TestBootTimingsAreReadCorrectly(t *testing.T) {
	boots, _ := loadSample(t)
	first := boots[0]
	if first.Total != 168420*time.Millisecond {
		t.Errorf("total = %v, want 168.42s", first.Total)
	}
	if first.MainPath != 121310*time.Millisecond {
		t.Errorf("main path = %v, want 121.31s", first.MainPath)
	}
	if first.Degraded != 31200*time.Millisecond {
		t.Errorf("degradation = %v, want 31.2s", first.Degraded)
	}
	if first.When.IsZero() {
		t.Error("timestamp did not parse")
	}
}

// The reader wants the worst offender, so culprits come back slowest-first
// regardless of the order Windows logged them in.
func TestCulpritsAreSortedSlowestFirst(t *testing.T) {
	_, culprits := loadSample(t)
	if culprits[0].Name != "LegacyBackupAgent" {
		t.Errorf("worst culprit = %q, want LegacyBackupAgent", culprits[0].Name)
	}
	if culprits[0].Kind != "service" {
		t.Errorf("kind = %q, want service (event 103)", culprits[0].Kind)
	}
	for i := 1; i < len(culprits); i++ {
		if culprits[i-1].Total < culprits[i].Total {
			t.Fatalf("not sorted: %v before %v", culprits[i-1], culprits[i])
		}
	}
}

// One corrupt record must not throw away the rest of the log.
func TestMalformedEventIsSkippedNotFatal(t *testing.T) {
	const mixed = `<Event><System><EventID>100</EventID><TimeCreated SystemTime='2026-09-15T08:30:12.0000000Z'/></System><EventData><Data Name='BootTime'>50000</Data></EventData></Event>
<Event><System><EventID>100</EventID><TimeCreated SystemTime='not a timestamp'/></System><EventData><Data Name='BootTime'>abc</Data></EventData></Event>
<Event><System><EventID>100</EventID><TimeCreated SystemTime='2026-09-14T08:30:12.0000000Z'/></System><EventData><Data Name='BootTime'>60000</Data></EventData></Event>`

	boots, _, err := parseBootEvents(strings.NewReader(mixed))
	if err != nil {
		t.Fatalf("a bad record aborted the parse: %v", err)
	}
	if len(boots) != 3 {
		t.Fatalf("got %d boots, want all 3 (the bad one degraded, not dropped)", len(boots))
	}
	if boots[1].Total != 0 {
		t.Errorf("unparseable duration = %v, want 0", boots[1].Total)
	}
}

// Thresholds are absolute on purpose: Windows' own degradation figure is
// relative to the machine's history, so a PC that has always been slow reports
// no degradation while the user still waits two minutes.
func TestBootGradingUsesAbsoluteThresholds(t *testing.T) {
	mk := func(total time.Duration) []Boot {
		return []Boot{{When: time.Now(), Total: total, MainPath: total / 2}}
	}
	for _, c := range []struct {
		total time.Duration
		want  Status
	}{
		{25 * time.Second, StatusOK},
		{75 * time.Second, StatusWarn},
		{150 * time.Second, StatusFail},
	} {
		got := bootChecks(mk(c.total), nil, 5)[0]
		if got.Status != c.want {
			t.Errorf("a %v boot graded %v, want %v", c.total, got.Status, c.want)
		}
	}
}

func TestSampleLogGradesAsBroken(t *testing.T) {
	boots, culprits := loadSample(t)
	checks := bootChecks(boots, culprits, 5)
	rep := Report{Checks: checks}
	if rep.Verdict() != StatusFail {
		t.Errorf("a 154s average boot graded %v, want fail", rep.Verdict())
	}
	joined := checks[0].Summary + strings.Join(checks[0].Detail, " ")
	if !strings.Contains(joined, "average") {
		t.Error("the boot check should report an average across boots")
	}
}

func TestEmptyLogIsSkippedNotFailed(t *testing.T) {
	c := bootChecks(nil, nil, 5)[0]
	if c.Status != StatusSkip {
		t.Errorf("an empty log graded %v, want skip", c.Status)
	}
}

// On a non-Windows machine this must explain itself rather than crash.
func TestReadBootLogOffWindowsExplainsItself(t *testing.T) {
	if _, err := readBootLog(nil, 5); err == nil {
		t.Skip("running on Windows; the live log is available")
	} else if !strings.Contains(err.Error(), "Windows") {
		t.Errorf("error should name the platform limitation, got %q", err)
	}
}
