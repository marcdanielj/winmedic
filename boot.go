package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Windows records why a boot was slow in its own diagnostics log and then never
// shows it to anyone. Event 100 is the boot timing summary; 101-109 name the
// specific application, driver, or service that dragged.
//
// Reading it through wevtutil rather than the Windows Event Log API is a
// deliberate trade: wevtutil ships on every Windows install since Vista, needs
// no cgo and no third-party package, and hands back XML that can be parsed and
// tested anywhere. The cost is shelling out to a tool and depending on its
// output format, which is stable and documented.
const bootChannel = "Microsoft-Windows-Diagnostics-Performance/Operational"

// bootEventKind labels the 101-109 range, which all share a shape.
var bootEventKind = map[int]string{
	101: "app",
	102: "driver",
	103: "service",
	106: "background",
	109: "device",
}

type winEvent struct {
	System struct {
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func (e winEvent) field(name string) string {
	for _, d := range e.EventData.Data {
		if d.Name == name {
			return strings.TrimSpace(d.Value)
		}
	}
	return ""
}

func (e winEvent) ms(name string) time.Duration {
	v, err := strconv.ParseInt(e.field(name), 10, 64)
	if err != nil {
		return 0
	}
	return time.Duration(v) * time.Millisecond
}

func (e winEvent) when() time.Time {
	t, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Boot is one recorded startup.
type Boot struct {
	When     time.Time     `json:"when"`
	Total    time.Duration `json:"total"`
	MainPath time.Duration `json:"main_path"` // until the desktop is usable
	PostBoot time.Duration `json:"post_boot"` // still settling after that
	Degraded time.Duration `json:"degraded"`  // slower than this machine's own baseline
}

// Culprit is one thing Windows blamed for a slow start.
type Culprit struct {
	Kind     string        `json:"kind"`
	Name     string        `json:"name"`
	Total    time.Duration `json:"total"`
	Degraded time.Duration `json:"degraded"`
}

// parseBootEvents reads a wevtutil XML stream.
//
// The output is a bare sequence of <Event> elements with no root, which is not
// a well-formed document. Decoding token by token handles that, and has the
// side benefit that a single malformed event is skipped rather than discarding
// the whole log.
func parseBootEvents(r io.Reader) ([]Boot, []Culprit, error) {
	dec := xml.NewDecoder(r)
	var boots []Boot
	var culprits []Culprit

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return boots, culprits, err
		}
		se, isStart := tok.(xml.StartElement)
		if !isStart || se.Name.Local != "Event" {
			continue
		}
		var ev winEvent
		if err := dec.DecodeElement(&ev, &se); err != nil {
			continue // one bad record must not sink the rest
		}

		id := ev.System.EventID
		if id == 100 {
			boots = append(boots, Boot{
				When:     ev.when(),
				Total:    ev.ms("BootTime"),
				MainPath: ev.ms("MainPathBootTime"),
				PostBoot: ev.ms("BootPostBootTime"),
				Degraded: ev.ms("BootDegradationTime"),
			})
			continue
		}
		if kind, ok := bootEventKind[id]; ok {
			name := ev.field("Name")
			if name == "" {
				name = ev.field("FriendlyName")
			}
			if name == "" {
				continue
			}
			culprits = append(culprits, Culprit{
				Kind:     kind,
				Name:     name,
				Total:    ev.ms("TotalTime"),
				Degraded: ev.ms("DegradationTime"),
			})
		}
	}

	// Slowest first: the reader wants the worst offender, not a chronology.
	slices.SortStableFunc(culprits, func(a, b Culprit) int { return int(b.Total - a.Total) })
	return boots, culprits, nil
}

// readBootLog shells out to wevtutil. Split out so tests drive the parser with
// recorded output instead of needing a Windows machine.
func readBootLog(ctx context.Context, count int) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("the boot log is a Windows feature; this is %s", runtime.GOOS)
	}
	query := "*[System[(EventID=100 or (EventID >= 101 and EventID <= 109))]]"
	cmd := exec.CommandContext(ctx, "wevtutil", "qe", bootChannel,
		"/q:"+query, "/f:xml", "/rd:true", "/c:"+strconv.Itoa(count))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wevtutil: %w", err)
	}
	return string(out), nil
}

// bootChecks turns parsed events into a verdict on startup time.
//
// Thresholds are absolute rather than relative to the machine's own history,
// because Windows' own "degradation" figure is measured against that history -
// a PC that has always taken four minutes reports no degradation at all, and
// the user is still waiting four minutes.
func bootChecks(boots []Boot, culprits []Culprit, show int) []Check {
	if len(boots) == 0 {
		return []Check{skip("boot", "no boot records found (the log may be empty on a new install)")}
	}

	var sum time.Duration
	for _, b := range boots {
		sum += b.Total
	}
	avg := sum / time.Duration(len(boots))
	last := boots[0]

	detail := make([]string, 0, len(boots)+1)
	for i, b := range boots {
		if i >= show {
			break
		}
		line := fmt.Sprintf("%s  %6s  (desktop at %s, settling %s)",
			b.When.Local().Format("2006-01-02 15:04"), secs(b.Total), secs(b.MainPath), secs(b.PostBoot))
		if b.Degraded > 0 {
			line += fmt.Sprintf("  %s slower than usual", secs(b.Degraded))
		}
		detail = append(detail, line)
	}
	detail = append(detail, fmt.Sprintf("average %s across %d boots", secs(avg), len(boots)))

	var checks []Check
	switch {
	case avg >= 2*time.Minute:
		checks = append(checks, fail("boot", fmt.Sprintf("startup averages %s - very slow", secs(avg)),
			"Anything over two minutes usually means too much starting at login.\n"+
				"See what is named below, and disable what is not needed.", detail...))
	case avg >= 60*time.Second:
		checks = append(checks, warn("boot", fmt.Sprintf("startup averages %s", secs(avg)),
			"A healthy PC with an SSD starts in well under a minute.", detail...))
	default:
		checks = append(checks, ok("boot", fmt.Sprintf("startup averages %s", secs(avg)), detail...))
	}

	if last.Degraded >= 10*time.Second {
		checks = append(checks, warn("last boot",
			fmt.Sprintf("the most recent start was %s slower than this PC's norm", secs(last.Degraded)),
			"Something changed recently - a new app, driver, or update."))
	}

	if len(culprits) > 0 {
		var lines []string
		for i, c := range culprits {
			if i >= show {
				break
			}
			line := fmt.Sprintf("%-10s %-34s %7s", c.Kind, truncate(c.Name, 34), secs(c.Total))
			if c.Degraded > 0 {
				line += fmt.Sprintf("  (%s slower than usual)", secs(c.Degraded))
			}
			lines = append(lines, line)
		}
		worst := culprits[0]
		summary := fmt.Sprintf("%s (%s) took %s", worst.Name, worst.Kind, secs(worst.Total))
		if worst.Total < 5*time.Second {
			checks = append(checks, ok("slowest", summary, lines...))
		} else {
			checks = append(checks, warn("slowest", summary,
				"Windows named these itself. A service or app here that you do not\n"+
					"recognise is usually safe to stop starting automatically.", lines...))
		}
	}
	return checks
}

func secs(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
