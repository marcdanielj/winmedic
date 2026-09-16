# winmedic

[![ci](https://github.com/marcdanielj/winmedic/actions/workflows/ci.yml/badge.svg)](https://github.com/marcdanielj/winmedic/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/marcdanielj/winmedic.svg)](https://pkg.go.dev/github.com/marcdanielj/winmedic)

Diagnoses the things that actually break Windows environments, and says **what to do about each one** in plain language.

One executable. No installer, no dependencies, no admin rights — because the machine that needs diagnosing is rarely in a state to install anything.

```
winmedic ad       why this PC cannot sign in or reach the shared drive
winmedic boot     why this PC takes so long to start
winmedic certs    what is about to expire and take something down with it
```

Exit code is `0` healthy, `1` needs attention, `2` broken — so it scripts as well as it reads.

## Why it exists

Windows tells you *what* happened and leaves you to work out *what it means*. `dcdiag` needs admin tooling installed, targets servers rather than the laptop in front of you, and answers in paragraphs. Event Viewer records exactly why a PC boots slowly and then never shows anyone.

Every failure here names the consequence and the fix:

```
  clock  FAIL  this PC is 7m14s behind the domain controller
               server time 2026-09-16T14:02:11Z · round trip 12ms
               -> Sign-in fails past 5m0s of difference, usually with an error
                  that never mentions the clock.
               -> Fix: point this PC at the domain for time, then resync.
               ->   w32tm /config /syncfromflags:domhier /update
               ->   w32tm /resync
```

"Your clock is 7 minutes off" is the single most common cause of *"we can't sign you in"*, and Windows will never once mention the clock while it happens.

## `winmedic ad`

Checks the four things that break domain sign-in, in the order they break:

| Check | What it catches |
|---|---|
| **dns** | The PC is asking a resolver that has never heard of your domain — a home router, or 8.8.8.8. AD runs on DNS, so this fails everything downstream. |
| **clock** | More than 5 minutes of skew and Kerberos rejects the ticket. Sign-in fails with a message that never mentions time. |
| **ports** | 88, 389, 445 and friends. Each blocked port is reported as *what the user loses*, not as a number. |
| **certs** | The LDAPS certificate: expired, expiring, or issued by a CA this PC doesn't trust. Three different problems with three different fixes. |

```bash
winmedic ad                              # detect the domain and check it
winmedic ad -domain corp.example.com
winmedic ad -dc dc1.corp.example.com     # skip discovery, test one DC
```

Discovery runs first because it's both the most common failure *and* a prerequisite — without a domain controller to aim at, the rest have no subject.

## `winmedic boot`

Windows records why each boot was slow in `Microsoft-Windows-Diagnostics-Performance`, then shows it to nobody. Event 100 is the timing summary; 101–109 name the specific app, driver, or service that dragged.

```
  boot       FAIL  startup averages 154.2s - very slow
                   2026-09-15 04:30  168.4s  (desktop at 121.3s, settling 47.1s)  31.2s slower than usual
                   2026-09-14 04:12  152.3s  (desktop at 108.2s, settling 44.1s)
                   average 154.2s across 3 boots
                   -> Anything over two minutes usually means too much starting at login.
  last boot  warn  the most recent start was 31.2s slower than this PC's norm
                   -> Something changed recently - a new app, driver, or update.
  slowest    warn  LegacyBackupAgent (service) took 41.8s
                   service    LegacyBackupAgent     41.8s  (28.4s slower than usual)
                   driver     oldprinter.sys        12.6s
                   app        CloudSyncTray.exe      9.2s  (4.1s slower than usual)
```

Thresholds are **absolute, not relative**. Windows' own "degradation" figure compares a boot against that machine's own history — so a PC that has always taken four minutes reports no degradation at all, while the user still waits four minutes.

It reads the live log on Windows, or an export from anywhere:

```bash
winmedic boot                      # this PC
winmedic boot -from boot.xml       # an export someone sent you
```

Try it right now without a Windows machine — a real-shaped sample ships with the repo:

```bash
winmedic boot -from testdata/boot-sample.xml
```

## `winmedic certs`

Certificate expiry is the outage everyone sees coming and nobody catches. Give it hosts, get back what's about to break, **soonest first**:

```bash
winmedic certs dc1.corp.example.com:636 intranet:443
winmedic certs -f servers.txt -days 45
```

```
  expired.badssl.com:443      FAIL  EXPIRED 4174 days ago
                                    -> This is breaking right now. Renew it.
  go.dev:443                  ok    valid 38 more days, trusted
  github.com:443              ok    valid 74 more days, trusted
  self-signed.badssl.com:443  warn  self-signed, 729 days left
                                    -> Fine internally if intended; browsers and clients will warn.
```

(A real run. Unreachable hosts sort **last** — they're a different problem, and shouldn't bury a certificate that's about to take a service down.)

## How this is verified without a domain

There's no Active Directory here, so the tests build the conditions instead of mocking them away:

- **Clock skew** is measured against a fake NTP server whose clock is deliberately wrong by a known amount, asserting the 5-minute Kerberos boundary from both directions. It also rejects non-server replies and kiss-o'-death packets, because a UDP socket hears from anyone and a stray packet must never become "the time".
- **Certificate expiry** is tested against a real TLS handshake with a certificate generated to be already expired — not a stubbed clock.
- **Ports** bind real listeners. The port list is a parameter rather than a global precisely so the *open* path can be tested; the real AD ports are all privileged, and a check that can only be tested in its failure case is half a check.
- **DNS discovery** uses an injected resolver, so the test asserts priority ordering rather than whatever DNS the build machine happens to have.
- **The boot parser** runs against recorded `wevtutil` output, including a deliberately corrupt record to prove one bad event doesn't discard the log.

**CI runs the suite on real Windows**, plus Linux and macOS, and cross-compiles for `windows/amd64`, `windows/arm64`, `linux/amd64` and `darwin/arm64` on every push.

## Honest limitations

- The AD checks have never met a real domain controller. Every piece of logic is tested, but the first run against real infrastructure is the one that proves it.
- `winmedic boot` shells out to `wevtutil`. That's a deliberate trade: it ships on every Windows install since Vista, needs no cgo and no third-party package, and its XML parses and tests anywhere. The cost is depending on another tool's output format.
- Certificate trust is judged against *this* machine's root store, so "not trusted" means not trusted here — which is usually the finding you want, and occasionally not.

## Install

```bash
go install github.com/marcdanielj/winmedic@latest
```

Or grab a single `.exe` — it cross-compiles from anything:

```bash
GOOS=windows GOARCH=amd64 go build -o winmedic.exe .
```

## Licence

MIT
