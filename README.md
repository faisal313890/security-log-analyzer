# Security Log Analyzer

An offline authentication-log investigation tool for a cybersecurity portfolio. Upload UTF-8 OpenSSH text or normalized CSV, review time-window patterns, and export JSON, alerts CSV, or a printable report. **No API key, pip package, network lookup, live host access, or automatic blocking.** Python 3.12+ standard library only.

## Windows setup

1. Extract the ZIP and open **SecurityLogAnalyzer**.
2. Run **start_windows.cmd** and keep CMD open.
3. Open **http://127.0.0.1:8800**.

Equivalent command from CMD inside the project folder:

```bat
py -3.12 server.py
```

The port differs from Web Security Inspector and Phishing URL Analyzer, so the tools can run independently. Press Ctrl+C to stop. To change the UI port:

```bat
set "LOG_ANALYZER_PORT=8801"
py -3.12 server.py
```

Then open http://127.0.0.1:8801. On Linux/macOS run `python3 server.py` using Python 3.12+.

## First practical checks

Click a built-in sample, then **Analyze logs**. Samples reset rule defaults and timestamp assumptions to the documented settings.

| Sample | Parsed events | Failures | Successes | Review alerts | Parse status |
|---|---:|---:|---:|---:|---|
| Normal activity | 4 | 1 | 3 | 0 | parsed |
| Suspicious patterns | 14 | 13 | 1 | 5 | parsed |
| Normalized CSV | 6 | 5 | 1 | 2 | parsed |
| Parsing gaps | 1 | 1 | 0 | 0 | partial |

The parsing-gaps sample has four input records: one parsed event, one invalid record, and two ignored records. A zero-alert result here is not a clean assessment of all input.

Export JSON and alerts CSV, then use Print / Save PDF. Expand parsing diagnostics and the normalized event preview to examine source-line references. All sample accounts, hosts and logs are synthetic; IP addresses use documentation ranges.

## Rules and interpretation

| ID | Grouping | Default criterion |
|---|---|---|
| SLA-001 | Same host, service, source IP | At least 5 failed records within 5 minutes; threshold/window adjustable in the UI or CLI |
| SLA-002 | Same host, service, source IP | Failures involving at least 5 distinct usernames within 10 minutes |
| SLA-003 | Same host, service, username | Failures from at least 3 distinct source IPs within 10 minutes |
| SLA-004 | Same host, service, source IP, username | A success after at least 3 failures at strictly earlier timestamps within the preceding 10 minutes |

Each rule returns its strongest qualifying window per grouping key for the uploaded file, not every episode. Sliding windows include both endpoints. Records across hosts or services are never combined for a rule. Success-after-failures does not infer order among records with identical timestamps.

An alert includes the grouping key, window, threshold, observed metric, UTC evidence interval, source-line references, and suggested investigation. Some evidence lists are capped at 20 source lines, with truncation marked. Different rules can match overlapping records; alert counts are not unique incident counts. At most 200 alert details are returned; full rule-match counts and omitted-detail counts are explicit.

Repeated guessing, password spraying or account compromise are possible explanations, not conclusions. User errors, automation, shared gateways, device changes and duplicated/forwarded records can look similar. Passwords, attacker identity, and authorization of a successful login are not known from these records. The tool neither assigns an overall system-security score nor claims that no alerts means safe.

## Supported OpenSSH text

These conventional `Failed`/`Accepted` authentication-result lines are supported, including `sshd-session` tags and IPv4/IPv6 source addresses:

```text
2026-10-25T10:00:00Z lab01 sshd[100]: Failed password for alice from 192.0.2.10 port 50000 ssh2
Oct 25 10:00:01 lab01 sshd[101]: Failed password for invalid user admin from 192.0.2.10 port 50001 ssh2
2026-10-25T10:01:00+05:00 lab01 sshd-session[102]: Accepted publickey for alice from 2001:db8::1 port 50002 ssh2
```

Auxiliary `Invalid user`, connection, session and PAM messages are not counted as independent authentication results. This avoids counting an auxiliary invalid-user line plus a corresponding failed-result line as two attempts. Unsupported records remain visible in coverage counts and diagnostics. This is not a universal syslog or OpenSSH-version parser; RFC5424 structured prefixes, raw journal JSON, alternative vendor formats, multiline messages, and other authentication systems require normalization.

## Normalized CSV schema

Required unique headers are `timestamp,event,username,source_ip,host`. Optional `service` defaults to `auth`. Use stable, nonempty host/service identifiers so unrelated systems are not grouped together. Unknown extra columns are ignored and not exported. A missing/invalid source IP makes a record invalid rather than grouping it under an invented source.

```csv
timestamp,event,username,source_ip,host,service
2026-10-25T10:00:00Z,failure,alice,192.0.2.10,lab01,ssh
2026-10-25T10:01:00Z,success,alice,192.0.2.10,lab01,ssh
```

Event values may be `failure`, `success`, `4625`, or `4624`. Windows IDs are accepted **only in this normalized schema**. When preparing Windows records, map the event's timestamp, target account, logged source IP and destination computer into these fields. Preserve relevant domain/account context in `username` and use a stable `service` value. Not all Windows logons have a source IP; missing-IP records cannot be analyzed by these source-oriented rules.

Native Windows EVTX, event XML, and raw Event Viewer CSV exports are not supported in this version. Do not merely rename an EVTX file to CSV. The bundled normalized Windows-style example demonstrates schema handling, not native event-file parsing.

## Time, ordering and duplicates

- Explicit ISO timestamp offsets take precedence and are normalized to UTC.
- Yearless traditional syslog records use the selected **Log year**. ISO timestamps with no offset use the selected fixed UTC offset.
- Set these values for the logs being analyzed, not your current location. Defaults are shown as year 2026 and UTC+00:00; assumptions are counted and reported.
- A fixed offset is not a named timezone or DST model. Normalize logs with changing offsets before analysis.
- Multi-year logs and December/January year rollover are not inferred. Split files by year or normalize timestamps before upload.
- Out-of-order input is sorted by UTC time and original source line; a warning records this.
- Identical normalized records are counted, not silently removed. Duplicate counts and a warning are included. Review overlapping rotations/forwarded logs; records do not equal unique connections or human attempts.
- Username, host and service grouping is case-sensitive. IPs use Python's literal-address normalization; no entity resolution, DNS identity or IPv4-mapped-IPv6 identity merging is performed.

## File limits and coverage

Input must be nonempty UTF-8 text, optionally with a BOM, up to 5 MiB and 20,000 records/approximately 20,000 physical lines. Binary/NUL-containing data is rejected. Oversized text lines, CSV fields, malformed rows, invalid timestamps and missing identifiers are rejected or diagnosed according to the parser. The report shows parsed, ignored and invalid record counts; up to 50 diagnostic details are returned, with truncation marked. Raw record text is not included in diagnostics.

The normalized preview contains at most 200 chronological events. Alert references may point beyond that preview; use the original input and its SHA-256 fingerprint to locate them. JSON includes this preview and alert evidence, not a full normalized copy of every input record. Alerts CSV contains returned alert details only; a no-alert export contains a header row. Parsing status and diagnostics remain in JSON/the printable report.

## Command line

From CMD inside the project folder:

```bat
py -3.12 analyzer.py examples\suspicious.log --out reports\analysis.json --csv reports\alerts.csv
```

Example for legacy syslog from UTC+05:00 in 2026:

```bat
py -3.12 analyzer.py inputs\auth.log --format openssh --year 2026 --offset=+05:00 --threshold 5 --window 5 --out reports\auth-analysis.json
```

Use `--offset=-04:00` with the equals sign for negative offsets. Exit 0 means all nonblank input records were parsed, even if alerts exist. Exit 1 indicates partial/no-supported-event coverage; exit 2 indicates a configuration/file/parser error. Exit codes are not incident verdicts.

## Privacy and local handling

Uploads are analyzed in memory on this computer and are not sent to external services. The server suppresses request logs. Raw messages and unknown CSV columns are not exported, but normalized event fields, usernames, IPs, hostnames, service names, filenames and timestamps may be sensitive. A username or hostname itself may contain confidential information. Review exports before sharing.

The input SHA-256 fingerprints the original file bytes; it does not prove authenticity. Explicit browser downloads and CLI output options write files. No upload/report history is deliberately saved by the UI server. Browser/OS memory, caches, CLI files and user downloads are outside this guarantee. Clear session removes current UI data; downloaded reports remain.

Reports escape CSV cells beginning with common spreadsheet formula prefixes, but spreadsheet behaviors differ; this is not an exhaustive spreadsheet-security guarantee. Browser results are rendered as text rather than injected HTML.

## Project layout

```text
analyzer.py                  Parsers, time normalization, window rules, CLI, CSV
server.py                    Local upload/sample/report endpoints
static/                      Interface, styles, print layout and exports
start_windows.cmd            Windows Python 3.12 launcher
examples/                    Synthetic logs, normalized CSV and generated report
tests/test_analyzer.py        Parser, rule and local HTTP integration tests
VALIDATION.md                Verification scope and limitations
```

Run the tests:

```bat
py -3.12 -m unittest discover -s tests -v
```

The service binds to loopback and includes Host/Origin/custom-header checks, bounded inputs, a static-route allowlist, restrictive CSP and safe text rendering. This is a single-user prototype with no login, multi-user isolation, production hardening, live ingestion or SIEM integration. Keep it local. Thresholds are demonstration defaults and have not been tuned against a representative production dataset.

## References

- OpenSSH authentication log generation: https://github.com/openssh/openssh-portable/blob/master/auth.c
- Traditional syslog timestamp format: https://www.rfc-editor.org/rfc/rfc3164.html
- Microsoft logon event definitions: https://learn.microsoft.com/windows/security/threat-protection/auditing/basic-audit-logon-events
