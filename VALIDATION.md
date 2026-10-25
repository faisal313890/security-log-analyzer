# Validation — Security Log Analyzer 0.1.0

Validated on 2026-10-25 in Linux with Python 3.12.14.

## Passed

- JavaScript syntax and HTML/JavaScript element-reference checks passed; report rendering uses text nodes and no browser-storage calls.
- 35 automated tests: `python -m unittest discover -s tests -v`.
- Real local HTTP upload-to-report integration produced the expected suspicious-sample alerts and CSV output.
- All sample datasets: normal (4 events, 0 alerts), suspicious (14 events, 5 alerts), normalized CSV (6 events, 2 alerts), and parsing gaps (1 parsed / 1 invalid / 2 ignored records).
- OpenSSH ISO/traditional timestamps, invalid-user handling without auxiliary double counting, sshd-session, IPv6, normalized 4624/4625 values, required CSV headers, BOM and invalid binary/oversized inputs.
- Explicit versus assumed offsets/year, out-of-order input, duplicates, threshold/window boundaries, distinct-user/source counts, host/service separation, strictly earlier failures, and no correlation across incompatible keys or outside the window.
- Evidence source-line references, raw trailing-secret exclusion, no-network analysis, CSV structure and common formula-prefix guarding.
- Local request-origin/header protection, invalid upload handling, static allowlisting, and sample endpoints.

## Remaining limits

- Windows execution, actual browser rendering, download/print dialogs, responsive layout and accessibility require local verification. JavaScript syntax and element-reference checks passed; actual browser behavior was not visually tested.
- Detection quality has not been measured on production logs or a labeled incident dataset. No precision/recall or attack-detection accuracy claim is made.
- Parser coverage is limited to documented formats. Native Windows event files, arbitrary applications, live logs and alternative syslog framing are not supported.
- No DST/year-rollover/clock-skew inference, deduplication, cross-file correlation, external enrichment, or automatic response actions.

## Acceptance check

Start `start_windows.cmd`, open http://127.0.0.1:8800, load Normal activity and analyze. Verify 4 parsed events, 1 failure, 3 successes and 0 alerts. Then load Suspicious patterns and verify 14 events and 5 alerts. Test Parsing gaps to confirm the partial status and diagnostic counts. Export JSON/CSV and print/save a PDF. Review timestamps and source-line references before using any alert as investigation evidence.
