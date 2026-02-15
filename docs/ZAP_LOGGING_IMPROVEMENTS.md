# ZAP Logging Improvements - Summary

## TL;DR

**Enhanced logging is now ON by default** - you get detailed progress updates, phase timing, and scan summaries automatically with no flags required!

- **No configuration needed**: Just run the scan normally
- **stderr**: Human-readable progress logs (INFO level by default)
- **stdout**: Clean JSON output (unchanged - for Guardian integration)
- **Optional**: Use `--verbose` for DEBUG-level API logging
- **Optional**: Use `--log-file PATH` to save logs to a file

## Overview

Both `zap_daemon_scan.py` and `zap_docker_daemon_scan.py` have been enhanced with comprehensive structured logging to provide visibility into scan progress, performance, and troubleshooting.

---

## What Was Added

### 1. **Structured Logging System**

#### New Command-Line Flags
```bash
--verbose, -v              # Enable DEBUG-level logging (API calls, responses, etc.)
--log-file PATH            # Write detailed logs to file (in addition to stderr)
```

#### For Docker Mode Only:
```bash
--zap-log-dir PATH         # Mount host directory for ZAP's internal logs
--docker-log PATH          # Capture Docker container logs
```

#### Logging Behavior (**Enhanced logging is ALWAYS ON by default**)
- **stderr**: Human-readable timestamped logs (**enabled by default**)
  - **INFO level** (default): Progress updates, phase timing, scan summary
  - **DEBUG level** (with `--verbose`): API calls, responses, detailed internals
- **stdout**: Clean JSON output (unchanged - for Guardian integration)
- **log-file**: Detailed logs with function names and line numbers (optional)
- **Docker logs**: Container stdout/stderr (Docker mode only)
- **ZAP internal logs**: ZAP's own log file (Docker mode only)

**You don't need any flags to get enhanced logging - it's on by default!**

---

### 2. **Phase Timing Tracker**

Automatic tracking and reporting of scan phases:

```python
class PhaseTimer:
    - Tracks start/end times for each phase
    - Logs "PHASE START" and "PHASE COMPLETE" messages
    - Formats durations human-readable (e.g., "2m 15s", "45.2s")
    - Includes timing summary in JSON output
```

**Tracked Phases:**
1. ZAP Connection & Verification
2. Seed URL Access
3. Context & Authentication Setup (if configured)
4. Spider Scan (if enabled)
5. AJAX Spider Scan (if enabled)
6. Active Scan (if enabled)
7. Passive Scan Queue Drain
8. Alert Collection
9. HAR Export (if enabled)

---

### 3. **Progress Logging**

#### Spider/Active Scan Progress
```
Spider progress: 10%
Spider progress: 25%
Spider progress: 50%
Spider progress: 100%
✓ Spider scan completed - discovered 127 URLs
```

#### Passive Scan Queue Monitoring
```
Passive scan queue: 342 records remaining
Passive scan queue: 198 records remaining
Passive scan queue: 0 records remaining
✓ Passive scan queue drained
```

#### Alert Fetching
```
Fetching alerts (max: 5000)...
✓ Collected 23 alerts
Alert breakdown:
  High: 2
  Medium: 5
  Low: 14
  Informational: 2
```

---

### 4. **Timeout Context Preservation**

When a scan times out, the error message now includes the **last known status**:

**Before:**
```
ERROR: Timed out waiting for ZAP scan to finish
```

**After:**
```
ERROR: Timed out waiting for ZAP scan to finish (last known status: spider 67%)
```

Or:
```
ERROR: Timed out waiting for ZAP scan to finish (last known status: pscan_queue 142 records)
```

This helps diagnose **where** the scan got stuck.

---

### 5. **Enhanced JSON Output**

The JSON output now includes additional metadata for reproducibility:

```json
{
  "zap": {
    "api_url": "http://127.0.0.1:8080",
    "version": "2.14.0",
    "scan_policy": "Default Policy"
  },
  "scan_options": {
    "spider": true,
    "ajax_spider": false,
    "active": false,
    "ignore_robots": true,
    "max_minutes": 10,
    "context": "Guardian",
    "authenticated": true
  },
  "timing": {
    "phases": {
      "ZAP Connection & Verification": {
        "elapsed_seconds": 1.23,
        "elapsed_formatted": "1.2s"
      },
      "Spider Scan": {
        "elapsed_seconds": 145.67,
        "elapsed_formatted": "2m 25s"
      },
      "Passive Scan Queue Drain": {
        "elapsed_seconds": 32.45,
        "elapsed_formatted": "32.5s"
      }
    },
    "total_seconds": 179.35,
    "total_formatted": "2m 59s"
  },
  "timestamp": "2026-01-24T15:30:42.123456",
  "alerts": [...]
}
```

**New Fields:**
- `zap.scan_policy` - Active scan policy name
- `scan_options` - All scan configuration options
- `timing` - Phase-by-phase timing breakdown
- `timestamp` - ISO 8601 timestamp

---

### 6. **Docker-Specific Improvements**

#### Docker Availability Check
```
Checking Docker availability...
✓ Docker is available
```

#### Container Lifecycle Logging
```
=== PHASE 1: Starting ZAP Docker Container ===
Docker command: docker run -d --rm --name guardian-zapd...
✓ Docker container started
  Container ID: a3b8c9d12345
  Container Name: guardian-zapd
  Port Mapping: 8080:8080
```

#### ZAP API Readiness
```
=== PHASE 2: Waiting for ZAP API ===
Waiting for ZAP API at http://127.0.0.1:8080 (timeout: 180s)...
✓ ZAP API ready after 15 attempts (32s)
```

#### Docker Log Capture
Automatically captures container logs on **failure** or when `--docker-log` is specified:

```
Capturing Docker container logs to: /path/to/zapd.log
✓ Docker logs captured (45832 bytes)
```

**Log file format:**
```
=== ZAP DOCKER CONTAINER LOGS ===

=== STDOUT ===
[ZAP container stdout here]

=== STDERR ===
[ZAP container stderr here]
```

#### ZAP Internal Log Mounting
When `--zap-log-dir` is specified:

```
Mounting ZAP log directory: /host/path -> /zap/wrk
✓ ZAP internal log written: /host/path/zap.log (234567 bytes)
```

This captures **ZAP's own internal log file** for deep debugging.

---

### 7. **Scan Configuration Summary**

At the start of every scan:

```
======================================================================
ZAP DAEMON SCAN STARTING
======================================================================
Scan Configuration:
  Target: https://example.com
  API URL: http://127.0.0.1:8080
  Spider: True
  AJAX Spider: False
  Active Scan: False
  Max Time: 10 minutes
  Context: Guardian
  Auth: Yes
  Verbose: True
  Log File: /path/to/zap_scan.log
======================================================================
```

---

### 8. **Alert Severity Breakdown**

After alert collection:

```
✓ Collected 23 alerts
Alert breakdown:
  High: 2
  Medium: 5
  Low: 14
  Informational: 2
```

---

### 9. **Final Scan Summary**

```
======================================================================
ZAP SCAN COMPLETED SUCCESSFULLY
Total Duration: 2m 59s
Total Alerts: 23
Warnings: 1
======================================================================
```

---

## Usage Examples

### Basic Scan (**Enhanced logging is automatic - no flags needed!**)

```bash
python scripts/zap_daemon_scan.py \
  --target https://example.com \
  --spider
```

**Output (stderr) - Automatic:**
```
2026-01-24 15:30:00 [INFO] ZAP DAEMON SCAN STARTING
2026-01-24 15:30:00 [INFO] Scan Configuration:
2026-01-24 15:30:00 [INFO]   Target: https://example.com
...
2026-01-24 15:30:01 [INFO] === PHASE START: Spider Scan ===
2026-01-24 15:30:01 [INFO] Starting spider scan...
2026-01-24 15:30:02 [INFO] Spider progress: 10%
...
2026-01-24 15:32:00 [INFO] === PHASE COMPLETE: Spider Scan (2m 25s) ===
2026-01-24 15:32:30 [INFO] ZAP SCAN COMPLETED SUCCESSFULLY
```

**Output (stdout):** Clean JSON (unchanged)

**No flags needed!** Progress updates, phase timing, and scan summaries are shown by default.

---

### DEBUG-Level Logging with File Logging

Use `--verbose` only if you need API-level debugging:

```bash
python scripts/zap_daemon_scan.py \
  --target https://example.com \
  --spider \
  --verbose \
  --log-file /tmp/zap_scan.log
```

**Output (stderr):** Same as default, **plus** DEBUG messages (API calls, responses)

**Output (/tmp/zap_scan.log):**
```
2026-01-24 15:30:00 [INFO] [main:408] ZAP DAEMON SCAN STARTING
2026-01-24 15:30:00 [DEBUG] [_get_json:144] API GET: http://127.0.0.1:8080/JSON/core/view/version/
2026-01-24 15:30:01 [DEBUG] [_get_json:150] API Response: {"version": "2.14.0"}
...
```

---

### Docker Scan with Full Logging

```bash
python scripts/zap_docker_daemon_scan.py \
  --target https://example.com \
  --spider \
  --verbose \
  --log-file /tmp/zapd.log \
  --docker-log /tmp/zapd_container.log \
  --zap-log-dir /tmp/zap_logs
```

**Creates 3 log files:**
1. `/tmp/zapd.log` - Docker wrapper logs
2. `/tmp/zapd_scan.log` - ZAP daemon scan logs (nested)
3. `/tmp/zapd_container.log` - Docker container stdout/stderr
4. `/tmp/zap_logs/zap.log` - ZAP's own internal log file

---

## Debugging Tips

### Scan Hangs/Times Out

**Before (minimal info):**
```
ERROR: Timed out waiting for ZAP scan to finish
```

**After (actionable info):**
```
ERROR: Timed out waiting for ZAP scan to finish (last known status: spider 67%)
```

**Action:** Check if the spider is stuck on a specific URL or domain. Review ZAP internal logs for rate limiting, redirects, or infinite loops.

---

### Scan Fails Without Obvious Reason

**Before:**
```
ERROR: API request failed
```

**After (with --verbose):**
```
2026-01-24 15:30:45 [ERROR] [_get_json:153] API request failed for http://127.0.0.1:8080/JSON/core/view/version/: Connection refused
```

**Action:** Check if ZAP daemon is running. Review Docker logs with `--docker-log`.

---

### Docker Container Startup Issues

**Before (no visibility):**
```
ERROR: Timed out waiting for ZAP daemon API to become ready
```

**After:**
```
Checking Docker availability...
✓ Docker is available
=== PHASE 1: Starting ZAP Docker Container ===
✓ Docker container started
  Container ID: a3b8c9d12345
=== PHASE 2: Waiting for ZAP API ===
Waiting for ZAP API at http://127.0.0.1:8080 (timeout: 180s)...
[DEBUG] API check attempt 1 failed: Connection refused
[DEBUG] API check attempt 2 failed: Connection refused
...
[ERROR] ZAP API not ready after 180s (90 attempts)
```

**Action:** Review Docker logs with `--docker-log` to see ZAP's startup errors.

---

### Missing ZAP Internal Logs

**Before:** No access to ZAP's internal logs in Docker mode

**After (with --zap-log-dir):**
```
Mounting ZAP log directory: /tmp/zap_logs -> /zap/wrk
✓ ZAP internal log written: /tmp/zap_logs/zap.log (234567 bytes)
```

**Action:** Review `/tmp/zap_logs/zap.log` for ZAP's internal errors, plugin failures, or configuration issues.

---

## Performance Analysis

### Example Timing Breakdown

```json
{
  "timing": {
    "phases": {
      "ZAP Connection & Verification": {"elapsed_seconds": 1.2, "elapsed_formatted": "1.2s"},
      "Seed URL Access": {"elapsed_seconds": 0.8, "elapsed_formatted": "0.8s"},
      "Context & Authentication Setup": {"elapsed_seconds": 2.3, "elapsed_formatted": "2.3s"},
      "Spider Scan": {"elapsed_seconds": 145.6, "elapsed_formatted": "2m 25s"},
      "Passive Scan Queue Drain": {"elapsed_seconds": 32.4, "elapsed_formatted": "32.4s"},
      "Alert Collection": {"elapsed_seconds": 1.9, "elapsed_formatted": "1.9s"}
    },
    "total_seconds": 184.2,
    "total_formatted": "3m 4s"
  }
}
```

**Analysis:**
- Spider scan took 79% of total time (145.6s / 184.2s)
- Passive scan queue drain took 18% (32.4s / 184.2s)
- All other phases were fast (<3s each)

**Optimization:** If spider is too slow, consider:
- Using seed URLs to skip discovery (`--seed-file`)
- Limiting max spider depth
- Using `--ignore-robots` if robots.txt is blocking important paths

---

## Report Enhancements

### HTML/Markdown Reports Now Include Timing

**HTML Report:**
```html
<div class="timing">
  <h2>Scan Timing</h2>
  <p><strong>Total Duration:</strong> 3m 4s</p>
  <ul>
    <li><strong>Spider Scan:</strong> 2m 25s</li>
    <li><strong>Passive Scan Queue Drain:</strong> 32.4s</li>
    ...
  </ul>
</div>
```

**Markdown Report:**
```markdown
## Scan Timing

**Total Duration**: 3m 4s

### Phase Breakdown

- **Spider Scan**: 2m 25s
- **Passive Scan Queue Drain**: 32.4s
...
```

---

## Backward Compatibility

### JSON Output
- All existing fields preserved
- New fields added (non-breaking)
- Guardian workflows continue to work unchanged

### Command-Line Interface
- All existing flags work exactly as before
- New flags are **optional** (defaults to previous behavior)
- stderr logging is always enabled (was previously silent)
- stdout JSON is unchanged

---

## Comparison: Before vs After

### Before (Minimal Logging)

**Console/Logs:**
```
(nothing - completely silent except errors)
```

**JSON Output:**
```json
{
  "zap": {"api_url": "...", "version": "..."},
  "target": "...",
  "mode": "daemon",
  "spider": true,
  "alerts": [...]
}
```

---

### After (Rich Logging)

**Console (stderr):**
```
2026-01-24 15:30:00 [INFO] ZAP DAEMON SCAN STARTING
2026-01-24 15:30:00 [INFO] Scan Configuration: ...
2026-01-24 15:30:01 [INFO] === PHASE START: Spider Scan ===
2026-01-24 15:30:02 [INFO] Spider progress: 10%
2026-01-24 15:30:15 [INFO] Spider progress: 50%
2026-01-24 15:32:26 [INFO] Spider progress: 100%
2026-01-24 15:32:26 [INFO] === PHASE COMPLETE: Spider Scan (2m 25s) ===
2026-01-24 15:32:30 [INFO] ZAP SCAN COMPLETED SUCCESSFULLY
```

**JSON Output (stdout - still clean):**
```json
{
  "zap": {
    "api_url": "...",
    "version": "...",
    "scan_policy": "Default Policy"
  },
  "scan_options": {...},
  "timing": {...},
  "timestamp": "2026-01-24T15:32:30.123456",
  "alerts": [...]
}
```

---

## Files Modified

1. **scripts/zap_daemon_scan.py** (559 lines → 954 lines)
   - Added: Logging setup, PhaseTimer, progress tracking, timing summary
   - Enhanced: Timeout errors, JSON output, API debugging

2. **scripts/zap_docker_daemon_scan.py** (156 lines → 476 lines)
   - Added: Logging setup, Docker availability check, container log capture
   - Enhanced: API readiness monitoring, ZAP log mounting, cleanup logging

---

## Testing

### Test Basic Scan
```bash
python scripts/zap_daemon_scan.py \
  --target http://testphp.vulnweb.com \
  --spider \
  --verbose \
  --log-file /tmp/test_zap.log
```

**Expected:**
- Detailed phase-by-phase logs on stderr
- Clean JSON on stdout
- Full debug log in /tmp/test_zap.log

### Test Docker Scan
```bash
python scripts/zap_docker_daemon_scan.py \
  --target http://testphp.vulnweb.com \
  --spider \
  --verbose \
  --log-file /tmp/test_zapd.log \
  --docker-log /tmp/test_zapd_container.log \
  --zap-log-dir /tmp/test_zap_logs
```

**Expected:**
- Container startup logs
- API readiness checks
- Scan execution (delegated to zap_daemon_scan.py)
- Container cleanup logs
- 4 log files created

### Test Timeout
```bash
python scripts/zap_daemon_scan.py \
  --target http://example.com \
  --spider \
  --max-minutes 0.1 \
  --verbose
```

**Expected:**
- Scan starts
- Timeout error with "last known status: spider X%"
- Exit code 1

---

## Future Enhancements (Optional)

1. **Metrics Export**: Export timing data to Prometheus/StatsD
2. **Real-time WebSocket**: Stream logs via WebSocket for live monitoring
3. **Alert Deduplication**: Flag duplicate alerts across scans
4. **Scan Comparison**: Compare alerts/timing between scans
5. **ZAP Plugin Logging**: Log which ZAP plugins contributed alerts

---

## Summary

**Before:** ZAP scans were black boxes with minimal visibility.

**After:** Full transparency with:
- ✅ Phase-by-phase progress tracking
- ✅ Timing breakdowns for performance analysis
- ✅ Last-known status on timeout
- ✅ Alert severity breakdown
- ✅ Docker container log capture
- ✅ ZAP internal log mounting
- ✅ Structured logging with --verbose and --log-file
- ✅ Enhanced JSON output with timing and scan options
- ✅ Zero breaking changes to existing workflows

All improvements are **opt-in** via command-line flags, ensuring backward compatibility.
