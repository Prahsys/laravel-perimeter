# Remote Service Testing - Step by Step

## Baseline: Local Docker Results
✅ **All 55 tests passing locally** (274 assertions)
- Unit tests: ClamAV, Fail2ban, Falco, Trivy, UFW parsers
- Feature tests: Middleware, health commands, integrations
- Service manager and data transformation tests

## Remote Testing Protocol

### Prerequisites Setup
```bash
# 1. Deploy latest changes (run locally first)
git push origin remote-dev

# 2. Connect to remote server
ssh forge@test-api.prognosix.ai
cd ~/test-api.prognosix.ai/current

# 3. Update package
git fetch origin && git checkout remote-dev && git pull origin remote-dev
composer update prahsys/laravel-perimeter --with-all-dependencies
php artisan config:clear && php artisan cache:clear

# 4. Check memory baseline
free -h
# Expected: ~961MB total, insufficient for ClamAV daemon mode
```

## Service Testing Sequence

### 1. System Audit Service (Basic Foundation)
```bash
echo "=== TESTING: System Audit Service ==="
php artisan perimeter:health | grep -A 10 "System Audit"

# Expected Output:
# ✅ System Audit: Available
# - Service: Enabled
# - Status: Operational
```

**Compare with Local Docker:**
- Should show same "Available" and "Operational" status
- No system dependencies, should work consistently

---

### 2. ClamAV Service (Memory-Aware Testing)
```bash
echo "=== TESTING: ClamAV Service (Memory-Aware) ==="

# A. Check memory detection
php artisan perimeter:health | grep -A 15 "ClamAV"

# Expected Output (NEW BEHAVIOR):
# ⚠️  ClamAV: Available (using direct scanning due to memory constraints)
# - Service: Enabled
# - Memory Available: ~400MB (insufficient for daemon mode)
# - Scan Mode: Direct scanning (clamscan)
# - Daemon Status: Not suitable for this environment

# B. Test scan with progress logging
echo "Starting ClamAV scan test..."
rm -f /tmp/clamav-scan.log
timeout 60 php artisan perimeter:audit --only=clamav &
AUDIT_PID=$!

# Monitor progress
echo "Watching scan progress..."
sleep 2
tail -f /tmp/clamav-scan.log &
TAIL_PID=$!

# Wait for completion or timeout
wait $AUDIT_PID
kill $TAIL_PID 2>/dev/null

# C. Verify results
echo "Scan completed. Results:"
ls -la /tmp/clamav-scan.log
wc -l /tmp/clamav-scan.log
tail -10 /tmp/clamav-scan.log
```

**Compare with Local Docker:**
- **Local**: May use daemon mode if enough memory
- **Remote**: Should use direct scanning mode
- **Both**: Should complete without timeout errors
- **Both**: Should create scan log with progress

---

### 3. UFW Service (Network Security)
```bash
echo "=== TESTING: UFW Service ==="

# Check UFW status
php artisan perimeter:health | grep -A 10 "UFW"

# Expected Output:
# ✅ UFW: Available
# - Service: Enabled  
# - Status: Active/Inactive (depends on server config)
# - Rules: [number] rules configured

# Test UFW command execution
sudo ufw status verbose
```

**Compare with Local Docker:**
- **Local**: May show "inactive" in container
- **Remote**: Should show actual server firewall status
- **Both**: Service should be detected as available

---

### 4. Fail2ban Service (Intrusion Prevention)
```bash
echo "=== TESTING: Fail2ban Service ==="

# Check Fail2ban status
php artisan perimeter:health | grep -A 15 "Fail2ban"

# Expected Output:
# ✅ Fail2ban: Available
# - Service: Enabled
# - Status: Active
# - Jails: [list of active jails]
# - Banned IPs: [number]

# Test jail status
sudo fail2ban-client status
php artisan perimeter:audit --only=fail2ban
```

**Compare with Local Docker:**
- **Local**: Limited functionality in container
- **Remote**: Full service functionality
- **Both**: Parser should handle output correctly

---

### 5. Trivy Service (Vulnerability Scanning)
```bash
echo "=== TESTING: Trivy Service ==="

# Check Trivy status  
php artisan perimeter:health | grep -A 10 "Trivy"

# Expected Output:
# ✅ Trivy: Available
# - Service: Enabled
# - Database: Updated [timestamp]
# - Scanner: Ready

# Test vulnerability scan with timeout
echo "Testing Trivy scan with extended timeout..."
timeout 300 php artisan perimeter:audit --only=trivy
```

**Compare with Local Docker:**
- **Local**: Same functionality expected
- **Remote**: Should have network access for DB updates
- **Both**: Should complete within timeout

---

### 6. Falco Service (Runtime Security)
```bash
echo "=== TESTING: Falco Service ==="

# Check Falco status
php artisan perimeter:health | grep -A 10 "Falco"

# Expected Output:
# ❌ Falco: Not Available (likely not installed)
# - Service: Enabled in config
# - Status: Binary not found
# - Installation: Required

# This is expected on most servers
echo "Falco not available - this is normal for staging servers"
```

**Compare with Local Docker:**
- **Local**: Also likely not available unless specifically installed
- **Remote**: Expected to be unavailable
- **Both**: Should gracefully handle missing binary

---

## Comprehensive Integration Test
```bash
echo "=== FULL INTEGRATION TEST ==="

# 1. Full health check
echo "1. Complete health check:"
php artisan perimeter:health

# 2. Complete audit with logging
echo "2. Full audit with progress monitoring:"
rm -f /tmp/clamav-scan.log
time php artisan perimeter:audit

# 3. Generate report
echo "3. Generate security report:"
php artisan perimeter:report

# 4. Check for any errors
echo "4. Check for errors in Laravel logs:"
tail -20 storage/logs/laravel.log | grep -i error
```

## Expected Results Summary

### ✅ Success Criteria
- [ ] System Audit: Always available
- [ ] ClamAV: Available with memory-aware mode selection
- [ ] UFW: Available (status depends on server config)
- [ ] Fail2ban: Available with active jails
- [ ] Trivy: Available with network connectivity
- [ ] Falco: May not be available (acceptable)
- [ ] No timeout errors during scans
- [ ] Progress logging works for ClamAV
- [ ] Memory usage stays within limits
- [ ] All operations complete in reasonable time

### ❌ Failure Indicators
- Timeout errors during audit
- OOM killer activating
- Services showing as "Error" instead of "Available" or "Not Available"
- Missing scan progress logs
- PHP memory exhaustion

## Troubleshooting Quick Commands
```bash
# Check for OOM kills
dmesg | grep -i "killed\|oom" | tail -5

# Monitor memory during scan
free -h
ps aux | grep clam

# Check service binaries
which clamav clamscan clamdscan fail2ban-client ufw trivy

# Test individual components
clamscan --version
fail2ban-client version
ufw version
trivy version
```

## Results Documentation Template
```
## Remote Testing Results - [DATE]

### Environment
- Server: forge@test-api.prognosix.ai  
- Memory: [output of free -h]
- OS: [output of lsb_release -a]

### Service Status
- [ ] System Audit: ✅/❌ [notes]
- [ ] ClamAV: ✅/❌ [scan mode: daemon/direct]
- [ ] UFW: ✅/❌ [status]
- [ ] Fail2ban: ✅/❌ [jails active]
- [ ] Trivy: ✅/❌ [scan time]
- [ ] Falco: ✅/❌ [expected unavailable]

### Performance
- [ ] ClamAV scan completed: ✅/❌ [time taken]
- [ ] No OOM issues: ✅/❌
- [ ] Progress logging: ✅/❌ [log entries count]

### Issues Found
[List any problems]

### Comparison with Local Docker
[Note differences and similarities]
```