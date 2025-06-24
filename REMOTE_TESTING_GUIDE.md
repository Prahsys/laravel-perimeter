# Remote Testing Guide - Laravel Perimeter

## Server Profile
- **Host**: `forge@test-api.prognosix.ai`
- **Environment**: Staging
- **Memory**: 961MB (insufficient for ClamAV daemon mode)
- **OS**: Ubuntu/Debian-based
- **ClamAV Version**: 1.0.8
- **Application Path**: `/home/forge/test-api.prognosix.ai/releases/20250610205713`

## Prerequisites
- SSH key access configured
- Sudo access available
- Laravel application deployed

## Testing Checklist

### 1. Pre-Testing Setup
```bash
# Connect to server
ssh forge@test-api.prognosix.ai

# Navigate to application directory
cd ~/test-api.prognosix.ai/current

# Check current memory status
free -h

# Verify ClamAV installation
clamscan --version
freshclam --version
```

### 2. Deploy Latest Package Changes
```bash
# Push latest changes from local development
# (Run this locally first)
git add .
git commit -m "feat: add memory-aware ClamAV scanning and Laravel package conventions"
git push origin remote-dev

# On remote server, pull latest changes
git fetch origin
git checkout remote-dev
git pull origin remote-dev

# Update Composer dependencies to get latest package changes
composer update prahsys/laravel-perimeter --with-all-dependencies

# Clear any cached config
php artisan config:clear
php artisan cache:clear
```

### 3. Configuration Testing

#### A. Publish Configuration (New Workflow)
```bash
# Test the new vendor:publish workflow
php artisan vendor:publish --tag=perimeter-config

# Verify config file was created
ls -la config/perimeter.php

# Check config contains new memory settings
grep -A 5 "scan_timeout\|min_memory_for_daemon" config/perimeter.php
```

#### B. Test Install Command Validation
```bash
# Remove config to test validation
sudo rm config/perimeter.php

# Try install without config - should fail with helpful message
sudo php artisan perimeter:install

# Restore config
php artisan vendor:publish --tag=perimeter-config
```

### 4. Memory-Aware ClamAV Testing

#### A. Verify Memory Detection
```bash
# Test memory detection and scan mode selection
php artisan perimeter:health

# Should show: "Using direct scanning (daemon requires more memory)"
```

#### B. Test Scan Progress Logging
```bash
# Start audit in background and watch progress
php artisan perimeter:audit &

# In another terminal, watch the scan log
tail -f /tmp/clamav-scan.log

# Expected output:
# [timestamp] Starting ClamAV scan of: /path/to/dir
# /path/to/file1.php: OK
# /path/to/file2.js: OK
# ... (should show progress for each file)
```

#### C. Test Timeout Configuration
```bash
# Check current timeout settings
grep -A 3 "scan_timeout" config/perimeter.php

# Should show: 'scan_timeout' => env('PERIMETER_CLAMAV_SCAN_TIMEOUT', 1800)
```

### 5. Full Audit Testing

#### A. Complete Audit Run
```bash
# Run full audit with progress monitoring
php artisan perimeter:audit

# Expected behavior:
# 1. Shows "Watch scan progress with: tail -f /tmp/clamav-scan.log"
# 2. Completes without timeout errors
# 3. Shows scan results summary
# 4. Reports "Using direct scanning" for ClamAV
```

#### B. Verify Log Output
```bash
# Check scan log was created and contains data
ls -la /tmp/clamav-scan.log
wc -l /tmp/clamav-scan.log
tail -20 /tmp/clamav-scan.log
```

### 6. Configuration Override Testing

#### A. Test Environment Variable Overrides
```bash
# Add to .env file
echo "PERIMETER_CLAMAV_SCAN_TIMEOUT=3600" >> .env
echo "PERIMETER_CLAMAV_MIN_MEMORY=2048" >> .env

# Test updated settings
php artisan config:clear
php artisan perimeter:health
```

#### B. Test Force Direct Scan
```bash
# Force direct scanning via config
echo "PERIMETER_CLAMAV_FORCE_DIRECT=true" >> .env
php artisan config:clear
php artisan perimeter:health

# Should show "Using direct scanning (forced by configuration)"
```

### 7. Error Handling Testing

#### A. Test Missing Permissions
```bash
# Test scan log creation permissions
sudo chown root:root /tmp/clamav-scan.log 2>/dev/null || true
sudo chmod 600 /tmp/clamav-scan.log 2>/dev/null || true

# Run audit - should handle gracefully
php artisan perimeter:audit

# Cleanup
sudo rm -f /tmp/clamav-scan.log
```

#### B. Test Large Directory Scan
```bash
# Test with vendor directory (if exists)
ls -la vendor/ | wc -l

# Run targeted scan
php artisan perimeter:audit

# Monitor progress and completion
```

### 8. Performance Monitoring

#### A. Resource Usage
```bash
# Monitor during scan
top -p $(pgrep clamscan) &
php artisan perimeter:audit

# Check memory usage didn't cause issues
dmesg | grep -i "killed\|oom" | tail -5
```

#### B. Timing Tests
```bash
# Time the audit
time php artisan perimeter:audit

# Should complete in reasonable time (< 30 minutes)
```

### 9. Integration Testing

#### A. Service Health After Changes
```bash
php artisan perimeter:health

# All services should report status correctly
```

#### B. Report Generation
```bash
php artisan perimeter:report

# Should generate report quickly without timeouts
```

## Expected Results

### ✅ Success Criteria
- [ ] Config publishes via `vendor:publish` command
- [ ] Install command requires config to be published first
- [ ] ClamAV detects insufficient memory and uses direct scanning
- [ ] Scan progress is logged to `/tmp/clamav-scan.log`
- [ ] Audit completes without timeout errors
- [ ] Memory usage stays within server limits
- [ ] All progress messages are clear and helpful

### ❌ Failure Indicators
- Config publishes automatically during install
- Timeout errors during scanning
- OOM killer terminating processes
- Missing or empty scan log file
- Unclear error messages

## Troubleshooting

### Common Issues
1. **Permission Denied on Log File**
   ```bash
   sudo chmod 666 /tmp/clamav-scan.log
   ```

2. **Config Not Found**
   ```bash
   php artisan vendor:publish --tag=perimeter-config --force
   ```

3. **Memory Issues**
   ```bash
   # Check for OOM kills
   dmesg | tail -20
   # Increase swap if needed
   sudo fallocate -l 1G /swapfile
   ```

## Rollback Plan
If issues occur:
```bash
# Stop any running scans
sudo pkill clamscan

# Clear scan log
sudo rm -f /tmp/clamav-scan.log

# Reset configuration
git checkout config/perimeter.php

# Clear config cache
php artisan config:clear
```

## Test Report Template

```markdown
## Test Results - [DATE]

### Configuration Publishing
- [ ] vendor:publish works: ✅/❌
- [ ] Install validation works: ✅/❌

### Memory-Aware Scanning  
- [ ] Memory detection accurate: ✅/❌
- [ ] Direct scan mode selected: ✅/❌
- [ ] Progress logging works: ✅/❌

### Performance
- [ ] Completes without timeout: ✅/❌
- [ ] Memory usage acceptable: ✅/❌
- [ ] Scan log created: ✅/❌

### Issues Found
[List any problems encountered]

### Notes
[Additional observations]
```

## Security Notes
- Never commit credentials to version control
- Use environment variables for sensitive configuration
- Regularly rotate access credentials
- Monitor server logs for unusual activity
- Test changes in staging before production