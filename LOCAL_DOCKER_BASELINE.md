# Local Docker Baseline Results

## Quick Docker Test Commands
```bash
# Run these locally for comparison with remote results

# 1. Enter Docker container
docker-compose exec app bash

# 2. Inside container, run the same tests:
cd /package

# 3. Check memory in container
free -h

# 4. Test each service
php artisan perimeter:health

# 5. Full audit
php artisan perimeter:audit

# 6. Check what services are actually available in container
which clamscan clamdscan fail2ban-client ufw trivy

# 7. Test ClamAV specifically
clamscan --version
echo "EICAR test:" > /tmp/test.txt
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >> /tmp/test.txt
clamscan /tmp/test.txt

# 8. Check container memory constraints
cat /proc/meminfo | grep MemTotal
```

## Expected Docker Results
Based on our Docker setup:

### Memory Environment
- **Container Memory**: Typically much more than 961MB
- **ClamAV Mode**: May use daemon mode if memory sufficient
- **Memory Detection**: Should show different behavior than remote

### Service Availability
- **System Audit**: ✅ Always available
- **ClamAV**: ✅ Should be installed and working
- **UFW**: ❓ May not be active in container
- **Fail2ban**: ❓ May not be running in container  
- **Trivy**: ✅ Should be available
- **Falco**: ❌ Likely not installed

### Key Differences from Remote
1. **Memory**: Container may have more memory → daemon mode possible
2. **Services**: Some security services don't run well in containers
3. **Network**: Container networking vs real server networking
4. **Permissions**: Container root vs server user permissions

This baseline helps identify which differences are environment-specific vs actual bugs.