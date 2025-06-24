#!/bin/bash

# Remote Perimeter Testing Script
# Run this on the remote server after deploying latest changes

set -e

echo "🚀 Starting Perimeter Remote Testing..."
echo "========================================"

# Environment check
echo "📊 Environment Baseline:"
echo "Memory: $(free -h | grep Mem)"
echo "OS: $(lsb_release -d 2>/dev/null || echo 'Unknown')"
echo "Current directory: $(pwd)"
echo ""

# Deploy latest changes
echo "🔄 Deploying Latest Changes..."
git fetch origin
git checkout remote-dev
git pull origin remote-dev
composer update prahsys/laravel-perimeter --with-all-dependencies
php artisan config:clear
php artisan cache:clear
echo "✅ Deployment complete"
echo ""

# Test 1: Health Check
echo "🏥 Service Health Check:"
php artisan perimeter:health
echo ""

# Test 2: Memory-aware ClamAV Test
echo "🧠 Memory-Aware ClamAV Test:"
echo "Expected: Should use direct scanning due to 961MB memory limit"
rm -f /tmp/clamav-scan.log

# Start audit and monitor
echo "Starting audit with progress monitoring..."
timeout 120 php artisan perimeter:audit &
AUDIT_PID=$!

# Monitor progress
sleep 3
if [ -f /tmp/clamav-scan.log ]; then
    echo "✅ Scan log created"
    echo "Progress entries: $(wc -l < /tmp/clamav-scan.log)"
    echo "Latest entries:"
    tail -5 /tmp/clamav-scan.log
else
    echo "⚠️ No scan log found yet"
fi

# Wait for completion
wait $AUDIT_PID
AUDIT_EXIT=$?

echo "Audit completed with exit code: $AUDIT_EXIT"
echo ""

# Test 3: Check for memory issues
echo "💾 Memory and Process Check:"
echo "Memory after scan:"
free -h | grep Mem

echo "Check for OOM kills:"
dmesg | grep -i "killed\|oom" | tail -3 || echo "No OOM kills detected"

echo "ClamAV processes:"
ps aux | grep clam | grep -v grep || echo "No ClamAV processes running"
echo ""

# Test 4: Verify scan log
echo "📝 Scan Log Analysis:"
if [ -f /tmp/clamav-scan.log ]; then
    echo "✅ Scan log exists"
    echo "Size: $(ls -lh /tmp/clamav-scan.log | awk '{print $5}')"
    echo "Lines: $(wc -l < /tmp/clamav-scan.log)"
    echo "Sample entries:"
    head -3 /tmp/clamav-scan.log
    echo "..."
    tail -3 /tmp/clamav-scan.log
else
    echo "❌ Scan log not found"
fi
echo ""

# Test 5: Configuration verification
echo "⚙️ Configuration Check:"
echo "ClamAV config entries:"
grep -A 3 "scan_timeout\|min_memory_for_daemon\|force_direct" config/perimeter.php || echo "Config not found"
echo ""

# Test 6: Service binary check
echo "🔧 Service Binary Check:"
echo "Available binaries:"
which clamscan 2>/dev/null && echo "✅ clamscan available" || echo "❌ clamscan missing"
which clamdscan 2>/dev/null && echo "✅ clamdscan available" || echo "❌ clamdscan missing"
which fail2ban-client 2>/dev/null && echo "✅ fail2ban-client available" || echo "❌ fail2ban-client missing"
which ufw 2>/dev/null && echo "✅ ufw available" || echo "❌ ufw missing"
which trivy 2>/dev/null && echo "✅ trivy available" || echo "❌ trivy missing"
echo ""

# Test 7: Generate report
echo "📊 Generate Security Report:"
php artisan perimeter:report
echo ""

echo "🎉 Testing Complete!"
echo "===================="
echo ""
echo "📋 Results Summary:"
echo "- Memory constraint: $(free -h | grep Mem | awk '{print $2}') total"
echo "- Audit exit code: $AUDIT_EXIT"
echo "- Scan log: $([ -f /tmp/clamav-scan.log ] && echo 'Created' || echo 'Missing')"
echo "- OOM issues: $(dmesg | grep -i oom | wc -l) events"
echo ""
echo "🔍 Key checks:"
echo "- Should use direct scanning (not daemon mode)"
echo "- Should complete without timeout"
echo "- Should create /tmp/clamav-scan.log with progress"
echo "- Should not trigger OOM killer"