# Laravel Perimeter Security Runbooks

This document provides incident response procedures and runbooks for common security events detected by Laravel Perimeter.

## Incident Response Framework

### 1. Preparation

- Ensure Laravel Perimeter is properly configured and all components are healthy
- Set up appropriate logging channels with alerting for critical events
- Define security roles and responsibilities within your organization
- Document contact information for the security team

### 2. Detection

Laravel Perimeter detects security events through:
- ClamAV malware scanning
- Falco behavioral monitoring
- Trivy vulnerability scanning

### 3. Analysis

When an event is detected:
- Verify the event by checking logs and reports
- Determine the severity and potential impact
- Identify affected systems and data
- Gather all relevant information

### 4. Containment

Implement containment strategies based on the type of event:
- Isolate affected systems
- Block suspicious IP addresses
- Disable compromised accounts
- Stop affected services

### 5. Eradication

Remove the threat from your systems:
- Delete malicious files
- Patch vulnerabilities
- Update dependencies
- Fix misconfigurations

### 6. Recovery

Restore systems to normal operation:
- Validate system integrity
- Confirm security controls are in place
- Restore from clean backups if necessary
- Perform security testing

### 7. Post-Incident Activities

Learn from the incident:
- Document the incident and response
- Update security controls
- Conduct a post-incident review
- Implement preventive measures

## Runbooks for Specific Events

### Malware Detection Response

#### Severity: Critical

When Laravel Perimeter detects malware in an uploaded file or system directory:

1. **Immediate Actions**
   - Quarantine the infected file
   - Block the IP address that uploaded the file
   - Check other files from the same user/IP
   - Scan the entire system for additional infections

2. **Investigation**
   ```bash
   # Get details about the detected threat
   php artisan perimeter:report --type=malware --severity=critical,high
   
   # Scan the entire system for additional infections
   php artisan perimeter:audit --format=json > malware-audit.json
   ```

3. **Remediation**
   - Remove infected files
   - Update antivirus definitions
   - Patch vulnerabilities that may have been exploited
   - Review file upload validation rules

4. **Prevention**
   - Add additional file validation
   - Implement stricter content type restrictions
   - Consider implementing additional scanning layers

### Behavioral Anomaly Response

#### Severity: High

When Falco detects suspicious system behavior:

1. **Immediate Actions**
   - Identify the process and user involved
   - Temporarily suspend the suspicious activity
   - Preserve evidence for investigation

2. **Investigation**
   ```bash
   # Get details about the behavioral event
   php artisan perimeter:monitor
   
   # Check system logs for related activities
   grep -r "suspicious_process_name" /var/log/
   ```

3. **Remediation**
   - Terminate unauthorized processes
   - Reset compromised credentials
   - Apply security patches
   - Update system configurations

4. **Prevention**
   - Review and update Falco rules
   - Implement additional access controls
   - Enhance monitoring for similar patterns

### Vulnerability Detection Response

#### Severity: Medium to Critical

When Trivy identifies vulnerabilities in dependencies:

1. **Immediate Actions**
   - Assess the severity and exploitability of the vulnerability
   - Check if the vulnerability is being actively exploited
   - Determine if temporary mitigations are needed

2. **Investigation**
   ```bash
   # Get detailed vulnerability report
   php artisan perimeter:report --type=vulnerability --severity=critical,high
   
   # Check for exploitability in your environment
   grep -r "CVE-20XX-XXXX" /var/log/
   ```

3. **Remediation**
   - Update vulnerable dependencies
   - Apply vendor-provided patches
   - Implement workarounds if updates aren't available
   - Test application functionality after updates

4. **Prevention**
   - Implement regular dependency scanning
   - Subscribe to security advisories
   - Automate dependency updates for security patches

## Common Security Event Scenarios

### Scenario 1: SQL Injection Attempt

When the perimeter middleware detects SQL injection patterns:

1. **Immediate Actions**
   - Block the offending IP address
   - Review the affected request and endpoint
   - Check database for signs of compromise

2. **Investigation**
   - Analyze logs to identify all requests from the source
   - Check for successful exploits
   - Determine if data was accessed or modified

3. **Remediation**
   - Patch vulnerable code with proper parameterization
   - Validate and sanitize all inputs
   - Update WAF rules

4. **Prevention**
   - Implement prepared statements everywhere
   - Add input validation and sanitization
   - Consider using an ORM for database queries

### Scenario 2: Mass Assignment Vulnerability Exploit

When Falco detects potential mass assignment exploitation:

1. **Immediate Actions**
   - Identify the affected model and controller
   - Review the request data
   - Check for unauthorized data modifications

2. **Investigation**
   - Review model attributes for sensitive fields
   - Check for missing protections ($fillable/$guarded)
   - Determine if privilege escalation occurred

3. **Remediation**
   - Implement proper attribute protection
   - Add request validation
   - Revert unauthorized changes

4. **Prevention**
   - Audit all models for proper attribute protection
   - Implement strict request validation
   - Use form requests for complex validation rules

### Scenario 3: Critical Dependency Vulnerability

When Trivy identifies a critical vulnerability:

1. **Immediate Actions**
   - Verify the affected component is in use
   - Check if the vulnerability is exploitable in your context
   - Apply temporary mitigations if possible

2. **Investigation**
   - Research the vulnerability details
   - Determine how it could impact your application
   - Check for signs of exploitation

3. **Remediation**
   - Update the vulnerable dependency
   - Apply security patches
   - Verify the fix with additional scanning

4. **Prevention**
   - Implement automated dependency scanning in CI/CD
   - Establish a vulnerability management process
   - Set up alerts for new vulnerabilities

## Contact Information

- **Security Team Email**: security@yourcompany.com
- **Security On-Call**: +1-555-123-4567
- **Incident Response Channel**: #security-incidents (Slack)

## References

- [ClamAV Documentation](https://www.clamav.net/documents/clam-antivirus-user-manual)
- [Falco Documentation](https://falco.org/docs/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/latest/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Laravel Security Best Practices](https://laravel.com/docs/security)