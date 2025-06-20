# Laravel Perimeter Test App

This directory contains Docker-specific tests for the Laravel Perimeter package that need to run in an isolated environment with system-level access.

## Purpose

These tests focus on functionality that would affect the host system if run directly:

- Installing security tools (ClamAV, Trivy, Fail2ban, Falco)
- Verifying system services are running correctly
- Testing real file scanning with security tools
- Running commands that require elevated permissions

## Running the Tests

```bash
# Build and start the Docker containers
docker-compose up -d

# Run all tests (requires sudo for system installations)
docker-compose exec app bash -c 'cd /var/www && sudo ./vendor/bin/pest'

# Run only feature tests (those requiring Docker environment)
docker-compose exec app bash -c 'cd /var/www && sudo ./vendor/bin/pest tests/Feature'

# Run a specific test
docker-compose exec app bash -c 'cd /var/www && sudo ./vendor/bin/pest tests/Feature/InstallCommandTest.php'
```

## Important Notes

- Tests are automatically copied from test-app/tests to /var/www/tests in the Docker container
- Many tests require sudo privileges (for installing security tools)
- Tests follow the dependency chain: install → verify health → run scans
- The Docker container is already configured with necessary directories and permissions

## Test Categories

1. **Installation Tests**: Verify security tools can be properly installed
2. **Health Checks**: Ensure services are running and properly configured
3. **Audit Tests**: Check security reporting functionality
4. **Scanning Tests**: Test actual file scanning with security tools

These Docker-based tests complement the regular package tests by focusing only on functionality that requires system-level access.