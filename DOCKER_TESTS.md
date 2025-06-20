# Running Perimeter Tests in Docker

This guide explains how to run the Laravel Perimeter package tests in a Docker environment.

## Quick Start

1. Start the Docker container:
   ```bash
   docker-compose up -d
   ```

2. The container automatically sets up Pest PHP and copies the test files.

3. Run the tests:
   ```bash
   docker-compose exec app php artisan test
   ```
   
   Or using Pest directly:
   ```bash
   docker-compose exec app ./vendor/bin/pest
   ```

## What Gets Tested

The automated tests cover:

1. **SecurityEventData**
   - Service field for tracking which security service generated an event
   - Scan ID for associating events with specific security scans

2. **ServiceManager**
   - Service name management in configuration
   - Service name retrieval methods

3. **PerimeterAudit Command**
   - Display of service names in event tables
   - Logging of audit results at appropriate severity levels

4. **AbstractSecurityService**
   - Inclusion of service names in security events
   - Proper handling of scan_id property

## Adding More Tests

To add more tests to the test suite:

1. Add files to the `test-app/` directory matching Laravel's structure:
   - Unit tests go in `test-app/tests/Unit/`
   - Feature tests go in `test-app/tests/Feature/`
   - Config files go in `test-app/config/`
   - etc.

2. Follow the Pest PHP format for tests (see existing tests for examples)

3. Restart the Docker container:
   ```bash
   docker-compose restart app
   ```
   
   Or rebuild if you've made significant changes:
   ```bash
   docker-compose down
   docker-compose up -d --build
   ```

## Directory Structure

The `test-app` directory mirrors a Laravel application structure:

```
test-app/
├── bootstrap/              # Bootstrap files for Laravel
│   └── app.php
├── phpunit.xml             # PHPUnit/Pest configuration
├── storage/                # Storage directories
│   └── logs/
└── tests/                  # Test files
    ├── Feature/            # Feature tests
    ├── Unit/               # Unit tests
    ├── CreatesApplication.php
    ├── Pest.php
    └── TestCase.php
```

All files are intelligently copied to the corresponding location in the Docker Laravel application, preserving the directory structure.

## Debugging Test Issues

If you encounter issues running the tests:

1. Check the container logs:
   ```bash
   docker-compose logs app
   ```

2. Enter the container to debug directly:
   ```bash
   docker-compose exec app bash
   ```

3. Inside the container, you can:
   - Check if Pest is installed: `composer show pestphp/pest`
   - Verify test files are copied: `ls -la tests/Unit/`
   - Run tests with verbose output: `./vendor/bin/pest --verbose`