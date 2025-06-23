#!/bin/bash
set -e

# Run setup script to configure systemd services
/sbin/setup

# Create basic log directories
mkdir -p /var/log/perimeter
mkdir -p /var/log/fail2ban
mkdir -p /var/log/auth

# Setup auth.log for fail2ban
touch /var/log/auth/auth.log
ln -sf /var/log/auth/auth.log /var/log/auth.log

# Create auth.log but don't add any test entries
# Test data should only be created through the proper seeding command

# Setup SQLite for Laravel
mkdir -p /var/www/laravel-app/database
touch /var/www/laravel-app/database/database.sqlite
chmod 666 /var/www/laravel-app/database/database.sqlite

# Install package from local path if available
if [ -d "/package" ]; then
    # Configure composer repository
    composer config repositories.local '{"type": "path", "url": "/package", "options": {"symlink": true}}' --working-dir=/var/www/laravel-app
    
    # Update the lock file and install all dependencies
    composer update --no-interaction --with-all-dependencies --working-dir=/var/www/laravel-app
    
    # Install the package
    composer require prahsys/laravel-perimeter:@dev --working-dir=/var/www/laravel-app
    
    # Generate Pest file if needed
    if [ ! -f "/var/www/laravel-app/tests/Pest.php" ]; then
        echo "Setting up Pest test framework..."
        php /var/www/laravel-app/artisan pest:install --no-interaction
    fi
    
    # Publish config, migrations and run migrations
    php /var/www/laravel-app/artisan vendor:publish --tag=perimeter-config
    php /var/www/laravel-app/artisan vendor:publish --tag=perimeter-migrations
    php /var/www/laravel-app/artisan migrate --force
    
    # Automatically seed test data for Docker testing environment
    echo "Seeding test data for Docker testing environment..."
    php /var/www/laravel-app/artisan perimeter:seed-test-data --count=20
fi

# List the package commands if installed
if [ -d "/package" ] && command -v php > /dev/null; then
    echo "=== Available Perimeter Commands ==="
    php /var/www/laravel-app/artisan list | grep perimeter
    echo "==================================="
fi

echo "Docker entrypoint complete, launching systemd..."