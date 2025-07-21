FROM ubuntu:22.04

ENV container docker
ENV DEBIAN_FRONTEND noninteractive

# Don't start any optional services except for the few we need
RUN find /etc/systemd/system \
    /lib/systemd/system \
    -path '*.wants/*' \
    -not -name '*journald*' \
    -not -name '*systemd-tmpfiles*' \
    -not -name '*systemd-user-sessions*' \
    -exec rm \{} \;

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    dbus \
    systemd \
    iproute2 \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    libzip-dev \
    zip \
    unzip \
    sudo \
    procps \
    wget \
    gnupg \
    lsb-release \
    apt-transport-https \
    ca-certificates \
    fail2ban \
    python3-minimal \
    software-properties-common \
    apparmor-utils \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install PHP 8.2 and extensions
RUN add-apt-repository ppa:ondrej/php && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    php8.2-cli php8.2-common \
    php8.2-mysql php8.2-zip php8.2-gd \
    php8.2-mbstring php8.2-curl php8.2-xml \
    php8.2-bcmath php8.2-sqlite3 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Configure systemd
RUN systemctl set-default multi-user.target
RUN systemctl mask dev-hugepages.mount sys-fs-fuse-connections.mount

# Workaround for agetty high CPU usage
RUN rm -f /lib/systemd/system/systemd*udev*
RUN rm -f /lib/systemd/system/getty.target

# Setup directories
RUN mkdir -p /var/www/laravel-app
RUN mkdir -p /var/run/perimeter
RUN mkdir -p /var/log/perimeter

# Set working directory
WORKDIR /var/www/laravel-app

# Copy the Laravel app from test-app
COPY test-app/ /var/www/laravel-app/

# Setup permissions
RUN chmod -R 755 /var/www/laravel-app
RUN mkdir -p /var/www/laravel-app/storage/logs
RUN chmod -R 777 /var/www/laravel-app/storage
RUN chmod -R 777 /var/www/laravel-app/bootstrap/cache

# Copy systemd service definitions
COPY docker/setup /sbin/
RUN chmod +x /sbin/setup

# Copy AppArmor profiles
COPY docker/apparmor/ /etc/apparmor.d/
RUN chmod 644 /etc/apparmor.d/*

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose port for Laravel
EXPOSE 8000

# Set stop signal for systemd
STOPSIGNAL SIGRTMIN+3

# Run entrypoint and then systemd
CMD ["/bin/bash", "-c", "/usr/local/bin/docker-entrypoint.sh && exec /sbin/init --log-target=journal 3>&1"]