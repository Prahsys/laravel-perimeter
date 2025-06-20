# Docker Configuration Files

This directory contains configuration files used by the security services when running in Docker containers.

## Directory Structure

- `clamav/` - Configuration files for ClamAV antivirus
  - `clamd.conf` - Main ClamAV daemon configuration
  - `freshclam.conf` - Database updater configuration

- `falco/` - Configuration files for Falco runtime security monitoring
  - `falco.yaml` - Main Falco configuration
  - `laravel-rules.yaml` - Laravel-specific Falco rules

- `trivy/` - Configuration files for Trivy vulnerability scanner
  - `config.json` - Trivy configuration with memory optimizations

## Usage

These files are automatically copied to the appropriate locations in the container during the installation process when `Perimeter::isRunningInContainer()` returns true.

You can modify these files to customize the behavior of security services in Docker environments without having to modify the installer code.

## Memory Considerations

The configurations are optimized for containerized environments with limited resources:

- **Trivy**: Uses minimal parallelism and skips scanning large directories
- **ClamAV**: Uses minimal configuration without large virus databases
- **Falco**: Operates without the kernel driver in container environments