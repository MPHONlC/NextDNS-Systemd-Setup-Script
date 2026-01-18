# NextDNS Systemd-Resolved Setup Script

## Overview
A comprehensive, interactive bash script for configuring NextDNS with systemd-resolved on Linux systems, featuring DNS-over-TLS encryption, automatic fallback DNS configuration, and robust backup/restore capabilities.

## Features

### 🚀 Core Functionality
- **Easy NextDNS Integration**: Automatically configures systemd-resolved with your NextDNS profile
- **DNS-over-TLS Encryption**: All DNS queries are encrypted end-to-end
- **Custom Endpoint Naming**: Assign meaningful names to DNS endpoints for easy identification in logs
- **Automatic IPv6 Support**: Detects and configures IPv6 addresses for DNS services
- **Dry-Run Mode**: Test configurations without making system changes (`--dry-run` flag)

### 🔄 Fallback DNS Configuration
- **Smart Auto-Detection**: Automatically detects TLS hostnames, IPv6 addresses, and DNS-over-HTTP/3 support
- **Service Database**: Pre-configured with major DNS providers (Cloudflare, Google, Quad9, AdGuard, OpenDNS, CleanBrowsing)
- **Health Checking**: Tests DNS servers for responsiveness before adding them
- **Multi-Protocol Support**: Supports traditional DNS, DNS-over-TLS, and DNS-over-HTTP/3

### 💾 Backup & Restore System
- **Automatic Backups**: Creates timestamped backups before making changes
- **User-Friendly Restoration**: Interactive menu for restoring from any backup
- **Multiple Backup Locations**: Stores backups in both system and user directories
- **Manual Backup Creation**: Create backups on-demand with custom names
- **Backup Management**: List, restore, delete individual backups, or delete all backups

### 🛠️ DNS Utilities
The script adds these commands to your `.bashrc`:

- **`dns-config`**: View current DNS configuration
- **`verify-dns`**: Comprehensive verification and connectivity testing
- **`fix-dns`**: Fix NetworkManager DNS override issues
- **`dns-logs`**: View DNS statistics and systemd-resolved information
- **`dns-restore`**: Restore DNS configuration from backup
- **`dns-backup`**: Create manual backup of current DNS configuration
- **`checkdns`** / **`check-dns`**: Check DNS service responsiveness and protocol support
- **`dns-services`**: Show information about various DNS services

### 🎯 Additional Features
- **NetworkManager Integration**: Automatically configures NetworkManager to not interfere
- **Progress Indicators**: Visual progress bars for long operations
- **Color-coded Output**: Easy-to-read color-coded console output
- **Error Handling**: Comprehensive error checking and user-friendly error messages
- **Root Detection**: Ensures script runs with appropriate privileges

## Configuration Flow

1. **Backup Check**: Script checks for existing backups and offers restoration options
2. **NextDNS Setup**: Enter your NextDNS Profile ID and optional custom endpoint name
3. **Fallback DNS**: Optionally add fallback DNS servers with auto-detection
4. **System Configuration**: Configures systemd-resolved, resolv.conf, and NetworkManager
5. **Utilities Installation**: Adds DNS management commands to your shell
6. **Verification**: Runs final checks to ensure everything is working

## Supported DNS Services

The script includes a database of DNS services with their:
- IPv4 and IPv6 addresses
- TLS hostnames for DNS-over-TLS
- DNS-over-HTTP/3 endpoints
- Official websites and features

**Included Services**: NextDNS, Cloudflare, Google, Quad9, AdGuard, OpenDNS, CleanBrowsing

## Backup System

### Automatic Backups
- Created before any configuration changes
- Stored in `~/.setup-dns-backups/` (user-accessible)
- Named based on configuration (e.g., `QUAD9-20240101-120000.backup`)

### Backup Contents
- `/etc/systemd/resolved.conf`
- `/etc/resolv.conf`
- `/etc/NetworkManager/NetworkManager.conf`
- `~/.bashrc`

## Safety Features

- **No destructive actions without confirmation**
- **Comprehensive backups before changes**
- **Dry-run mode for testing**
- **Error checking at every step**
- **Automatic service restarts with verification**


## Requirements
- Linux with systemd and systemd-resolved
- Root/sudo privileges
- NetworkManager (optional, for NetworkManager integration)


## Quick Start

### Direct Download & Install
```bash
# Download the script
curl -L -o setup-dns.sh https://raw.githubusercontent.com/MPHONlC/NextDNS-Systemd-Setup-Script/main/setup-dns.sh

### Git Clone 
git clone https://github.com/MPHONlC/NextDNS-Systemd-Setup-Script.git
cd NextDNS-Systemd-Setup-Script
sudo ./setup-dns.sh

# Make executable and run
chmod +x setup-dns.sh
sudo ./setup-dns.sh

### Dry Run (Test Mode)
sudo ./setup-dns.sh --dry-run
```

## Support

If this project has been useful to you, consider supporting its development:

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/aph0nlc)

## Attribution

This script is released for free public use. If you modify or distribute this script:

**Please include attribution to the original author.**

Example attribution in modified scripts:
```bash
# Based on NextDNS Systemd-Resolved Setup Script by [APHONlC]
# Original: https://github.com/MPHONlC/NextDNS-Systemd-Setup-Script
```

---

*Note: This script is designed for technical users. Always review scripts before running them with sudo privileges.*
