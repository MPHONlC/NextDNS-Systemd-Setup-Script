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

## Quick Start

### Direct Download & Install
```bash
# Download the script
curl -L -o setup-dns.sh https://raw.githubusercontent.com/MPHONlC/NextDNS-Systemd-Setup-Script/main/setup-dns.sh

### Git Clone 
git clone https://github.com/MPHONlC/NextDNS-Systemd-Setup-Script.git
cd nextdns-systemd-setup
sudo ./setup-dns.sh

# Make executable and run
chmod +x setup-dns.sh
sudo ./setup-dns.sh

### Dry Run (Test Mode)
sudo ./setup-dns.sh --dry-run
