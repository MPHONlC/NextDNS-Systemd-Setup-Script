#!/bin/bash
# save as: setup-dns.sh
# sudo chmod +x setup-dns.sh
# sudo ./setup-dns.sh
# sudo ./setup-dns.sh --dry-run  # For testing without making changes
# check-dns-service
# First-time install script for NextDNS with systemd-resolved

set -e

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Define print functions BEFORE they are used
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Dry-run mode flag
DRY_RUN=false

# Check for --dry-run flag
for arg in "$@"; do
    if [[ "$arg" == "--dry-run" ]]; then
        DRY_RUN=true
        print_info "Dry-run mode enabled. No changes will be made to the system."
    fi
done

# Dry-run wrapper for system commands
dry_run_command() {
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would execute: $*"
        return 0
    else
        "$@"
    fi
}

# Progress indicator functions
show_progress() {
    local current=$1
    local total=$2
    local message=$3
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    
    printf "\r${BLUE}[PROGRESS]${NC} ${message} ["
    printf "%${filled}s" "" | tr ' ' '█'
    printf "%${empty}s" "" | tr ' ' '░'
    printf "] %3d%%" "$percentage"
    
    if [[ $current -eq $total ]]; then
        printf "\n"
    fi
}

# Function to check DNS-over-HTTP/3 with curl (if available)
check_doh3_service() {
    local ip="$1"
    local timeout=3
    
    # Only check if curl is available and not in dry-run mode
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would check DNS-over-HTTP/3 for: $ip"
        return 0
    fi
    
    if command -v curl >/dev/null 2>&1; then
        # Try common DNS-over-HTTP/3 endpoints
        local doh_endpoints=(
            "https://$ip/dns-query"
            "https://cloudflare-dns.com/dns-query"
            "https://dns.google/dns-query"
            "https://dns.quad9.net/dns-query"
        )
        
        for endpoint in "${doh_endpoints[@]}"; do
            # Try with HTTP/3 if curl supports it
            if curl --http3 --max-time $timeout -s -H "accept: application/dns-json" \
                "$endpoint?name=google.com&type=A" 2>/dev/null | grep -q "Answer"; then
                print_info "✓ DNS-over-HTTP/3 supported at: $endpoint"
                return 0
            fi
        done
    fi
    
    return 1
}

# Clear screen
clear

if [[ "$DRY_RUN" == true ]]; then
    print_info "==========================================="
    print_info "   NEXTDNS SYSTEMD-RESOLVED SETUP - DRY RUN"
    print_info "==========================================="
else
    print_info "==========================================="
    print_info "   NEXTDNS SYSTEMD-RESOLVED SETUP"
    print_info "==========================================="
fi
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root!"
    print_info "Please run: sudo $0"
    exit 1
fi

# ============================================
# DNS Service Database
# ============================================

# Database of known DNS services with their IPv4, IPv6, TLS, and DOH3 configurations
declare -A DNS_SERVICES=(
    # Quad9
    ["9.9.9.9:ipv4"]="9.9.9.9"
    ["9.9.9.9:ipv6"]="2620:fe::fe"
    ["9.9.9.9:tls"]="dns.quad9.net"
    ["9.9.9.9:doh3"]="https://dns.quad9.net/dns-query"
    ["9.9.9.9:name"]="Quad9 DNS"
    ["9.9.9.9:url"]="https://www.quad9.net"
    
    ["149.112.112.112:ipv4"]="149.112.112.112"
    ["149.112.112.112:ipv6"]="2620:fe::9"
    ["149.112.112.112:tls"]="dns.quad9.net"
    ["149.112.112.112:doh3"]="https://dns.quad9.net/dns-query"
    ["149.112.112.112:name"]="Quad9 Secondary"
    ["149.112.112.112:url"]="https://www.quad9.net"
    
    # Cloudflare
    ["1.1.1.1:ipv4"]="1.1.1.1"
    ["1.1.1.1:ipv6"]="2606:4700:4700::1111"
    ["1.1.1.1:tls"]="1dot1dot1dot1.cloudflare-dns.com"
    ["1.1.1.1:doh3"]="https://cloudflare-dns.com/dns-query"
    ["1.1.1.1:name"]="Cloudflare DNS"
    ["1.1.1.1:url"]="https://1.1.1.1"
    
    ["1.0.0.1:ipv4"]="1.0.0.1"
    ["1.0.0.1:ipv6"]="2606:4700:4700::1001"
    ["1.0.0.1:tls"]="1dot1dot1dot1.cloudflare-dns.com"
    ["1.0.0.1:doh3"]="https://cloudflare-dns.com/dns-query"
    ["1.0.0.1:name"]="Cloudflare Secondary"
    ["1.0.0.1:url"]="https://1.1.1.1"]
    
    # Google
    ["8.8.8.8:ipv4"]="8.8.8.8"
    ["8.8.8.8:ipv6"]="2001:4860:4860::8888"
    ["8.8.8.8:tls"]="dns.google"
    ["8.8.8.8:doh3"]="https://dns.google/dns-query"
    ["8.8.8.8:name"]="Google DNS"
    ["8.8.8.8:url"]="https://developers.google.com/speed/public-dns"
    
    ["8.8.4.4:ipv4"]="8.8.4.4"
    ["8.8.4.4:ipv6"]="2001:4860:4860::8844"
    ["8.8.4.4:tls"]="dns.google"
    ["8.8.4.4:doh3"]="https://dns.google/dns-query"
    ["8.8.4.4:name"]="Google Secondary"
    ["8.8.4.4:url"]="https://developers.google.com/speed/public-dns"
    
    # AdGuard
    ["94.140.14.14:ipv4"]="94.140.14.14"
    ["94.140.14.14:ipv6"]="2a10:50c0::ad1:ff"
    ["94.140.14.14:tls"]="dns.adguard.com"
    ["94.140.14.14:doh3"]="https://dns.adguard.com/dns-query"
    ["94.140.14.14:name"]="AdGuard DNS"
    ["94.140.14.14:url"]="https://adguard-dns.io"
    
    ["94.140.15.15:ipv4"]="94.140.15.15"
    ["94.140.15.15:ipv6"]="2a10:50c0::ad2:ff"
    ["94.140.15.15:tls"]="dns.adguard.com"
    ["94.140.15.15:doh3"]="https://dns.adguard.com/dns-query"
    ["94.140.15.15:name"]="AdGuard Secondary"
    ["94.140.15.15:url"]="https://adguard-dns.io"
    
    # OpenDNS
    ["208.67.222.222:ipv4"]="208.67.222.222"
    ["208.67.222.222:ipv6"]="2620:119:35::35"
    ["208.67.222.222:tls"]="dns.opendns.com"
    ["208.67.222.222:doh3"]=""
    ["208.67.222.222:name"]="OpenDNS"
    ["208.67.222.222:url"]="https://www.opendns.com"
    
    ["208.67.220.220:ipv4"]="208.67.220.220"
    ["208.67.220.220:ipv6"]="2620:119:53::53"
    ["208.67.220.220:tls"]="dns.opendns.com"
    ["208.67.220.220:doh3"]=""
    ["208.67.220.220:name"]="OpenDNS Secondary"
    ["208.67.220.220:url"]="https://www.opendns.com"
    
    # CleanBrowsing
    ["185.228.168.9:ipv4"]="185.228.168.9"
    ["185.228.168.9:ipv6"]="2a0d:2a00:1::"
    ["185.228.168.9:tls"]="security-filter-dns.cleanbrowsing.org"
    ["185.228.168.9:doh3"]="https://doh.cleanbrowsing.org/doh/security-filter/"
    ["185.228.168.9:name"]="CleanBrowsing Security"
    ["185.228.168.9:url"]="https://cleanbrowsing.org"
    
    # NextDNS (for reference)
    ["45.90.28.0:ipv4"]="45.90.28.0"
    ["45.90.28.0:ipv6"]="2a07:a8c0::"
    ["45.90.28.0:tls"]="dns.nextdns.io"
    ["45.90.28.0:doh3"]="https://dns.nextdns.io/dns-query"
    ["45.90.28.0:name"]="NextDNS Primary"
    ["45.90.28.0:url"]="https://my.nextdns.io"
    
    ["45.90.30.0:ipv4"]="45.90.30.0"
    ["45.90.30.0:ipv6"]="2a07:a8c1::"
    ["45.90.30.0:tls"]="dns.nextdns.io"
    ["45.90.30.0:doh3"]="https://dns.nextdns.io/dns-query"
    ["45.90.30.0:name"]="NextDNS Secondary"
    ["45.90.30.0:url"]="https://my.nextdns.io"
    
    # Direct IPv6 entries for easier lookup
    ["2620:fe::fe:name"]="Quad9 DNS"
    ["2620:fe::fe:url"]="https://www.quad9.net"
    ["2620:fe::fe:tls"]="dns.quad9.net"
    ["2620:fe::fe:doh3"]="https://dns.quad9.net/dns-query"
    
    ["2620:fe::9:name"]="Quad9 Secondary"
    ["2620:fe::9:url"]="https://www.quad9.net"
    ["2620:fe::9:tls"]="dns.quad9.net"
    ["2620:fe::9:doh3"]="https://dns.quad9.net/dns-query"
    
    ["2606:4700:4700::1111:name"]="Cloudflare DNS"
    ["2606:4700:4700::1111:url"]="https://1.1.1.1"
    ["2606:4700:4700::1111:tls"]="1dot1dot1dot1.cloudflare-dns.com"
    ["2606:4700:4700::1111:doh3"]="https://cloudflare-dns.com/dns-query"
    
    ["2606:4700:4700::1001:name"]="Cloudflare Secondary"
    ["2606:4700:4700::1001:url"]="https://1.1.1.1"
    ["2606:4700:4700::1001:tls"]="1dot1dot1dot1.cloudflare-dns.com"
    ["2606:4700:4700::1001:doh3"]="https://cloudflare-dns.com/dns-query"
    
    ["2001:4860:4860::8888:name"]="Google DNS"
    ["2001:4860:4860::8888:url"]="https://developers.google.com/speed/public-dns"
    ["2001:4860:4860::8888:tls"]="dns.google"
    ["2001:4860:4860::8888:doh3"]="https://dns.google/dns-query"
    
    ["2001:4860:4860::8844:name"]="Google Secondary"
    ["2001:4860:4860::8844:url"]="https://developers.google.com/speed/public-dns"
    ["2001:4860:4860::8844:tls"]="dns.google"
    ["2001:4860:4860::8844:doh3"]="https://dns.google/dns-query"
    
    ["2a10:50c0::ad1:ff:name"]="AdGuard DNS"
    ["2a10:50c0::ad1:ff:url"]="https://adguard-dns.io"
    ["2a10:50c0::ad1:ff:tls"]="dns.adguard.com"
    ["2a10:50c0::ad1:ff:doh3"]="https://dns.adguard.com/dns-query"
    
    ["2a10:50c0::ad2:ff:name"]="AdGuard Secondary"
    ["2a10:50c0::ad2:ff:url"]="https://adguard-dns.io"
    ["2a10:50c0::ad2:ff:tls"]="dns.adguard.com"
    ["2a10:50c0::ad2:ff:doh3"]="https://dns.adguard.com/dns-query"
    
    ["2620:119:35::35:name"]="OpenDNS"
    ["2620:119:35::35:url"]="https://www.opendns.com"
    ["2620:119:35::35:tls"]="dns.opendns.com"
    
    ["2620:119:53::53:name"]="OpenDNS Secondary"
    ["2620:119:53::53:url"]="https://www.opendns.com"
    ["2620:119:53::53:tls"]="dns.opendns.com"
    
    ["2a0d:2a00:1:::name"]="CleanBrowsing Security"
    ["2a0d:2a00:1:::url"]="https://cleanbrowsing.org"
    ["2a0d:2a00:1:::tls"]="security-filter-dns.cleanbrowsing.org"
    ["2a0d:2a00:1:::doh3"]="https://doh.cleanbrowsing.org/doh/security-filter/"
    
    ["2a07:a8c0:::name"]="NextDNS Primary"
    ["2a07:a8c0:::url"]="https://my.nextdns.io"
    ["2a07:a8c0:::tls"]="dns.nextdns.io"
    ["2a07:a8c0:::doh3"]="https://dns.nextdns.io/dns-query"
    
    ["2a07:a8c1:::name"]="NextDNS Secondary"
    ["2a07:a8c1:::url"]="https://my.nextdns.io"
    ["2a07:a8c1:::tls"]="dns.nextdns.io"
    ["2a07:a8c1:::doh3"]="https://dns.nextdns.io/dns-query"
)

# Function to check if DNS service exists
check_dns_service() {
    local ip="$1"
    local timeout=2
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would check DNS service: $ip"
        return 0
    fi
    
    # Try multiple methods, starting with the most reliable
    if command -v nslookup >/dev/null 2>&1; then
        # Use nslookup
        if timeout $timeout nslookup -type=A google.com $ip >/dev/null 2>&1; then
            return 0
        fi
    elif command -v host >/dev/null 2>&1; then
        # Use host command
        if timeout $timeout host google.com $ip >/dev/null 2>&1; then
            return 0
        fi
    elif command -v getent >/dev/null 2>&1; then
        # Use getent hosts through the DNS server
        if DNS_SERVER=$ip timeout $timeout getent hosts google.com >/dev/null 2>&1; then
            return 0
        fi
    else
        # Last resort: try direct TCP connection to port 53
        if timeout $timeout bash -c "echo -n 'query' > /dev/tcp/$ip/53" 2>/dev/null; then
            return 0
        fi
    fi
    
    return 1  # Service doesn't respond
}

# Function to bulk check DNS services with progress indicator
bulk_check_dns_services() {
    local servers=("$@")
    local total=${#servers[@]}
    local current=0
    
    if [[ $total -eq 0 ]]; then
        return
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would check $total DNS services"
        return
    fi
    
    print_info "Checking $total DNS services for responsiveness..."
    
    for server in "${servers[@]}"; do
        ((current++))
        show_progress "$current" "$total" "Testing DNS service: $server"
        
        if check_dns_service "$server"; then
            # Also check for DNS-over-HTTP/3 if available
            check_doh3_service "$server" &
        fi
    done
    
    echo ""
    print_success "✓ DNS service check completed"
}

# Function to determine backup name based on DNS configuration
get_backup_name() {
    local nextdns_id="$1"
    local fallback_servers=("${!2}")
    
    # Default to NextDNS
    local base_name="NextDNS-${nextdns_id}"
    
    if [ ${#fallback_servers[@]} -eq 0 ]; then
        # No fallback, just NextDNS
        echo "NextDNS-${nextdns_id}"
        return
    fi
    
    # Check if any fallback servers are from known providers
    for server in "${fallback_servers[@]}"; do
        # Get service name from DNS_SERVICES database
        local service_name="${DNS_SERVICES[$server:name]}"
        
        if [[ -n "$service_name" ]]; then
            # Clean the service name for filename
            local clean_name=$(echo "$service_name" | sed 's/DNS//g' | sed 's/Security//g' | xargs | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
            
            case "$clean_name" in
                *quad9*|*9.9.9.9*)
                    echo "QUAD9"
                    return
                    ;;
                *cloudflare*|*1.1.1.1*)
                    echo "CLOUDFLARE"
                    return
                    ;;
                *google*|*8.8.8.8*)
                    echo "GOOGLE"
                    return
                    ;;
                *adguard*|*94.140*)
                    echo "ADGUARD"
                    return
                    ;;
                *opendns*|*208.67*)
                    echo "OPENDNS"
                    return
                    ;;
                *cleanbrowsing*|*185.228*)
                    echo "CLEANBROWSING"
                    return
                    ;;
                *)
                    # Use the first known fallback service
                    if [[ -n "$clean_name" ]]; then
                        echo "${clean_name^^}"
                        return
                    fi
                    ;;
            esac
        fi
    done
    
    # If we get here, use generic name
    echo "${base_name}-with-fallback"
}

# Function to get DNS service info (works for both IPv4 and IPv6)
get_dns_service_info() {
    local ip="$1"
    
    # First check if it's a direct match in our database
    if [[ -n "${DNS_SERVICES[$ip:name]}" ]]; then
        echo "${DNS_SERVICES[$ip:name]}"
        return 0
    fi
    
    # Check if it's an IPv6 address that corresponds to a known IPv4 service
    for key in "${!DNS_SERVICES[@]}"; do
        if [[ "$key" == *":ipv6" && "${DNS_SERVICES[$key]}" == "$ip" ]]; then
            # Extract the base IPv4 address from the key
            base_ip="${key%:ipv6}"
            if [[ -n "${DNS_SERVICES[$base_ip:name]}" ]]; then
                echo "${DNS_SERVICES[$base_ip:name]}"
                return 0
            fi
        fi
    done
    
    # Try to detect unknown DNS service
    if check_dns_service "$ip"; then
        echo "Unknown DNS Service"
        return 0
    else
        echo ""
        return 1
    fi
}

# Function to get IPv6 for a known IPv4
get_ipv6_for_ip() {
    local ip="$1"
    
    if [[ -n "${DNS_SERVICES[$ip:ipv6]}" ]]; then
        echo "${DNS_SERVICES[$ip:ipv6]}"
        return 0
    fi
    
    # Also check if we're looking up an IPv6 address directly
    for key in "${!DNS_SERVICES[@]}"; do
        if [[ "$key" == *":ipv6" && "${DNS_SERVICES[$key]}" == "$ip" ]]; then
            # This is already an IPv6 address, return it
            echo "$ip"
            return 0
        fi
    done
    
    return 1
}

# Function to get TLS hostname for a known IP (works for both IPv4 and IPv6)
get_tls_for_ip() {
    local ip="$1"
    
    # First check if it's a direct match in our database
    if [[ -n "${DNS_SERVICES[$ip:tls]}" ]]; then
        echo "${DNS_SERVICES[$ip:tls]}"
        return 0
    fi
    
    # Check if it's an IPv6 address that corresponds to a known IPv4 service
    for key in "${!DNS_SERVICES[@]}"; do
        if [[ "$key" == *":ipv6" && "${DNS_SERVICES[$key]}" == "$ip" ]]; then
            # Extract the base IPv4 address from the key
            base_ip="${key%:ipv6}"
            if [[ -n "${DNS_SERVICES[$base_ip:tls]}" ]]; then
                echo "${DNS_SERVICES[$base_ip:tls]}"
                return 0
            fi
        fi
    done
    
    return 1
}

# Function to get DNS-over-HTTP/3 endpoint for a known IP (works for both IPv4 and IPv6)
get_doh3_for_ip() {
    local ip="$1"
    
    # First check if it's a direct match in our database
    if [[ -n "${DNS_SERVICES[$ip:doh3]}" ]]; then
        echo "${DNS_SERVICES[$ip:doh3]}"
        return 0
    fi
    
    # Check if it's an IPv6 address that corresponds to a known IPv4 service
    for key in "${!DNS_SERVICES[@]}"; do
        if [[ "$key" == *":ipv6" && "${DNS_SERVICES[$key]}" == "$ip" ]]; then
            # Extract the base IPv4 address from the key
            base_ip="${key%:ipv6}"
            if [[ -n "${DNS_SERVICES[$base_ip:doh3]}" ]]; then
                echo "${DNS_SERVICES[$base_ip:doh3]}"
                return 0
            fi
        fi
    done
    
    return 1
}

# Function to get website URL for a known IP (works for both IPv4 and IPv6)
get_url_for_ip() {
    local ip="$1"
    
    # First check if it's a direct match in our database
    if [[ -n "${DNS_SERVICES[$ip:url]}" ]]; then
        echo "${DNS_SERVICES[$ip:url]}"
        return 0
    fi
    
    # Check if it's an IPv6 address that corresponds to a known IPv4 service
    for key in "${!DNS_SERVICES[@]}"; do
        if [[ "$key" == *":ipv6" && "${DNS_SERVICES[$key]}" == "$ip" ]]; then
            # Extract the base IPv4 address from the key
            base_ip="${key%:ipv6}"
            if [[ -n "${DNS_SERVICES[$base_ip:url]}" ]]; then
                echo "${DNS_SERVICES[$base_ip:url]}"
                return 0
            fi
        fi
    done
    
    return 1
}

# Function to auto-detect TLS hostname from common patterns or internet
auto_detect_tls() {
    local ip="$1"
    
    # First try our database
    local tls_name=$(get_tls_for_ip "$ip")
    if [[ -n "$tls_name" ]]; then
        echo "$tls_name"
        return 0
    fi
    
    # Try common TLS hostname patterns for known services
    case "$ip" in
        9.9.9.9|149.112.112.112|2620:fe::fe|2620:fe::9)
            echo "dns.quad9.net"
            return 0
            ;;
        1.1.1.1|1.0.0.1|2606:4700:4700::1111|2606:4700:4700::1001)
            echo "1dot1dot1dot1.cloudflare-dns.com"
            return 0
            ;;
        8.8.8.8|8.8.4.4|2001:4860:4860::8888|2001:4860:4860::8844)
            echo "dns.google"
            return 0
            ;;
        94.140.14.14|94.140.15.15|2a10:50c0::ad1:ff|2a10:50c0::ad2:ff)
            echo "dns.adguard.com"
            return 0
            ;;
        208.67.222.222|208.67.220.220|2620:119:35::35|2620:119:53::53)
            echo "dns.opendns.com"
            return 0
            ;;
        185.228.168.9|2a0d:2a00:1::)
            echo "security-filter-dns.cleanbrowsing.org"
            return 0
            ;;
        45.90.28.0|45.90.30.0|2a07:a8c0::|2a07:a8c1::)
            echo "dns.nextdns.io"
            return 0
            ;;
    esac
    
    # If it's a known public DNS but not in our patterns, try reverse lookup
    if [[ "$DRY_RUN" != true ]] && command -v dig >/dev/null 2>&1; then
        print_info "Attempting to auto-detect TLS hostname for $ip..."
        
        # Try to get reverse DNS
        local reverse_dns=$(timeout 2 dig -x "$ip" +short 2>/dev/null | head -1)
        if [[ -n "$reverse_dns" ]]; then
            # Clean up the reverse DNS (remove trailing dot, convert to lowercase)
            reverse_dns=$(echo "$reverse_dns" | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')
            
            # Common reverse DNS patterns that often match TLS hostnames
            case "$reverse_dns" in
                *cloudflare*)
                    echo "1dot1dot1dot1.cloudflare-dns.com"
                    return 0
                    ;;
                *google*)
                    echo "dns.google"
                    return 0
                    ;;
                *quad9*)
                    echo "dns.quad9.net"
                    return 0
                    ;;
                *adguard*)
                    echo "dns.adguard.com"
                    return 0
                    ;;
                *opendns*)
                    echo "dns.opendns.com"
                    return 0
                    ;;
                *cleanbrowsing*)
                    echo "security-filter-dns.cleanbrowsing.org"
                    return 0
                    ;;
                *nextdns*)
                    echo "dns.nextdns.io"
                    return 0
                    ;;
                *)
                    # If reverse DNS looks like a valid hostname, suggest it
                    if [[ "$reverse_dns" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                        echo "$reverse_dns"
                        return 0
                    fi
                    ;;
            esac
        fi
    fi
    
    return 1
}

# ============================================
# Backup Restoration Section
# ============================================

# Define backup directories
OLD_BACKUP_DIR="/etc/systemd/resolved.backup"
USERNAME=$(logname 2>/dev/null || echo "$SUDO_USER" || echo "$USER")
HOSTNAME_=$(hostname | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
NEW_BACKUP_DIR="/home/${USERNAME}/.setup-dns-backups"

# Function to list backups
list_backups() {
    local dir="$1"
    local label="$2"
    
    if [[ -d "$dir" ]]; then
        echo "=== $label Backups ==="
        local backups=()
        while IFS= read -r -d $'\0' file; do
            backups+=("$file")
        done < <(find "$dir" -type f -name "*.backup" -print0 2>/dev/null)
        
        while IFS= read -r -d $'\0' file; do
            backups+=("$file")
        done < <(find "$dir" -type f -name "resolved.conf.*" -print0 2>/dev/null)
        
        while IFS= read -r -d $'\0' file; do
            backups+=("$file")
        done < <(find "$dir" -type f -name "resolv.conf.*" -print0 2>/dev/null)
        
        while IFS= read -r -d $'\0' file; do
            backups+=("$file")
        done < <(find "$dir" -type f -name "NetworkManager.conf.*" -print0 2>/dev/null)
        
        while IFS= read -r -d $'\0' file; do
            backups+=("$file")
        done < <(find "$dir" -type f -name "bashrc.*" -print0 2>/dev/null)
        
        if [[ ${#backups[@]} -eq 0 ]]; then
            echo "  No backups found"
        else
            # Sort backups by modification time (newest first)
            local sorted_backups=()
            while IFS= read -r -d $'\0' file; do
                sorted_backups+=("$file")
            done < <(printf '%s\0' "${backups[@]}" | sort -z -r -k1,1)
            
            for ((i=0; i<${#sorted_backups[@]}; i++)); do
                local file="${sorted_backups[$i]}"
                local filename=$(basename "$file")
                local size=$(du -h "$file" 2>/dev/null | cut -f1)
                local mtime=$(stat -c "%y" "$file" 2>/dev/null | cut -d'.' -f1)
                echo "  [$((i+1))] $filename ($size) - $mtime"
            done
        fi
        echo ""
    else
        echo "=== $label Backups ==="
        echo "  Directory not found: $dir"
        echo ""
    fi
}

# Function to restore backup
restore_backup() {
    local backup_file="$1"
    local filename=$(basename "$backup_file")
    
    print_info "Restoring backup: $filename"
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would restore backup: $backup_file"
        return
    fi
    
    case "$filename" in
        resolved.conf.*)
            cp "$backup_file" /etc/systemd/resolved.conf
            print_success "✓ Restored /etc/systemd/resolved.conf"
            ;;
        resolv.conf.*)
            cp "$backup_file" /etc/resolv.conf
            print_success "✓ Restored /etc/resolv.conf"
            ;;
        NetworkManager.conf.*)
            if [[ -f /etc/NetworkManager/NetworkManager.conf ]]; then
                cp "$backup_file" /etc/NetworkManager/NetworkManager.conf
                print_success "✓ Restored /etc/NetworkManager/NetworkManager.conf"
            fi
            ;;
        bashrc.*)
            if [[ -n "$SUDO_USER" ]]; then
                USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
                cp "$backup_file" "$USER_HOME/.bashrc"
                print_success "✓ Restored $USER_HOME/.bashrc"
            fi
            ;;
        *.backup)
            # This is a full backup, extract and restore
            TEMP_DIR=$(mktemp -d)
            tar -xzf "$backup_file" -C "$TEMP_DIR"
            
            if [[ -f "$TEMP_DIR/resolved.conf" ]]; then
                cp "$TEMP_DIR/resolved.conf" /etc/systemd/resolved.conf
                print_success "✓ Restored /etc/systemd/resolved.conf"
            fi
            
            if [[ -f "$TEMP_DIR/resolv.conf" ]]; then
                cp "$TEMP_DIR/resolv.conf" /etc/resolv.conf
                print_success "✓ Restored /etc/resolv.conf"
            fi
            
            if [[ -f "$TEMP_DIR/NetworkManager.conf" && -f /etc/NetworkManager/NetworkManager.conf ]]; then
                cp "$TEMP_DIR/NetworkManager.conf" /etc/NetworkManager/NetworkManager.conf
                print_success "✓ Restored /etc/NetworkManager/NetworkManager.conf"
            fi
            
            if [[ -f "$TEMP_DIR/bashrc" && -n "$SUDO_USER" ]]; then
                USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
                cp "$TEMP_DIR/bashrc" "$USER_HOME/.bashrc"
                print_success "✓ Restored $USER_HOME/.bashrc"
            fi
            
            rm -rf "$TEMP_DIR"
            ;;
    esac
}

# Function to create manual backup
create_manual_backup() {
    echo ""
    print_info "Creating manual backup..."
    
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would create manual backup"
        return
    fi
    
    # Ensure user backup directory exists
    mkdir -p "$NEW_BACKUP_DIR"
    
    # Ask for custom backup name with suggestions
    echo ""
    print_info "Suggested backup names based on configuration:"
    if [ ${#FALLBACK_DNS_SERVERS[@]} -eq 0 ]; then
        print_info "  • NextDNS-${NEXTDNS_ID} (NextDNS only) - https://my.nextdns.io"
    else
        for server in "${FALLBACK_DNS_SERVERS[@]}"; do
            service_name="${DNS_SERVICES[$server:name]}"
            service_url="${DNS_SERVICES[$server:url]}"
            if [[ -n "$service_name" ]]; then
                clean_name=$(echo "$service_name" | sed 's/DNS//g' | sed 's/Security//g' | xargs | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
                if [[ -n "$service_url" ]]; then
                    print_info "  • ${clean_name^^} (with NextDNS) - $service_url"
                else
                    print_info "  • ${clean_name^^} (with NextDNS)"
                fi
            fi
        done
    fi
    print_info "  • manual-backup (custom)"
    
    read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter custom backup name (or press Enter for auto-name): ")" BACKUP_NAME
    
    if [[ -z "$BACKUP_NAME" ]]; then
        # Auto-generate backup name
        BACKUP_NAME_PREFIX=$(get_backup_name "$NEXTDNS_ID" FALLBACK_DNS_SERVERS[@])
        BACKUP_NAME="$BACKUP_NAME_PREFIX"
    else
        # Clean the backup name
        BACKUP_NAME=$(echo "$BACKUP_NAME" | tr ' ' '-' | tr -cd '[:alnum:]-_')
        if [[ -z "$BACKUP_NAME" ]]; then
            BACKUP_NAME_PREFIX=$(get_backup_name "$NEXTDNS_ID" FALLBACK_DNS_SERVERS[@])
            BACKUP_NAME="$BACKUP_NAME_PREFIX"
            print_warning "Invalid name, using auto-name: $BACKUP_NAME"
        fi
    fi
    
    # Create timestamp
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    BACKUP_FILE="$NEW_BACKUP_DIR/${BACKUP_NAME}-${TIMESTAMP}.backup"
    
    # Create temporary directory for backup
    TEMP_BACKUP_DIR=$(mktemp -d)
    
    # Backup current configuration
    print_info "Backing up current configuration..."
    
    # Backup systemd-resolved configuration
    if [[ -f /etc/systemd/resolved.conf ]]; then
        cp /etc/systemd/resolved.conf "$TEMP_BACKUP_DIR/resolved.conf"
        print_info "  ✓ Backed up /etc/systemd/resolved.conf"
    fi
    
    # Backup resolv.conf
    if [[ -f /etc/resolv.conf ]]; then
        cp /etc/resolv.conf "$TEMP_BACKUP_DIR/resolv.conf"
        print_info "  ✓ Backed up /etc/resolv.conf"
    fi
    
    # Backup NetworkManager configuration
    if [[ -f /etc/NetworkManager/NetworkManager.conf ]]; then
        cp /etc/NetworkManager/NetworkManager.conf "$TEMP_BACKUP_DIR/NetworkManager.conf"
        print_info "  ✓ Backed up /etc/NetworkManager/NetworkManager.conf"
    fi
    
    # Backup .bashrc if available
    if [[ -n "$SUDO_USER" ]]; then
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        if [[ -f "$USER_HOME/.bashrc" ]]; then
            cp "$USER_HOME/.bashrc" "$TEMP_BACKUP_DIR/bashrc"
            print_info "  ✓ Backed up $USER_HOME/.bashrc"
        fi
    fi
    
    # Create backup archive
    tar -czf "$BACKUP_FILE" -C "$TEMP_BACKUP_DIR" .
    
    # Clean up
    rm -rf "$TEMP_BACKUP_DIR"
    
    # Show backup info
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    print_success "✓ Manual backup created: $(basename "$BACKUP_FILE") ($BACKUP_SIZE)"
    print_info "  Location: $NEW_BACKUP_DIR"
    
    echo ""
    print_info "Press Enter to continue..."
    read
    clear
}

# Function to show backup menu
show_backup_menu() {
    print_info "Found existing backups. Would you like to:"
    echo ""
    print_info "1. List all available backups"
    print_info "2. Restore from a backup"
    print_info "3. Delete a backup"
    print_info "4. Delete all backups"
    print_info "5. Create manual backup"
    print_info "6. Skip restore and continue with setup"
    echo ""
}

# Check for backups
BACKUPS_FOUND=false
BACKUP_FILES=()

print_info "Checking for existing backups..."
echo ""

# Collect all backup files
for dir in "$OLD_BACKUP_DIR" "$NEW_BACKUP_DIR"; do
    if [[ -d "$dir" ]]; then
        while IFS= read -r -d $'\0' file; do
            BACKUP_FILES+=("$file")
            BACKUPS_FOUND=true
        done < <(find "$dir" -type f \( -name "*.backup" -o -name "resolved.conf.*" -o -name "resolv.conf.*" -o -name "NetworkManager.conf.*" -o -name "bashrc.*" \) -print0 2>/dev/null)
    fi
done

# If backups found, offer restore options
if [[ "$BACKUPS_FOUND" == true ]]; then
    while true; do
        show_backup_menu
        
        read -p "$(echo -e "${BLUE}[INPUT]${NC} Choose an option (1-6): ")" BACKUP_OPTION
        
        case "$BACKUP_OPTION" in
            1)
                echo ""
                list_backups "$OLD_BACKUP_DIR" "System"
                list_backups "$NEW_BACKUP_DIR" "User"
                
                echo "Press Enter to continue..."
                read
                clear
                ;;
            2)
                echo ""
                print_info "Available backups:"
                echo ""
                
                # Show numbered list of backups
                ALL_BACKUPS=()
                for dir in "$OLD_BACKUP_DIR" "$NEW_BACKUP_DIR"; do
                    if [[ -d "$dir" ]]; then
                        while IFS= read -r -d $'\0' file; do
                            ALL_BACKUPS+=("$file")
                        done < <(find "$dir" -type f \( -name "*.backup" -o -name "resolved.conf.*" -o -name "resolv.conf.*" -o -name "NetworkManager.conf.*" -o -name "bashrc.*" \) -print0 2>/dev/null | sort -z -r)
                    fi
                done
                
                if [[ ${#ALL_BACKUPS[@]} -eq 0 ]]; then
                    print_error "No backups found!"
                    continue
                fi
                
                for ((i=0; i<${#ALL_BACKUPS[@]}; i++)); do
                    file="${ALL_BACKUPS[$i]}"
                    filename=$(basename "$file")
                    dirname=$(dirname "$file")
                    size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "?")
                    mtime=$(stat -c "%y" "$file" 2>/dev/null | cut -d'.' -f1 || echo "?")
                    echo "  [$((i+1))] $filename"
                    echo "      Location: $dirname"
                    echo "      Size: $size, Modified: $mtime"
                    echo ""
                done
                
                while true; do
                    read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter backup number to restore (or 0 to cancel): ")" BACKUP_NUM
                    
                    if [[ "$BACKUP_NUM" == "0" ]]; then
                        break
                    fi
                    
                    if [[ "$BACKUP_NUM" =~ ^[0-9]+$ ]] && [[ "$BACKUP_NUM" -ge 1 ]] && [[ "$BACKUP_NUM" -le ${#ALL_BACKUPS[@]} ]]; then
                        selected_backup="${ALL_BACKUPS[$((BACKUP_NUM-1))]}"
                        echo ""
                        print_warning "Restoring from: $(basename "$selected_backup")"
                        print_warning "This will overwrite current configuration!"
                        read -p "$(echo -e "${YELLOW}[CONFIRM]${NC} Are you sure? (y/N): ")" CONFIRM_RESTORE
                        
                        if [[ "$CONFIRM_RESTORE" =~ ^[Yy]$ ]]; then
                            restore_backup "$selected_backup"
                            print_success "✓ Backup restored successfully!"
                            print_info "Restarting services..."
                            dry_run_command systemctl restart systemd-resolved 2>/dev/null
                            if systemctl is-active NetworkManager >/dev/null 2>&1; then
                                dry_run_command systemctl restart NetworkManager 2>/dev/null
                            fi
                            print_success "✓ Services restarted"
                            echo ""
                            print_info "Exiting script. Your system has been restored from backup."
                            exit 0
                        else
                            print_info "Restore cancelled."
                            break
                        fi
                    else
                        print_error "Invalid backup number!"
                    fi
                done
                
                echo ""
                ;;
            3)
                echo ""
                print_info "Available backups to delete:"
                echo ""
                
                # Show numbered list of backups
                ALL_BACKUPS=()
                for dir in "$OLD_BACKUP_DIR" "$NEW_BACKUP_DIR"; do
                    if [[ -d "$dir" ]]; then
                        while IFS= read -r -d $'\0' file; do
                            ALL_BACKUPS+=("$file")
                        done < <(find "$dir" -type f \( -name "*.backup" -o -name "resolved.conf.*" -o -name "resolv.conf.*" -o -name "NetworkManager.conf.*" -o -name "bashrc.*" \) -print0 2>/dev/null | sort -z -r)
                    fi
                done
                
                if [[ ${#ALL_BACKUPS[@]} -eq 0 ]]; then
                    print_error "No backups found!"
                    continue
                fi
                
                for ((i=0; i<${#ALL_BACKUPS[@]}; i++)); do
                    file="${ALL_BACKUPS[$i]}"
                    filename=$(basename "$file")
                    dirname=$(dirname "$file")
                    size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "?")
                    mtime=$(stat -c "%y" "$file" 2>/dev/null | cut -d'.' -f1 || echo "?")
                    echo "  [$((i+1))] $filename"
                    echo "      Location: $dirname"
                    echo "      Size: $size, Modified: $mtime"
                    echo ""
                done
                
                while true; do
                    read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter backup number to delete (or 0 to cancel): ")" DELETE_NUM
                    
                    if [[ "$DELETE_NUM" == "0" ]]; then
                        break
                    fi
                    
                    if [[ "$DELETE_NUM" =~ ^[0-9]+$ ]] && [[ "$DELETE_NUM" -ge 1 ]] && [[ "$DELETE_NUM" -le ${#ALL_BACKUPS[@]} ]]; then
                        selected_backup="${ALL_BACKUPS[$((DELETE_NUM-1))]}"
                        echo ""
                        print_warning "Deleting: $(basename "$selected_backup")"
                        print_warning "This action cannot be undone!"
                        read -p "$(echo -e "${YELLOW}[CONFIRM]${NC} Are you sure? (y/N): ")" CONFIRM_DELETE
                        
                        if [[ "$CONFIRM_DELETE" =~ ^[Yy]$ ]]; then
                            if [[ "$DRY_RUN" == true ]]; then
                                print_info "[DRY-RUN] Would delete: $selected_backup"
                            else
                                rm -f "$selected_backup"
                                print_success "✓ Backup deleted successfully!"
                                
                                # Check if directory is empty and remove it
                                backup_dir=$(dirname "$selected_backup")
                                if [[ "$(find "$backup_dir" -type f | wc -l)" -eq 0 ]]; then
                                    rmdir "$backup_dir" 2>/dev/null && print_info "Removed empty backup directory"
                                fi
                            fi
                            
                            echo ""
                            print_info "Backup deleted. Returning to menu..."
                            sleep 2
                            clear
                            break
                        else
                            print_info "Delete cancelled."
                            break
                        fi
                    else
                        print_error "Invalid backup number!"
                    fi
                done
                ;;
            4)
                echo ""
                print_warning "=== DELETE ALL BACKUPS ==="
                print_warning "This will delete ALL backups from:"
                print_warning "  • $OLD_BACKUP_DIR"
                print_warning "  • $NEW_BACKUP_DIR"
                print_warning ""
                print_warning "This action cannot be undone!"
                echo ""
                
                read -p "$(echo -e "${YELLOW}[CONFIRM]${NC} Type 'DELETE-ALL' to confirm: ")" CONFIRM_DELETE_ALL
                
                if [[ "$CONFIRM_DELETE_ALL" == "DELETE-ALL" ]]; then
                    # Count files to be deleted
                    OLD_COUNT=$(find "$OLD_BACKUP_DIR" -type f \( -name "*.backup" -o -name "resolved.conf.*" -o -name "resolv.conf.*" -o -name "NetworkManager.conf.*" -o -name "bashrc.*" \) 2>/dev/null | wc -l)
                    NEW_COUNT=$(find "$NEW_BACKUP_DIR" -type f \( -name "*.backup" -o -name "resolved.conf.*" -o -name "resolv.conf.*" -o -name "NetworkManager.conf.*" -o -name "bashrc.*" \) 2>/dev/null | wc -l)
                    TOTAL_COUNT=$((OLD_COUNT + NEW_COUNT))
                    
                    if [[ $TOTAL_COUNT -eq 0 ]]; then
                        print_info "No backups found to delete."
                        continue
                    fi
                    
                    print_warning "This will delete $TOTAL_COUNT backup files!"
                    read -p "$(echo -e "${YELLOW}[FINAL CONFIRM]${NC} Are you ABSOLUTELY sure? (y/N): ")" FINAL_CONFIRM
                    
                    if [[ "$FINAL_CONFIRM" =~ ^[Yy]$ ]]; then
                        # Delete all backup files
                        if [[ $OLD_COUNT -gt 0 ]]; then
                            if [[ "$DRY_RUN" == true ]]; then
                                print_info "[DRY-RUN] Would delete $OLD_COUNT files from $OLD_BACKUP_DIR"
                            else
                                find "$OLD_BACKUP_DIR" -type f \( -name "*.backup" -o -name "resolved.conf.*" -o -name "resolv.conf.*" -o -name "NetworkManager.conf.*" -o -name "bashrc.*" \) -delete 2>/dev/null
                                print_info "Deleted $OLD_COUNT files from $OLD_BACKUP_DIR"
                            fi
                        fi
                        
                        if [[ $NEW_COUNT -gt 0 ]]; then
                            if [[ "$DRY_RUN" == true ]]; then
                                print_info "[DRY-RUN] Would delete $NEW_COUNT files from $NEW_BACKUP_DIR"
                            else
                                find "$NEW_BACKUP_DIR" -type f \( -name "*.backup" -o -name "resolved.conf.*" -o -name "resolv.conf.*" -o -name "NetworkManager.conf.*" -o -name "bashrc.*" \) -delete 2>/dev/null
                                print_info "Deleted $NEW_COUNT files from $NEW_BACKUP_DIR"
                            fi
                        fi
                        
                        if [[ "$DRY_RUN" != true ]]; then
                            # Remove empty directories
                            rmdir "$OLD_BACKUP_DIR" 2>/dev/null && print_info "Removed empty backup directory: $OLD_BACKUP_DIR"
                            rmdir "$NEW_BACKUP_DIR" 2>/dev/null && print_info "Removed empty backup directory: $NEW_BACKUP_DIR"
                        fi
                        
                        print_success "✓ All backups deleted successfully!"
                        print_info "Total files deleted: $TOTAL_COUNT"
                        
                        echo ""
                        print_info "Press Enter to continue..."
                        read
                        clear
                    else
                        print_info "Delete all cancelled."
                    fi
                else
                    print_error "Confirmation text incorrect. Delete all cancelled."
                fi
                ;;
            5)
                # Create manual backup
                create_manual_backup
                ;;
            6)
                print_info "Skipping restore. Continuing with setup..."
                echo ""
                break
                ;;
            *)
                print_error "Invalid option! Please enter 1, 2, 3, 4, 5, or 6."
                ;;
        esac
    done
else
    print_info "No existing backups found. Continuing with setup..."
    echo ""
fi

# ============================================
# Get user input for NextDNS configuration
# ============================================

# Prompt for NextDNS Profile ID
print_info "To find your NextDNS Profile ID:"
print_info "1. Log in to: https://my.nextdns.io/"
print_info "2. Under: Setup > Endpoints > ID"
print_info "3. Copy your Profile ID (like: 123a45)"
print_info "4. Paste it below"
echo ""

while true; do
    read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter your NextDNS Profile ID (example: 123a45): ")" NEXTDNS_ID
    NEXTDNS_ID=$(echo "$NEXTDNS_ID" | tr -d '[:space:]')
    
    if [[ -z "$NEXTDNS_ID" ]]; then
        print_error "Profile ID cannot be empty!"
        continue
    fi
    
    if [[ ! "$NEXTDNS_ID" =~ ^[a-zA-Z0-9]+$ ]]; then
        print_error "Profile ID should contain only letters and numbers!"
        continue
    fi
    
    print_info "✓ Profile ID set to: $NEXTDNS_ID"
    break
done

echo ""

# Get system hostname for default endpoint
HOSTNAME_CLEAN=$(hostname | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]-' | sed 's/-/--/g')
DEFAULT_ENDPOINT="${HOSTNAME_CLEAN}--TLS"

# Prompt for custom endpoint name with examples
print_info "Custom DNS endpoint naming (optional):"
print_info "Prepend a custom name to your DNS endpoints for easier identification in logs."
print_info ""
print_info "Example: For 'My Home Router', use: My--Home--Router"
print_info "This will create endpoints like:"
print_info "  IPv4: 45.90.28.0#My--Home--Router--Prime--IPv4-123a45.dns.nextdns.io"
print_info "  IPv6: 2a07:a8c0::#My--Home--Router--Prime--IPv6-123a45.dns.nextdns.io"
print_info ""
print_info "Only use letters, numbers, and hyphens. Use '--' for spaces."
print_info "Default (press Enter): $DEFAULT_ENDPOINT"
echo ""

read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter custom name (or press Enter for default): ")" CUSTOM_NAME

if [[ -z "$CUSTOM_NAME" ]]; then
    ENDPOINT_PREFIX="$DEFAULT_ENDPOINT"
    print_info "Using default endpoint: $ENDPOINT_PREFIX"
else
    CLEAN_NAME=$(echo "$CUSTOM_NAME" | sed 's/ /--/g' | tr -cd '[:alnum:]-')
    
    if [[ -z "$CLEAN_NAME" ]]; then
        print_error "Invalid name. Using default: $DEFAULT_ENDPOINT"
        ENDPOINT_PREFIX="$DEFAULT_ENDPOINT"
    else
        ENDPOINT_PREFIX="$CLEAN_NAME"
        print_info "✓ Custom endpoint prefix: $ENDPOINT_PREFIX"
    fi
fi

echo ""

# Build endpoint strings with new naming convention
ENDPOINT_IPV4_PRIME="${ENDPOINT_PREFIX}--Prime--IPv4-${NEXTDNS_ID}"
ENDPOINT_IPV4_ALT="${ENDPOINT_PREFIX}--Alt--IPv4-${NEXTDNS_ID}"
ENDPOINT_IPV6_PRIME="${ENDPOINT_PREFIX}--Prime--IPv6-${NEXTDNS_ID}"
ENDPOINT_IPV6_ALT="${ENDPOINT_PREFIX}--Alt--IPv6-${NEXTDNS_ID}"

print_info "Generated endpoints that will appear in your dashboard logs:"
print_info "  IPv4 Primary:   45.90.28.0#${ENDPOINT_IPV4_PRIME}.dns.nextdns.io"
print_info "  IPv4 Alternate: 45.90.30.0#${ENDPOINT_IPV4_ALT}.dns.nextdns.io"
print_info "  IPv6 Primary:   2a07:a8c0::#${ENDPOINT_IPV6_PRIME}.dns.nextdns.io"
print_info "  IPv6 Alternate: 2a07:a8c1::#${ENDPOINT_IPV6_ALT}.dns.nextdns.io"
echo ""

# ============================================
# Configure fallback DNS servers with auto-configuration
# ============================================
FALLBACK_DNS_LINES=()
FALLBACK_DNS_SERVERS=()
FALLBACK_TLS_MAP=()

print_info "Fallback DNS Configuration (Optional):"
print_info "Add backup DNS servers in case NextDNS is unavailable."
print_info "You can add multiple fallback DNS servers."
print_info "The script will try to auto-detect IPv6 and TLS configurations for known DNS services."
echo ""

ADD_MORE_FALLBACK=true
FALLBACK_COUNT=0

set +e

while [[ "$ADD_MORE_FALLBACK" == true ]]; do
    echo ""
    print_info "Available DNS services with their websites:"
    print_info "  • Quad9 (9.9.9.9)          - https://www.quad9.net"
    print_info "  • Cloudflare (1.1.1.1)     - https://1.1.1.1"
    print_info "  • Google (8.8.8.8)         - https://developers.google.com/speed/public-dns"
    print_info "  • AdGuard (94.140.14.14)   - https://adguard-dns.io"
    print_info "  • OpenDNS (208.67.222.222) - https://www.opendns.com"
    print_info "  • CleanBrowsing (185.228.168.9) - https://cleanbrowsing.org"
    echo ""
    
    read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter fallback DNS server ${FALLBACK_COUNT} (IPv4 or IPv6, or press Enter to skip/stop): ")" FALLBACK_DNS
    
    if [[ -z "$FALLBACK_DNS" ]]; then
        if [[ $FALLBACK_COUNT -eq 0 ]]; then
            print_info "No fallback DNS servers configured."
        else
            print_info "Finished adding fallback DNS servers. Total: $FALLBACK_COUNT"
        fi
        ADD_MORE_FALLBACK=false
        break
    fi
    
    # Check if the DNS service exists
    print_info "Checking DNS service: $FALLBACK_DNS"
    
    SERVICE_NAME=$(get_dns_service_info "$FALLBACK_DNS")
    
    if [[ -z "$SERVICE_NAME" ]]; then
        print_error "DNS service $FALLBACK_DNS does not respond or is unreachable!"
        
        # Check if it's a known service with URL
        SERVICE_URL=$(get_url_for_ip "$FALLBACK_DNS")
        if [[ -n "$SERVICE_URL" ]]; then
            print_info "ℹ This appears to be a known service. Check website: $SERVICE_URL"
        fi
        
        print_warning "You can still add it, but it may not work."
        read -p "$(echo -e "${YELLOW}[CONFIRM]${NC} Continue anyway? (y/N): ")" CONTINUE_ANYWAY
        if [[ ! "$CONTINUE_ANYWAY" =~ ^[Yy]$ ]]; then
            print_info "Skipping this fallback DNS server."
            continue
        else
            SERVICE_NAME="Custom DNS Service"
        fi
    else
        # Get and display URL if available
        SERVICE_URL=$(get_url_for_ip "$FALLBACK_DNS")
        if [[ -n "$SERVICE_URL" ]]; then
            print_info "✓ Detected: $SERVICE_NAME"
            print_info "  Website: $SERVICE_URL"
            
            # Show features if available
            case "$FALLBACK_DNS" in
                9.9.9.9|149.112.112.112)
                    print_info "  Features: Malware blocking, DNSSEC, no logging"
                    ;;
                1.1.1.1|1.0.0.1)
                    print_info "  Features: Fast, privacy-focused, DNSSEC"
                    ;;
                8.8.8.8|8.8.4.4)
                    print_info "  Features: Fast, reliable, DNSSEC"
                    ;;
                94.140.14.14|94.140.15.15)
                    print_info "  Features: Ad blocking, tracking protection"
                    ;;
                208.67.222.222|208.67.220.220)
                    print_info "  Features: Content filtering, phishing protection"
                    ;;
                185.228.168.9)
                    print_info "  Features: Family-safe, malware blocking"
                    ;;
            esac
        else
            print_info "✓ Detected: $SERVICE_NAME"
        fi
    fi
    
    # Auto-detect IPv6 if available
    AUTO_IPV6=""
    if [[ $FALLBACK_DNS =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # IPv4 address, try to get IPv6
        AUTO_IPV6=$(get_ipv6_for_ip "$FALLBACK_DNS")
        if [[ -n "$AUTO_IPV6" ]]; then
            print_info "✓ Auto-detected IPv6: $AUTO_IPV6"
        fi
    fi
    
    # Ask about IPv6
    if [[ -n "$AUTO_IPV6" ]]; then
        read -p "$(echo -e "${BLUE}[INPUT]${NC} Use auto-detected IPv6 $AUTO_IPV6 as secondary fallback? (Y/n): ")" USE_AUTO_IPV6
        if [[ "$USE_AUTO_IPV6" =~ ^[Yy]$ || "$USE_AUTO_IPV6" == "" ]]; then
            FALLBACK_IPV6="$AUTO_IPV6"
        else
            read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter custom IPv6 fallback DNS (or press Enter to skip): ")" FALLBACK_IPV6
        fi
    else
        read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter IPv6 fallback DNS (or press Enter to skip): ")" FALLBACK_IPV6
    fi
    
    # Auto-detect TLS if available using improved detection
    AUTO_TLS=$(auto_detect_tls "$FALLBACK_DNS")
    if [[ -n "$AUTO_TLS" ]]; then
        print_info "✓ Auto-detected TLS hostname: $AUTO_TLS"
        read -p "$(echo -e "${BLUE}[INPUT]${NC} Use auto-detected TLS hostname $AUTO_TLS? (Y/n): ")" USE_AUTO_TLS
        if [[ "$USE_AUTO_TLS" =~ ^[Yy]$ || "$USE_AUTO_TLS" == "" ]]; then
            TLS_HOSTNAME="$AUTO_TLS"
        else
            read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter TLS hostname for $FALLBACK_DNS (or press Enter to skip TLS): ")" TLS_HOSTNAME
        fi
    else
        read -p "$(echo -e "${BLUE}[INPUT]${NC} Does $FALLBACK_DNS support DNS-over-TLS? (y/N): ")" HAS_TLS
        if [[ "$HAS_TLS" =~ ^[Yy]$ ]]; then
            read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter TLS hostname for $FALLBACK_DNS: ")" TLS_HOSTNAME
        fi
    fi
    
    # Auto-detect DNS-over-HTTP/3 if available
    AUTO_DOH3=$(get_doh3_for_ip "$FALLBACK_DNS")
    if [[ -n "$AUTO_DOH3" ]]; then
        print_info "✓ Auto-detected DNS-over-HTTP/3 endpoint: $AUTO_DOH3"
        if command -v curl >/dev/null 2>&1; then
            read -p "$(echo -e "${BLUE}[INPUT]${NC} Test DNS-over-HTTP/3 support for $FALLBACK_DNS? (Y/n): ")" TEST_DOH3
            if [[ "$TEST_DOH3" =~ ^[Yy]$ || "$TEST_DOH3" == "" ]]; then
                print_info "Testing DNS-over-HTTP/3 support..."
                # Run test in foreground, not background
                if curl --http3 --max-time 3 -s -H "accept: application/dns-json" \
                    "$AUTO_DOH3?name=google.com&type=A" 2>/dev/null | grep -q "Answer"; then
                    print_success "✓ DNS-over-HTTP/3 supported!"
                else
                    print_info "✗ DNS-over-HTTP/3 not supported or test failed"
                fi
            fi
        fi
    fi
    
    # Add primary fallback DNS
    if [[ -n "$TLS_HOSTNAME" ]]; then
        FALLBACK_DNS_LINES+=("DNS=$FALLBACK_DNS#$TLS_HOSTNAME")
        FALLBACK_DNS_SERVERS+=("$FALLBACK_DNS")
        FALLBACK_TLS_MAP+=("$FALLBACK_DNS:$TLS_HOSTNAME")
        print_success "✓ Added fallback with TLS: $FALLBACK_DNS#$TLS_HOSTNAME"
    else
        FALLBACK_DNS_LINES+=("DNS=$FALLBACK_DNS")
        FALLBACK_DNS_SERVERS+=("$FALLBACK_DNS")
        print_success "✓ Added fallback (no TLS): $FALLBACK_DNS"
    fi
    ((FALLBACK_COUNT++))
    
    # Add IPv6 fallback if provided
    if [[ -n "$FALLBACK_IPV6" ]]; then
        # Check IPv6 service
        if check_dns_service "$FALLBACK_IPV6"; then
            print_info "✓ IPv6 DNS service is responsive"
            
            # Auto-detect TLS for IPv6 using the same method as IPv4
            AUTO_TLS6=$(auto_detect_tls "$FALLBACK_IPV6")
            if [[ -n "$AUTO_TLS6" ]]; then
                print_info "✓ Auto-detected TLS hostname for IPv6: $AUTO_TLS6"
                read -p "$(echo -e "${BLUE}[INPUT]${NC} Use auto-detected TLS hostname $AUTO_TLS6 for $FALLBACK_IPV6? (Y/n): ")" USE_TLS6
                if [[ "$USE_TLS6" =~ ^[Yy]$ || "$USE_TLS6" == "" ]]; then
                    TLS_HOSTNAME6="$AUTO_TLS6"
                else
                    read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter TLS hostname for $FALLBACK_IPV6 (or press Enter to skip TLS): ")" TLS_HOSTNAME6
                fi
            else
                # Fall back to the old method if auto-detection fails
                read -p "$(echo -e "${BLUE}[INPUT]${NC} Does $FALLBACK_IPV6 support DNS-over-TLS? (y/N): ")" HAS_TLS6
                if [[ "$HAS_TLS6" =~ ^[Yy]$ ]]; then
                    read -p "$(echo -e "${BLUE}[INPUT]${NC} Enter TLS hostname for $FALLBACK_IPV6: ")" TLS_HOSTNAME6
                fi
            fi
            
            if [[ -n "$TLS_HOSTNAME6" ]]; then
                FALLBACK_DNS_LINES+=("DNS=$FALLBACK_IPV6#$TLS_HOSTNAME6")
                FALLBACK_DNS_SERVERS+=("$FALLBACK_IPV6")
                FALLBACK_TLS_MAP+=("$FALLBACK_IPV6:$TLS_HOSTNAME6")
                print_success "✓ Added IPv6 fallback with TLS: $FALLBACK_IPV6#$TLS_HOSTNAME6"
            else
                FALLBACK_DNS_LINES+=("DNS=$FALLBACK_IPV6")
                FALLBACK_DNS_SERVERS+=("$FALLBACK_IPV6")
                print_success "✓ Added IPv6 fallback (no TLS): $FALLBACK_IPV6"
            fi
            ((FALLBACK_COUNT++))
        else
            print_warning "IPv6 DNS service $FALLBACK_IPV6 does not respond. Skipping."
        fi
    fi
    
    # Ask if user wants to add another fallback server
    echo ""
    read -p "$(echo -e "${BLUE}[INPUT]${NC} Do you want to add another fallback DNS server? (y/N): ")" ADD_ANOTHER
    
    if [[ ! "$ADD_ANOTHER" =~ ^[Yy]$ ]]; then
        ADD_MORE_FALLBACK=false
        print_info "Finished adding fallback DNS servers. Total: $FALLBACK_COUNT"
    fi
done

# Re-enable set -e after the fallback DNS loop
set -e

echo ""

# Create backup with timestamp
BACKUP_DIR="/etc/systemd/resolved.backup"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

print_info "Creating backups..."
if [[ -f /etc/systemd/resolved.conf ]]; then
    dry_run_command cp /etc/systemd/resolved.conf "$BACKUP_DIR/resolved.conf.$TIMESTAMP"
    print_info "Backed up /etc/systemd/resolved.conf"
fi

if [[ -f /etc/resolv.conf ]]; then
    dry_run_command cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf.$TIMESTAMP"
    print_info "Backed up /etc/resolv.conf"
fi

print_info ""
print_info "Configuring systemd-resolved with NextDNS profile..."
echo ""

# ============================================
# Step 1: Configure /etc/systemd/resolved.conf
# ============================================
print_info "Creating /etc/systemd/resolved.conf..."

# Build the resolved.conf content
RESOLVED_CONF_CONTENT="[Resolve]
# NextDNS Configuration with Profile Names
# Profile: ${ENDPOINT_PREFIX} ($NEXTDNS_ID)

# IPv4 DNS Servers with NextDNS profile names
DNS=45.90.28.0#${ENDPOINT_IPV4_PRIME}.dns.nextdns.io
DNS=45.90.30.0#${ENDPOINT_IPV4_ALT}.dns.nextdns.io

# IPv6 DNS Servers with NextDNS profile names
DNS=2a07:a8c0::#${ENDPOINT_IPV6_PRIME}.dns.nextdns.io
DNS=2a07:a8c1::#${ENDPOINT_IPV6_ALT}.dns.nextdns.io"

# Add fallback DNS servers if any
if [ ${#FALLBACK_DNS_LINES[@]} -ne 0 ]; then
    RESOLVED_CONF_CONTENT="$RESOLVED_CONF_CONTENT

# Fallback DNS servers"
    for line in "${FALLBACK_DNS_LINES[@]}"; do
        RESOLVED_CONF_CONTENT="$RESOLVED_CONF_CONTENT
$line"
    done
fi

# Add the rest of the configuration
RESOLVED_CONF_CONTENT="$RESOLVED_CONF_CONTENT

# DNS-over-TLS (Encrypts all DNS queries)
DNSOverTLS=yes

# DNSSEC Validation
DNSSEC=allow-downgrade

# Disable stub listener - systemd-resolved will listen on port 53 directly
DNSStubListener=no

# Performance Settings
Cache=yes
DNSStubListenerExtra=127.0.0.53

# Security Settings
LLMNR=no
MulticastDNS=no
ReadEtcHosts=yes"

if [[ "$DRY_RUN" == true ]]; then
    print_info "[DRY-RUN] Would create /etc/systemd/resolved.conf with content:"
    echo "==========================================="
    echo "$RESOLVED_CONF_CONTENT"
    echo "==========================================="
else
    echo "$RESOLVED_CONF_CONTENT" > /etc/systemd/resolved.conf
    print_success "✓ systemd-resolved configured with NextDNS profile names"
fi

# ============================================
# Step 2: Configure /etc/resolv.conf to point to systemd-resolved
# ============================================
print_info "Configuring /etc/resolv.conf..."

if [[ "$DRY_RUN" == true ]]; then
    print_info "[DRY-RUN] Would remove existing /etc/resolv.conf"
    print_info "[DRY-RUN] Would create /etc/resolv.conf pointing to 127.0.0.53"
else
    # Remove any existing resolv.conf symlink or file
    rm -f /etc/resolv.conf
    
    # Create resolv.conf pointing to systemd-resolved
    cat > /etc/resolv.conf << EOF
# /etc/resolv.conf
# Managed by systemd-resolved
# NextDNS Profile: ${ENDPOINT_PREFIX} ($NEXTDNS_ID)

# Point to systemd-resolved which is listening on port 53
nameserver 127.0.0.53
options edns0
search .
EOF
    
    print_success "✓ /etc/resolv.conf points to 127.0.0.53 (systemd-resolved)"
fi

# ============================================
# Step 3: Configure NetworkManager to not interfere
# ============================================
print_info "Configuring NetworkManager..."

if command -v nmcli >/dev/null 2>&1; then
    print_info "Found NetworkManager, configuring it..."
    
    # Backup NetworkManager config
    if [[ -f /etc/NetworkManager/NetworkManager.conf ]]; then
        dry_run_command cp /etc/NetworkManager/NetworkManager.conf "$BACKUP_DIR/NetworkManager.conf.$TIMESTAMP"
    fi
    
    # Configure NetworkManager to not manage resolv.conf
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would add 'dns=none' to NetworkManager.conf"
        print_info "[DRY-RUN] Would clear DNS from all NetworkManager connections"
    else
        if ! grep -q "dns=none" /etc/NetworkManager/NetworkManager.conf; then
            if grep -q "^\[main\]" /etc/NetworkManager/NetworkManager.conf; then
                sed -i '/^\[main\]/a dns=none' /etc/NetworkManager/NetworkManager.conf
            else
                echo -e "[main]\ndns=none" >> /etc/NetworkManager/NetworkManager.conf
            fi
            print_info "NetworkManager configured with dns=none"
        fi
        
        # Remove DNS settings from ALL connections
        print_info "Clearing DNS from all NetworkManager connections..."
        for CONNECTION in $(nmcli -t -f NAME connection show); do
            nmcli connection modify "$CONNECTION" ipv4.dns "" 2>/dev/null || true
            nmcli connection modify "$CONNECTION" ipv6.dns "" 2>/dev/null || true
            nmcli connection modify "$CONNECTION" ipv4.ignore-auto-dns yes 2>/dev/null || true
            nmcli connection modify "$CONNECTION" ipv6.ignore-auto-dns yes 2>/dev/null || true
        done
    fi
else
    print_warning "NetworkManager not found, skipping configuration"
fi

print_success "✓ NetworkManager configured to not interfere"

# ============================================
# Step 4: Restart services
# ============================================
print_info "Restarting services..."

# Restart systemd-resolved
if [[ "$DRY_RUN" == true ]]; then
    print_info "[DRY-RUN] Would restart systemd-resolved"
    print_info "[DRY-RUN] Would enable systemd-resolved"
else
    systemctl restart systemd-resolved
    systemctl enable systemd-resolved --now >/dev/null 2>&1
    print_info "systemd-resolved restarted and enabled"
fi

# Restart NetworkManager if it exists
if systemctl is-active NetworkManager >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY-RUN] Would restart NetworkManager"
        print_info "[DRY-RUN] Would reconnect network connections"
    else
        systemctl restart NetworkManager
        print_info "NetworkManager restarted"
        
        # Reconnect network connections
        sleep 2
        for CONNECTION in $(nmcli -t -f NAME connection show --active); do
            nmcli connection down "$CONNECTION" 2>/dev/null || true
            sleep 1
            nmcli connection up "$CONNECTION" 2>/dev/null || true
        done
    fi
fi

if [[ "$DRY_RUN" != true ]]; then
    print_success "✓ DNS-over-TLS enabled for encryption"
    if [ ${#FALLBACK_DNS_SERVERS[@]} -eq 0 ]; then
        print_success "✓ No fallback DNS servers configured (NextDNS only)"
    else
        print_success "✓ Fallback DNS servers configured: ${FALLBACK_DNS_SERVERS[*]}"
    fi
fi

# ============================================
# Step 5: Create clean .bashrc with DNS utilities
# ============================================
print_info ""
print_info "Setting up DNS utilities..."

# Get user's home directory
if [[ -n "$SUDO_USER" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME="$HOME"
fi

# Backup current .bashrc
if [[ -f "$USER_HOME/.bashrc" ]]; then
    dry_run_command cp "$USER_HOME/.bashrc" "$BACKUP_DIR/bashrc.$TIMESTAMP"
    print_info "Backed up existing .bashrc"
fi

# Save fallback servers for use in bashrc
FALLBACK_SERVERS_FILE="$USER_HOME/.nextdns_fallback_servers"
if [[ "$DRY_RUN" != true ]]; then
    > "$FALLBACK_SERVERS_FILE"
    for server in "${FALLBACK_DNS_SERVERS[@]}"; do
        echo "$server" >> "$FALLBACK_SERVERS_FILE"
    done
fi

# Save TLS map for fallback servers
FALLBACK_TLS_FILE="$USER_HOME/.nextdns_fallback_tls"
if [[ "$DRY_RUN" != true ]]; then
    > "$FALLBACK_TLS_FILE"
    for tls_entry in "${FALLBACK_TLS_MAP[@]}"; do
        echo "$tls_entry" >> "$FALLBACK_TLS_FILE"
    done
fi

# Save DNS service names and URLs for fallback servers
SERVICE_NAMES_FILE="$USER_HOME/.dns_service_names"
if [[ "$DRY_RUN" != true ]]; then
    > "$SERVICE_NAMES_FILE"
    for server in "${FALLBACK_DNS_SERVERS[@]}"; do
        service_name="${DNS_SERVICES[$server:name]}"
        service_url="${DNS_SERVICES[$server:url]}"
        if [[ -n "$service_name" ]]; then
            if [[ -n "$service_url" ]]; then
                echo "$server:$service_name:$service_url" >> "$SERVICE_NAMES_FILE"
            else
                echo "$server:$service_name" >> "$SERVICE_NAMES_FILE"
            fi
        fi
    done
fi

# Also create a user backup directory
USER_BACKUP_DIR="/home/${USERNAME}/.setup-dns-backups"
if [[ "$DRY_RUN" != true ]]; then
    mkdir -p "$USER_BACKUP_DIR"
    # Fix ownership so user can write to it
    if [[ -n "$USERNAME" ]]; then
        chown -R "$USERNAME:$USERNAME" "$USER_BACKUP_DIR"
        print_info "Set proper ownership for backup directory"
    fi
fi

# Create a full backup archive
# Determine backup name
BACKUP_NAME_PREFIX=$(get_backup_name "$NEXTDNS_ID" FALLBACK_DNS_SERVERS[@])
FULL_BACKUP_FILE="$USER_BACKUP_DIR/${BACKUP_NAME_PREFIX}-$TIMESTAMP.backup"

if [[ "$DRY_RUN" == true ]]; then
    print_info "[DRY-RUN] Would create full backup: $FULL_BACKUP_FILE"
else
    TEMP_BACKUP_DIR=$(mktemp -d)
    cp /etc/systemd/resolved.conf "$TEMP_BACKUP_DIR/resolved.conf" 2>/dev/null || true
    cp /etc/resolv.conf "$TEMP_BACKUP_DIR/resolv.conf" 2>/dev/null || true
    if [[ -f /etc/NetworkManager/NetworkManager.conf ]]; then
        cp /etc/NetworkManager/NetworkManager.conf "$TEMP_BACKUP_DIR/NetworkManager.conf" 2>/dev/null || true
    fi
    if [[ -f "$USER_HOME/.bashrc" ]]; then
        cp "$USER_HOME/.bashrc" "$TEMP_BACKUP_DIR/bashrc" 2>/dev/null || true
    fi
    tar -czf "$FULL_BACKUP_FILE" -C "$TEMP_BACKUP_DIR" .
    rm -rf "$TEMP_BACKUP_DIR"
    print_info "Created full backup: $FULL_BACKUP_FILE"
fi

# Create completely new .bashrc with default content
print_info "Creating clean .bashrc..."
if [[ "$DRY_RUN" == true ]]; then
    print_info "[DRY-RUN] Would create ~/.bashrc with DNS utilities"
else
cat > "$USER_HOME/.bashrc" << EOF
# .bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
    . /etc/bashrc
fi

# User specific environment
if ! [[ "\$PATH" =~ "\$HOME/.local/bin:\$HOME/bin:" ]]; then
    PATH="\$HOME/.local/bin:\$HOME/bin:\$PATH"
fi
export PATH

# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

# User specific aliases and functions
if [ -d ~/.bashrc.d ]; then
    for rc in ~/.bashrc.d/*; do
        if [ -f "\$rc" ]; then
            . "\$rc"
        fi
    done
fi
unset rc

# =========================================
# DNS Utilities for NextDNS systemd setup
# =========================================

# Show DNS configuration
dns-config() {
    echo "=== NextDNS Configuration ==="
    echo ""
    echo "Profile: ${ENDPOINT_PREFIX} ($NEXTDNS_ID)"
    echo ""
    echo "Full systemd-resolved status:"
    resolvectl status
    echo ""
    echo "DNS-over-TLS status:"
    resolvectl status | grep -A2 "DNSOverTLS"
}

# Comprehensive verification and connectivity test
verify-dns() {
    echo "========================================"
    echo "   DNS Setup Verification and Connectivity Test"
    echo "========================================"
    echo ""
    echo "Profile: ${ENDPOINT_PREFIX} ($NEXTDNS_ID)"
    echo ""
    
    echo "1. Configuration Files:"
    echo "----------------------"
    echo -n "  /etc/resolv.conf: "
    if grep -q "127.0.0.53" /etc/resolv.conf 2>/dev/null; then
        echo "✓ Points to systemd-resolved"
    else
        echo "✗ Not configured correctly"
    fi
    
    echo -n "  /etc/systemd/resolved.conf: "
    if grep -q "$NEXTDNS_ID" /etc/systemd/resolved.conf 2>/dev/null; then
        echo "✓ Contains NextDNS profile"
    else
        echo "✗ Missing NextDNS configuration"
    fi
    
    echo ""
    echo "2. Service Status:"
    echo "-----------------"
    echo -n "  systemd-resolved: "
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        echo "✓ Active"
    else
        echo "✗ Inactive"
    fi
    
    echo ""
    echo "3. Active DNS Detection:"
    echo "-----------------------"
    CURRENT_DNS=\$(resolvectl status 2>/dev/null | grep "Current DNS Server" | awk '{print \$4}' | head -1)
    if [[ -n "\$CURRENT_DNS" ]]; then
        echo "  Current DNS Server: \$CURRENT_DNS"
    else
        echo "  ✗ Could not detect current DNS"
    fi
    
    echo ""
    echo "4. NetworkManager DNS:"
    echo "---------------------"
    if command -v nmcli >/dev/null 2>&1; then
        NM_DNS_FOUND=false
        for conn in \$(nmcli -t -f NAME connection show --active); do
            ipv4_dns=\$(nmcli -g ipv4.dns connection show "\$conn" 2>/dev/null)
            if [[ -n "\$ipv4_dns" ]]; then
                echo "  ✗ \$conn has DNS: \$ipv4_dns"
                NM_DNS_FOUND=true
            fi
        done
        if [[ "\$NM_DNS_FOUND" == false ]]; then
            echo "  ✓ No NetworkManager DNS override"
        fi
    else
        echo "  ℹ NetworkManager not installed"
    fi
    
    echo ""
    echo "5. DNS Server Connectivity Test:"
    echo "--------------------------------"
    
    # Define servers to test
    SERVERS_TO_TEST=(
        "45.90.28.0"
        "45.90.30.0"
        "2a07:a8c0::"
        "2a07:a8c1::"
    )
    
    # Add fallback servers if available
    if [ -f ~/.nextdns_fallback_servers ]; then
        while IFS= read -r server; do
            if [[ -n "\$server" ]]; then
                SERVERS_TO_TEST+=("\$server")
            fi
        done < ~/.nextdns_fallback_servers
    fi
    
    # Add popular public DNS for comparison
    SERVERS_TO_TEST+=("8.8.8.8" "1.1.1.1" "9.9.9.9")
    
    total=\${#SERVERS_TO_TEST[@]}
    current=0
    
    echo "Testing \$total DNS servers..."
    echo ""
    
    declare -A RESULTS
    
    for server in "\${SERVERS_TO_TEST[@]}"; do
        ((current++))
        
        # Calculate percentage (avoid floating point)
        percentage=\$(( (current * 100) / total ))
        
        echo -n "  Testing \$server (\$percentage%)... "
        
        # Test DNS response with timing
        start_time=\$(date +%s%N)
        if timeout 2 nslookup -type=A google.com \$server >/dev/null 2>&1; then
            end_time=\$(date +%s%N)
            response_time_ms=\$(( (end_time - start_time) / 1000000 ))
            
            if [[ \$response_time_ms -lt 50 ]]; then
                result="✓ FAST (\${response_time_ms}ms)"
            elif [[ \$response_time_ms -lt 100 ]]; then
                result="✓ OK (\${response_time_ms}ms)"
            else
                result="✓ SLOW (\${response_time_ms}ms)"
            fi
            
            RESULTS[\$server]="\$result"
            echo "\$result"
        else
            RESULTS[\$server]="✗ NO RESPONSE"
            echo "✗ NO RESPONSE"
        fi
        
        # Small delay
        sleep 0.1
    done
    
    echo ""
    
    # Display results
    echo "Results:"
    echo "--------"
    
    # NextDNS servers
    echo "NextDNS Servers:"
    for server in "45.90.28.0" "45.90.30.0" "2a07:a8c0::" "2a07:a8c1::"; do
        if [[ -n "\${RESULTS[\$server]}" ]]; then
            echo "  \$server: \${RESULTS[\$server]}"
        fi
    done
    echo ""
    
    # Fallback servers
    if [ -f ~/.nextdns_fallback_servers ] && [ -s ~/.nextdns_fallback_servers ]; then
        echo "Fallback Servers:"
        while IFS= read -r server; do
            if [[ -n "\$server" && -n "\${RESULTS[\$server]}" ]]; then
                echo "  \$server: \${RESULTS[\$server]}"
            fi
        done < ~/.nextdns_fallback_servers
        echo ""
    fi
    
    # Public DNS
    echo "Public DNS (for comparison):"
    for server in "8.8.8.8" "1.1.1.1" "9.9.9.9"; do
        if [[ -n "\${RESULTS[\$server]}" ]]; then
            echo "  \$server: \${RESULTS[\$server]}"
        fi
    done
    
    echo ""
    echo "6. NextDNS Dashboard Test:"
    echo "--------------------------"
    HOSTNAME_LOWER=\$(hostname | tr '[:upper:]' '[:lower:]')
    TEST="test-\$(date +%s)-\${HOSTNAME_LOWER}.nextdns.io"
    echo "  Sending test query: \$TEST"
    echo "  (This may take a moment...)"
    
    # Send test query in background
    timeout 5 nslookup \$TEST 127.0.0.53 >/dev/null 2>&1 &
    
    echo "  ✓ Test query sent to NextDNS"
    echo ""
    echo "  Check your dashboard in 1-2 minutes:"
    echo "  https://my.nextdns.io/${NEXTDNS_ID}/logs"
    echo "  Look for query: \$TEST"
    
    echo ""
    echo "========================================"
    echo "NextDNS Dashboard: https://my.nextdns.io/${NEXTDNS_ID}"
    echo "========================================"
}

# Fix NetworkManager DNS override
fix-dns() {
    echo "Fixing NetworkManager DNS override..."
    echo ""
    
    if ! command -v nmcli >/dev/null 2>&1; then
        echo "NetworkManager not found. Nothing to fix."
        return
    fi
    
    # Find active connections
    ACTIVE_CONNS=\$(nmcli -t -f NAME connection show --active)
    
    if [[ -z "\$ACTIVE_CONNS" ]]; then
        echo "No active NetworkManager connections found."
        return
    fi
    
    for CONN in \$ACTIVE_CONNS; do
        echo "Clearing DNS for: \$CONN"
        sudo nmcli connection modify "\$CONN" ipv4.dns "" 2>/dev/null
        sudo nmcli connection modify "\$CONN" ipv6.dns "" 2>/dev/null
        sudo nmcli connection modify "\$CONN" ipv4.ignore-auto-dns yes 2>/dev/null
        sudo nmcli connection modify "\$CONN" ipv6.ignore-auto-dns yes 2>/dev/null
    done
    
    echo ""
    echo "Restarting NetworkManager..."
    sudo systemctl restart NetworkManager 2>/dev/null
    
    echo "Waiting 5 seconds for connections to reconnect..."
    sleep 5
    
    echo ""
    echo "✓ NetworkManager DNS cleared"
    echo "Run 'verify-dns' to confirm the fix."
}

# View DNS statistics and logs
dns-logs() {
    echo "=== DNS Statistics and Information ==="
    echo ""
    echo "Profile endpoints in logs:"
    echo "  IPv4: 45.90.28.0#${ENDPOINT_IPV4_PRIME}.dns.nextdns.io"
    echo "  IPv6: 2a07:a8c0::#${ENDPOINT_IPV6_PRIME}.dns.nextdns.io"
    echo ""
    echo "DNS Statistics:"
    echo "==============="
    resolvectl statistics
    echo ""
    echo "Systemd-resolved status:"
    echo "========================"
    resolvectl status | grep -E "(DNS Servers|Protocol|Current DNS Server|DNSSEC|DNS-over-TLS)"
    echo ""
    echo "Note: To see detailed DNS queries, enable debug logging with:"
    echo "  sudo resolvectl log-level debug"
    echo "  Then check logs with: sudo journalctl -u systemd-resolved"
    echo "  Remember to disable debug logging after troubleshooting:"
    echo "  sudo resolvectl log-level info"
}

# Restore backup function for user
dns-restore() {
    echo "=== DNS Configuration Restore ==="
    echo ""
    echo "This will restore DNS configuration from a backup."
    echo ""
    
    # Check for backups in user directory
    USER_BACKUP_DIR="\$HOME/.setup-dns-backups"
    if [[ ! -d "\$USER_BACKUP_DIR" ]]; then
        echo "No backup directory found: \$USER_BACKUP_DIR"
        echo "Run the setup script to create backups."
        return
    fi
    
    # List backups
    BACKUP_FILES=()
    while IFS= read -r -d \$'\0' file; do
        BACKUP_FILES+=("\$file")
    done < <(find "\$USER_BACKUP_DIR" -type f -name "*.backup" -print0 2>/dev/null | sort -z -r)
    
    if [[ \${#BACKUP_FILES[@]} -eq 0 ]]; then
        echo "No backup files found in \$USER_BACKUP_DIR"
        return
    fi
    
    echo "Available backups:"
    for ((i=0; i<\${#BACKUP_FILES[@]}; i++)); do
        local file="\${BACKUP_FILES[\$i]}"
        local filename=\$(basename "\$file")
        local size=\$(du -h "\$file" 2>/dev/null | cut -f1 || echo "?")
        local mtime=\$(stat -c "%y" "\$file" 2>/dev/null | cut -d'.' -f1 || echo "?")
        echo "  [\$((i+1))] \$filename (\$size) - \$mtime"
    done
    
    echo ""
    read -p "Enter backup number to restore (or 0 to cancel): " BACKUP_NUM
    
    if [[ "\$BACKUP_NUM" == "0" ]]; then
        echo "Restore cancelled."
        return
    fi
    
    if [[ "\$BACKUP_NUM" =~ ^[0-9]+\$ ]] && [[ "\$BACKUP_NUM" -ge 1 ]] && [[ "\$BACKUP_NUM" -le \${#BACKUP_FILES[@]} ]]; then
        local selected_backup="\${BACKUP_FILES[\$((BACKUP_NUM-1))]}"
        echo ""
        echo "Restoring from: \$(basename "\$selected_backup")"
        echo "This will overwrite current DNS configuration!"
        read -p "Are you sure? (y/N): " CONFIRM_RESTORE
        
        if [[ "\$CONFIRM_RESTORE" =~ ^[Yy]\$ ]]; then
            echo "Restoring backup..."
            TEMP_DIR=\$(mktemp -d)
            
            # Extract backup
            if ! tar -xzf "\$selected_backup" -C "\$TEMP_DIR"; then
                echo "✗ Failed to extract backup file!"
                rm -rf "\$TEMP_DIR"
                return
            fi
            
            # Restore files with sudo for system files
            if [[ -f "\$TEMP_DIR/resolved.conf" ]]; then
                sudo cp "\$TEMP_DIR/resolved.conf" /etc/systemd/resolved.conf
                echo "✓ Restored /etc/systemd/resolved.conf"
            fi
            
            if [[ -f "\$TEMP_DIR/resolv.conf" ]]; then
                sudo cp "\$TEMP_DIR/resolv.conf" /etc/resolv.conf
                echo "✓ Restored /etc/resolv.conf"
            fi
            
            if [[ -f "\$TEMP_DIR/NetworkManager.conf" ]]; then
                sudo cp "\$TEMP_DIR/NetworkManager.conf" /etc/NetworkManager/NetworkManager.conf
                echo "✓ Restored /etc/NetworkManager/NetworkManager.conf"
            fi
            
            if [[ -f "\$TEMP_DIR/bashrc" ]]; then
                # Fix permission issue: first copy as current user
                cp "\$TEMP_DIR/bashrc" "\$HOME/.bashrc.tmp"
                # Then move it (this preserves user ownership)
                mv "\$HOME/.bashrc.tmp" "\$HOME/.bashrc"
                echo "✓ Restored \$HOME/.bashrc"
                echo "Note: Restart your shell or run 'source ~/.bashrc' to apply changes"
            fi
            
            rm -rf "\$TEMP_DIR"
            
            echo ""
            echo "Restarting services..."
            sudo systemctl restart systemd-resolved 2>/dev/null
            if systemctl is-active NetworkManager >/dev/null 2>&1; then
                sudo systemctl restart NetworkManager 2>/dev/null
            fi
            echo "✓ Services restarted"
            echo ""
            echo "Backup restored successfully!"
        else
            echo "Restore cancelled."
        fi
    else
        echo "Invalid backup number!"
    fi
}

# Create manual backup function for user
dns-backup() {
    echo "=== Create Manual DNS Backup ==="
    echo ""
    echo "This will create a backup of your current DNS configuration."
    echo ""
    
    # Check if backup directory exists
    USER_BACKUP_DIR="\$HOME/.setup-dns-backups"
    mkdir -p "\$USER_BACKUP_DIR"
    
    # Ask for backup name
    read -p "Enter backup name (or press Enter for default): " BACKUP_NAME
    
    if [[ -z "\$BACKUP_NAME" ]]; then
        BACKUP_NAME="manual-backup"
    else
        # Clean the backup name
        BACKUP_NAME=\$(echo "\$BACKUP_NAME" | tr ' ' '-' | tr -cd '[:alnum:]-_')
        if [[ -z "\$BACKUP_NAME" ]]; then
            BACKUP_NAME="manual-backup"
            echo "Invalid name, using default: \$BACKUP_NAME"
        fi
    fi
    
    # Create timestamp
    TIMESTAMP=\$(date +%Y%m%d-%H%M%S)
    BACKUP_FILE="\$USER_BACKUP_DIR/\${BACKUP_NAME}-\${TIMESTAMP}.backup"
    
    echo ""
    echo "Creating backup: \$(basename "\$BACKUP_FILE")"
    echo ""
    
    # Create temporary directory for backup
    TEMP_DIR=\$(mktemp -d)
    
    # Backup current configuration
    echo "Backing up current configuration..."
    
    # Backup systemd-resolved configuration
    if [[ -f /etc/systemd/resolved.conf ]]; then
        sudo cp /etc/systemd/resolved.conf "\$TEMP_DIR/resolved.conf"
        echo "  ✓ Backed up /etc/systemd/resolved.conf"
    fi
    
    # Backup resolv.conf
    if [[ -f /etc/resolv.conf ]]; then
        sudo cp /etc/resolv.conf "\$TEMP_DIR/resolv.conf"
        echo "  ✓ Backed up /etc/resolv.conf"
    fi
    
    # Backup NetworkManager configuration
    if [[ -f /etc/NetworkManager/NetworkManager.conf ]]; then
        sudo cp /etc/NetworkManager/NetworkManager.conf "\$TEMP_DIR/NetworkManager.conf"
        echo "  ✓ Backed up /etc/NetworkManager/NetworkManager.conf"
    fi
    
    # Backup .bashrc
    if [[ -f "\$HOME/.bashrc" ]]; then
        cp "\$HOME/.bashrc" "\$TEMP_DIR/bashrc"
        echo "  ✓ Backed up \$HOME/.bashrc"
    fi
    
    # Create backup archive (run tar as current user, not sudo)
    cd "\$TEMP_DIR"
    tar -czf "\$BACKUP_FILE" .
    
    # Clean up
    rm -rf "\$TEMP_DIR"
    
    # Show backup info
    if [[ -f "\$BACKUP_FILE" ]]; then
        BACKUP_SIZE=\$(du -h "\$BACKUP_FILE" | cut -f1)
        echo ""
        echo "✓ Backup created successfully!"
        echo "  File: \$(basename "\$BACKUP_FILE")"
        echo "  Size: \$BACKUP_SIZE"
        echo "  Location: \$USER_BACKUP_DIR"
        echo ""
        echo "To restore this backup later, run: dns-restore"
    else
        echo "✗ Failed to create backup file!"
        echo "Check if you have write permissions to: \$USER_BACKUP_DIR"
    fi
}

# check dns service function
check-dns-service() {
    echo "=== Check DNS Service ==="
    echo ""
    echo "This will check if a DNS service is responsive and test various protocols."
    echo ""
    
    read -p "Enter DNS server IP address to check: " CHECK_IP
    
    if [[ -z "\$CHECK_IP" ]]; then
        echo "No IP address provided."
        return
    fi
    
    echo ""
    echo "Checking DNS service: \$CHECK_IP"
    echo ""
    
    # Check if service is known
    SERVICE_NAME=\$(grep "^\$CHECK_IP:" ~/.dns_service_names 2>/dev/null | cut -d: -f2)
    if [[ -n "\$SERVICE_NAME" ]]; then
        echo "Service: \$SERVICE_NAME"
        
        # Try to get URL
        SERVICE_URL=\$(grep "^\$CHECK_IP:" ~/.dns_service_names 2>/dev/null | cut -d: -f3)
        if [[ -n "\$SERVICE_URL" ]]; then
            echo "Website: \$SERVICE_URL"
        fi
        echo ""
    fi
    
    echo "Testing protocols (with progress):"
    echo "--------------------------------"
    
    # Test traditional DNS (port 53)
    echo -n "1. Traditional DNS (port 53): "
    start_time=\$(date +%s%N)
    if timeout 2 nslookup -type=A google.com \$CHECK_IP >/dev/null 2>&1; then
        end_time=\$(date +%s%N)
        response_time_ms=\$(( (end_time - start_time) / 1000000 ))
        
        if [[ \$response_time_ms -lt 50 ]]; then
            result="✓ FAST (\${response_time_ms}ms)"
        elif [[ \$response_time_ms -lt 100 ]]; then
            result="✓ OK (\${response_time_ms}ms)"
        else
            result="✓ SLOW (\${response_time_ms}ms)"
        fi
        
        echo "\$result"
    else
        echo "✗ NO RESPONSE"
    fi
    
    # Test DNS-over-TLS (port 853)
    echo -n "2. DNS-over-TLS (port 853): "
    if timeout 1 nc -z \$CHECK_IP 853 2>/dev/null; then
        echo "✓ PORT OPEN"
        # Try to get TLS certificate info
        TLS_CERT=\$(timeout 3 openssl s_client -connect \$CHECK_IP:853 -servername \$CHECK_IP 2>/dev/null | openssl x509 -noout -subject 2>/dev/null | cut -d'=' -f2-)
        if [[ -n "\$TLS_CERT" ]]; then
            echo "   Certificate: \$TLS_CERT"
        fi
    else
        echo "✗ PORT CLOSED"
    fi
    
    # Test DNS-over-HTTP/3 if curl supports it
    echo -n "3. DNS-over-HTTP/3: "
    if command -v curl >/dev/null 2>&1; then
        # Try known DOH3 endpoints for this IP
        case "\$CHECK_IP" in
            "1.1.1.1"|"1.0.0.1")
                doh_endpoint="https://cloudflare-dns.com/dns-query"
                ;;
            "8.8.8.8"|"8.8.4.4")
                doh_endpoint="https://dns.google/dns-query"
                ;;
            "9.9.9.9"|"149.112.112.112")
                doh_endpoint="https://dns.quad9.net/dns-query"
                ;;
            "94.140.14.14"|"94.140.15.15")
                doh_endpoint="https://dns.adguard.com/dns-query"
                ;;
            *)
                doh_endpoint="https://\$CHECK_IP/dns-query"
                ;;
        esac
        
        # Try with HTTP/3
        if curl --http3 --max-time 3 -s -H "accept: application/dns-json" \
            "\$doh_endpoint?name=google.com&type=A" 2>/dev/null | grep -q "Answer"; then
            echo "✓ SUPPORTED"
            echo "   Endpoint: \$doh_endpoint"
        else
            # Try with HTTP/2 as fallback
            if curl --http2 --max-time 3 -s -H "accept: application/dns-json" \
                "\$doh_endpoint?name=google.com&type=A" 2>/dev/null | grep -q "Answer"; then
                echo "✓ SUPPORTED (HTTP/2)"
                echo "   Endpoint: \$doh_endpoint"
            else
                echo "✗ NOT SUPPORTED"
            fi
        fi
    else
        echo "✗ curl not available for testing"
    fi
    
    # Try reverse DNS
    echo ""
    echo "Reverse DNS lookup:"
    REVERSE_DNS=\$(nslookup \$CHECK_IP 2>/dev/null | grep "name =" | awk '{print \$4}' | head -1)
    if [[ -n "\$REVERSE_DNS" ]]; then
        echo "  \$REVERSE_DNS"
    else
        echo "  No reverse DNS record found"
    fi
    
    echo ""
    echo "Protocol summary:"
    echo "  • Traditional DNS: Used by systemd-resolved"
    echo "  • DNS-over-TLS: Encrypted DNS (used by this setup)"
    echo "  • DNS-over-HTTP/3: Modern encrypted DNS"
    echo ""
    echo "Note: HTTP/3 requires curl 7.66.0+ and may need --http3 flag"
}

# Show DNS service information
dns-info() {
    echo "=== DNS Service Information ==="
    echo ""
    echo "Available DNS services with their features:"
    echo ""
    echo "1. Quad9 (9.9.9.9, 149.112.112.112)"
    echo "   Website: https://www.quad9.net"
    echo "   Features: Malware blocking, DNSSEC, no logging, free"
    echo "   Privacy: Does not log IP addresses"
    echo "   Protocols: DNS, DNS-over-TLS, DNS-over-HTTP/3"
    echo ""
    echo "2. Cloudflare (1.1.1.1, 1.0.0.1)"
    echo "   Website: https://1.1.1.1"
    echo "   Features: Fast, privacy-focused, DNSSEC, free"
    echo "   Privacy: Committed to not selling data"
    echo "   Protocols: DNS, DNS-over-TLS, DNS-over-HTTP/3"
    echo ""
    echo "3. Google (8.8.8.8, 8.8.4.4)"
    echo "   Website: https://developers.google.com/speed/public-dns"
    echo "   Features: Reliable, fast, DNSSEC, free"
    echo "   Privacy: Logs for 24-48 hours"
    echo "   Protocols: DNS, DNS-over-TLS, DNS-over-HTTP/3"
    echo ""
    echo "4. AdGuard (94.140.14.14, 94.140.15.15)"
    echo "   Website: https://adguard-dns.io"
    echo "   Features: Ad blocking, tracking protection, free"
    echo "   Privacy: Basic mode logs 24 hours"
    echo "   Protocols: DNS, DNS-over-TLS, DNS-over-HTTP/3"
    echo ""
    echo "5. OpenDNS (208.67.222.222, 208.67.220.220)"
    echo "   Website: https://www.opendns.com"
    echo "   Features: Content filtering, phishing protection"
    echo "   Privacy: Free tier has logging"
    echo "   Protocols: DNS, DNS-over-TLS"
    echo ""
    echo "6. CleanBrowsing (185.228.168.9)"
    echo "   Website: https://cleanbrowsing.org"
    echo "   Features: Family-safe, malware blocking"
    echo "   Privacy: Free tier has limited logging"
    echo "   Protocols: DNS, DNS-over-TLS, DNS-over-HTTP/3"
    echo ""
    echo "7. NextDNS (45.90.28.0, 45.90.30.0)"
    echo "   Website: https://my.nextdns.io"
    echo "   Features: Customizable filtering, analytics, encrypted"
    echo "   Privacy: Configurable logging (free tier: 300k queries/month)"
    echo "   Protocols: DNS, DNS-over-TLS, DNS-over-HTTP/3"
    echo ""
    echo "Note: All services support DNS-over-TLS (port 853)"
    echo "      IPv6 addresses available for all major providers"
}

# Aliases
alias dns='dns-config'
alias logsdns='dns-logs'
alias fixdns='fix-dns'
alias restoredns='dns-restore'
alias backupdns='dns-backup'
alias checkdns='check-dns-service'
alias check-dns='check-dns-service'
alias dns-services='dns-info'

echo ""
echo "NextDNS utilities loaded. Available commands:"
echo "  dns-config  - Detailed DNS configuration"
echo "  verify-dns  - Comprehensive setup verification and Connectivity Test"
echo "  fix-dns     - Fix NetworkManager DNS override"
echo "  dns-logs    - View DNS statistics and information"
echo "  dns-restore - Restore DNS configuration from backup"
echo "  dns-backup  - Create manual backup of current DNS configuration"
echo "  checkdns    - Check DNS service responsiveness and information (or check-dns)"
echo "  dns-services - Show information about DNS services"
EOF

    # Fix ownership of .bashrc
    if [[ -n "$SUDO_USER" ]]; then
        chown "$SUDO_USER:$SUDO_USER" "$USER_HOME/.bashrc"
        print_info "Set proper ownership for .bashrc"
    fi
    
    print_success "✓ DNS utilities added to .bashrc"
fi

# ============================================
# Step 6: Create standalone verification script
# ============================================
print_info "Creating verification tools..."

if [[ "$DRY_RUN" == true ]]; then
    print_info "[DRY-RUN] Would create /usr/local/bin/verify-dns-system"
else
cat > /usr/local/bin/verify-dns-system << 'EOF'
#!/bin/bash
echo "========================================"
echo "   DNS System Verification"
echo "========================================"
echo ""

echo "1. System Configuration:"
echo "----------------------"
echo "resolv.conf:"
cat /etc/resolv.conf 2>/dev/null || echo "File not found"
echo ""
echo "systemd-resolved.conf:"
grep -E "^(DNS=|DNSOverTLS|DNSSEC)" /etc/systemd/resolved.conf 2>/dev/null || echo "File not found"
echo ""

echo "2. Service Status:"
echo "-----------------"
systemctl status systemd-resolved --no-pager | head -10
echo ""

echo "3. Current DNS Status:"
echo "---------------------"
resolvectl status 2>/dev/null | grep -E "(Current DNS|DNS Servers|Protocol)" | head -10
echo ""

echo "4. Basic Connectivity:"
echo "---------------------"
echo -n "DNS resolution: "
if timeout 2 nslookup google.com 127.0.0.53 >/dev/null 2>&1; then
    echo "✓ Working"
else
    echo "✗ Failing"
fi
echo ""

echo "5. NetworkManager Status:"
echo "------------------------"
if command -v nmcli >/dev/null 2>&1; then
    echo "Active connections:"
    nmcli -t -f NAME connection show --active
    echo ""
    echo "DNS settings:"
    for conn in $(nmcli -t -f NAME connection show --active); do
        dns=$(nmcli -g ipv4.dns connection show "$conn" 2>/dev/null)
        echo "  $conn: ${dns:-No DNS configured}"
    done
else
    echo "NetworkManager not installed"
fi

echo "========================================"
echo "Run 'verify-dns' for comprehensive testing"
echo "========================================"
EOF

chmod +x /usr/local/bin/verify-dns-system
fi

# ============================================
# Step 7: Final verification
# ============================================
print_info ""
print_info "==========================================="
print_info "            FINAL VERIFICATION"
print_info "==========================================="
echo ""

echo "1. Configuration check:"
echo "----------------------"
echo -n "resolv.conf: "
if [[ "$DRY_RUN" == true ]]; then
    echo "[DRY-RUN] Would check"
elif grep -q "127.0.0.53" /etc/resolv.conf 2>/dev/null; then
    echo "✓ Configured correctly"
else
    echo "✗ Not configured"
fi

echo -n "systemd-resolved: "
if [[ "$DRY_RUN" == true ]]; then
    echo "[DRY-RUN] Would check"
elif systemctl is-active systemd-resolved >/dev/null 2>&1; then
    echo "✓ Active"
else
    echo "✗ Inactive"
fi

echo ""
echo "2. Port check:"
echo "-------------"
echo -n "Port 53 listening: "
if [[ "$DRY_RUN" == true ]]; then
    echo "[DRY-RUN] Would check"
elif ss -tuln | grep ":53 " >/dev/null; then
    echo "✓ (systemd-resolved)"
else
    echo "✗ Not listening"
fi

echo ""
echo "3. Quick DNS test:"
echo "-----------------"
echo -n "DNS resolution: "
if [[ "$DRY_RUN" == true ]]; then
    echo "[DRY-RUN] Would test"
elif timeout 2 nslookup google.com 127.0.0.53 >/dev/null 2>&1; then
    echo "✓ Working"
else
    echo "✗ Failing"
fi

# ============================================
# Step 8: Final summary
# ============================================
if [[ "$DRY_RUN" == true ]]; then
    print_info ""
    print_info "==========================================="
    print_info "         DRY-RUN COMPLETE!"
    print_info "==========================================="
    echo ""
    print_info "No changes were made to the system."
    print_info "Review the [DRY-RUN] messages above to see what would be configured."
    print_info ""
    print_info "To apply the configuration, run without --dry-run flag:"
    print_info "  sudo $0"
else
    print_info ""
    print_info "==========================================="
    print_info "         SETUP COMPLETE!"
    print_info "==========================================="
    echo ""
    print_success "✓ systemd-resolved configured with NextDNS profile names"
    print_success "✓ /etc/resolv.conf points to 127.0.0.53 (systemd-resolved)"
    print_success "✓ DNS-over-TLS enabled for encryption"
    print_success "✓ NetworkManager configured to not interfere"
    if [ ${#FALLBACK_DNS_SERVERS[@]} -eq 0 ]; then
        print_success "✓ No fallback DNS servers configured (NextDNS only)"
    else
        print_success "✓ Fallback DNS servers configured: ${FALLBACK_DNS_SERVERS[*]}"
    fi
    print_success "✓ Clean .bashrc created with DNS utilities"
    print_success "✓ Full backup created: $FULL_BACKUP_FILE"
    echo ""
    print_info "Key Configuration:"
    print_info "  • NextDNS Profile: ${ENDPOINT_PREFIX} ($NEXTDNS_ID)"
    print_info "  • Dashboard: https://my.nextdns.io/${NEXTDNS_ID}/logs"
    print_info "  • DNS Servers: 45.90.28.0, 45.90.30.0"
    if [ ${#FALLBACK_DNS_SERVERS[@]} -gt 0 ]; then
        print_info "  • Fallback DNS: ${FALLBACK_DNS_SERVERS[*]}"
    fi
    print_info "  • DNS-over-TLS: Enabled"
    print_info "  • DNSSEC: allow-downgrade"
    print_info "  • Backup Location: $USER_BACKUP_DIR"
    echo ""
    print_info "Available Commands:"
    print_info "  • dns-config  - Detailed DNS configuration"
    print_info "  • verify-dns  - Comprehensive setup verification and Connectivity Test"
    print_info "  • fix-dns     - Fix NetworkManager override"
    print_info "  • dns-logs    - View DNS statistics and information"
    print_info "  • dns-restore - Restore DNS configuration from backup"
    print_info "  • dns-backup  - Create manual backup of current DNS configuration"
    print_info "  • checkdns    - Check DNS service responsiveness and information"
    print_info "  • check-dns   - Alternative alias for checkdns"
    echo ""
    print_info "Next Steps:"
    print_info "  1. Restart your shell or run: source ~/.bashrc"
    print_info "  2. Test with: verify-dns"
    print_info "  3. Check dashboard: https://my.nextdns.io/${NEXTDNS_ID}/logs"
    echo ""
    print_info "Note: If DNS stops working, run 'fix-dns' to clear NetworkManager override."
    echo ""
    print_info "Backup created. To create additional backups, run: backupdns"
    print_info "To restore later, run: restoredns"
    echo ""
    print_success "Setup complete! Your system is now configured for NextDNS."
fi
