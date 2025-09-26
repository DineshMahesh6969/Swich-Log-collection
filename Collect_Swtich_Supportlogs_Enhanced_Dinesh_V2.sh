#!/bin/bash

# Enhanced Network Switch Log Collector
# Author: Network Admin Tools
# Version: 2.0

# Color definitions for better UI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Define variables
LOG_DIR="tech_support_logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Function to display header
display_header() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}               Network Switch Log Collector v2.0              ${CYAN}║${NC}"
    echo -e "${CYAN}║${WHITE}              Professional Network Administration Tool         ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to create log directory
create_log_directory() {
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR"
        echo -e "${GREEN}✓ Created log directory: ${WHITE}$LOG_DIR${NC}"
    fi
    echo ""
}

# Function to parse IP range (e.g., 10.2.0.26 - to 10.2.0.30)
parse_ip_range() {
    local range_input="$1"
    local ip_list=()
    
    # Extract start and end IPs from range format
    if [[ $range_input =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.([0-9]{1,3}))\ *-\ *to\ *([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.([0-9]{1,3}))$ ]]; then
        local start_ip="${BASH_REMATCH[1]}"
        local start_last_octet="${BASH_REMATCH[2]}"
        local end_ip="${BASH_REMATCH[3]}"
        local end_last_octet="${BASH_REMATCH[4]}"
        
        # Extract base IP (first three octets)
        local base_ip=$(echo "$start_ip" | cut -d. -f1-3)
        
        # Generate IP range
        for ((i=start_last_octet; i<=end_last_octet; i++)); do
            ip_list+=("$base_ip.$i")
        done
    fi
    
    echo "${ip_list[@]}"
}

# Function to parse comma-separated IPs
parse_comma_separated_ips() {
    local input="$1"
    local ip_list=()
    
    # Split by comma and clean up whitespace
    IFS=',' read -ra ADDR <<< "$input"
    for ip in "${ADDR[@]}"; do
        # Remove leading/trailing whitespace
        ip=$(echo "$ip" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            ip_list+=("$ip")
        fi
    done
    
    echo "${ip_list[@]}"
}

# Function to validate and parse IP input
parse_ip_input() {
    local input="$1"
    local ip_array=()
    
    # Remove all whitespace for easier parsing
    local clean_input=$(echo "$input" | tr -d ' ')
    
    # Check for range format (contains "to")
    if [[ $input =~ -.*to ]]; then
        ip_array=($(parse_ip_range "$input"))
    # Check for comma-separated format
    elif [[ $clean_input =~ , ]]; then
        ip_array=($(parse_comma_separated_ips "$input"))
    # Single IP
    elif [[ $clean_input =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        ip_array=("$clean_input")
    fi
    
    echo "${ip_array[@]}"
}

# Function to get user input with validation
get_switch_credentials() {
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${WHITE}              Enter Switch Connection Details               ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${CYAN}Supported IP formats:${NC}"
    echo -e "${WHITE}  • Single IP: ${YELLOW}10.2.0.26${NC}"
    echo -e "${WHITE}  • Comma-separated: ${YELLOW}10.2.0.26,10.2.0.27,10.2.0.28${NC}"
    echo -e "${WHITE}  • Range: ${YELLOW}10.2.0.26 - to 10.2.0.30${NC}"
    echo ""
    
    # Get Switch IP(s)
    while true; do
        echo -ne "${YELLOW}Switch IP Address(es): ${WHITE}"
        read -r SWITCH_IP_INPUT
        
        # Parse and validate IP input
        SWITCH_IPS=($(parse_ip_input "$SWITCH_IP_INPUT"))
        
        if [ ${#SWITCH_IPS[@]} -gt 0 ]; then
            echo -e "${GREEN}✓ Parsed ${#SWITCH_IPS[@]} IP address(es):${NC}"
            for ip in "${SWITCH_IPS[@]}"; do
                echo -e "${WHITE}  • $ip${NC}"
            done
            echo ""
            break
        else
            echo -e "${RED}✗ Invalid IP address format. Please try again.${NC}"
            echo ""
        fi
    done
    
    # Get Username
    echo -ne "${YELLOW}Username: ${WHITE}"
    read -r USERNAME
    
    # Get Password (hidden input)
    echo -ne "${YELLOW}Password: ${WHITE}"
    read -s PASSWORD
    echo ""
    echo ""
}

# Function to test connectivity and authentication
test_connection() {
    local ip=$1
    local user=$2
    local pass=$3
    
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${WHITE}                Testing Connection...                        ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # Create a simple test command
    local test_cmd=$(mktemp)
    echo "show version | include uptime" > "$test_cmd"
    
    # Test SSH connection
    timeout 10s sshpass -p "$pass" ssh -o "UserKnownHostsFile=/dev/null" \
                                        -o "StrictHostKeyChecking=no" \
                                        -o "ConnectTimeout=5" \
                                        -o "PasswordAuthentication=yes" \
                                        -l "$user" "$ip" < "$test_cmd" > /dev/null 2>&1
    
    local result=$?
    rm -f "$test_cmd"
    
    if [ $result -eq 0 ]; then
        echo -e "${GREEN}✓ LOGIN SUCCESSFUL${NC} - Connected to ${WHITE}$ip${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}✗ LOGIN FAILED${NC} - Unable to connect to ${WHITE}$ip${NC}"
        echo -e "${RED}  Please check your credentials and try again.${NC}"
        echo ""
        return 1
    fi
}

# Function to collect tech support from a switch
collect_tech_support() {
    local ip=$1
    local user=$2
    local pass=$3
    local logfile="$LOG_DIR/${ip}_tech_support_${TIMESTAMP}.log"
    
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${WHITE}              Collecting Technical Support Logs             ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${YELLOW}Collecting from: ${WHITE}$ip${NC}"
    echo -e "${YELLOW}Log file: ${WHITE}$logfile${NC}"
    echo ""
    
    # Show progress indicator
    echo -ne "${CYAN}Progress: ${NC}"
    
    # Create comprehensive command file
    local cmd_file=$(mktemp)
    cat << EOF > "$cmd_file"
enable
$pass
terminal length 0
show version
show running-config
show startup-config
show interfaces
show ip interface brief
show ip route
show arp
show mac address-table
show spanning-tree
show vlan brief
show inventory
show environment
show processes cpu
show processes memory
show logging
show tech-support
exit
EOF
    
    # Execute log collection with progress updates
    {
        for i in {1..20}; do
            echo -ne "${GREEN}█${NC}"
            sleep 0.2
        done
        echo ""
    } &
    local progress_pid=$!
    
    # Use sshpass for password authentication
    sshpass -p "$pass" ssh -o "UserKnownHostsFile=/dev/null" \
                           -o "StrictHostKeyChecking=no" \
                           -o "ConnectTimeout=10" \
                           -o "PasswordAuthentication=yes" \
                           -l "$user" "$ip" < "$cmd_file" > "$logfile" 2>&1
    
    local result=$?
    
    # Stop progress indicator
    kill $progress_pid 2>/dev/null
    wait $progress_pid 2>/dev/null
    
    if [ $result -eq 0 ] && [ -s "$logfile" ]; then
        # Clean up any ANSI escape sequences and control characters
        sed -i 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$logfile"
        sed -i 's/\r//g' "$logfile"
        
        echo ""
        echo -e "${GREEN}✓ LOG COLLECTION COMPLETED SUCCESSFULLY${NC}"
        echo -e "${GREEN}  Output saved to: ${WHITE}$logfile${NC}"
        
        # Show file size
        local filesize=$(du -h "$logfile" | cut -f1)
        echo -e "${GREEN}  File size: ${WHITE}$filesize${NC}"
    else
        echo ""
        echo -e "${RED}✗ LOG COLLECTION FAILED${NC}"
        echo -e "${RED}  Please check the connection and try again.${NC}"
        
        # Remove empty log file
        [ -f "$logfile" ] && rm -f "$logfile"
    fi
    
    # Clean up command file
    rm -f "$cmd_file"
    echo ""
}

# Function to ask for continuation
ask_continue() {
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${WHITE}                    Continue Collection?                     ${PURPLE}│${NC}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    while true; do
        echo -ne "${YELLOW}Do you want to collect logs from another switch? (y/n): ${WHITE}"
        read -r answer
        case $answer in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo -e "${RED}Please answer yes (y) or no (n).${NC}";;
        esac
    done
}

# Function to show final summary
show_summary() {
    local full_path=$(realpath "$LOG_DIR")
    
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${WHITE}                    Collection Complete                      ${CYAN}│${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${GREEN}✓ All log collections completed successfully!${NC}"
    echo ""
    echo -e "${YELLOW}Logs are stored in:${NC}"
    echo -e "${WHITE}  Directory: ${GREEN}$full_path${NC}"
    echo ""
    
    # List collected log files
    if [ -d "$LOG_DIR" ] && [ "$(ls -A $LOG_DIR)" ]; then
        echo -e "${YELLOW}Collected files:${NC}"
        ls -la "$LOG_DIR" | grep -E "\.log$" | while read -r line; do
            filename=$(echo "$line" | awk '{print $9}')
            filesize=$(echo "$line" | awk '{print $5}')
            echo -e "${WHITE}  • ${GREEN}$filename${NC} ${CYAN}($filesize bytes)${NC}"
        done
    fi
    
    echo ""
    echo -e "${BLUE}Thank you for using Network Switch Log Collector!${NC}"
}

# Function to check dependencies
check_dependencies() {
    if ! command -v sshpass &> /dev/null; then
        echo -e "${RED}✗ Error: sshpass is required but not installed.${NC}"
        echo -e "${YELLOW}Please install sshpass:${NC}"
        echo -e "${WHITE}  RHEL/CentOS: sudo yum install sshpass${NC}"
        echo -e "${WHITE}  SUSE: sudo zypper install sshpass${NC}"
        echo -e "${WHITE}  Ubuntu/Debian: sudo apt-get install sshpass${NC}"
        echo ""
        exit 1
    fi
}

# Main script execution
main() {
    # Check dependencies
    check_dependencies
    
    # Display header
    display_header
    
    # Create log directory
    create_log_directory
    
    while true; do
        # Get switch credentials and IP addresses
        get_switch_credentials
        
        # Process each IP address
        local total_ips=${#SWITCH_IPS[@]}
        local current_ip=0
        
        echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${WHITE}            Processing ${total_ips} Switch(es)                         ${CYAN}│${NC}"
        echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        
        for ip in "${SWITCH_IPS[@]}"; do
            ((current_ip++))
            echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
            echo -e "${PURPLE}Processing switch ${current_ip} of ${total_ips}: ${WHITE}${ip}${NC}"
            echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${NC}"
            echo ""
            
            # Test connection first
            if test_connection "$ip" "$USERNAME" "$PASSWORD"; then
                # Collect tech support logs
                collect_tech_support "$ip" "$USERNAME" "$PASSWORD"
            else
                echo -e "${RED}⚠ Skipping log collection for ${ip} due to connection failure${NC}"
                echo ""
            fi
            
            # Add small delay between switches to avoid overwhelming the network
            if [ $current_ip -lt $total_ips ]; then
                echo -e "${CYAN}Waiting 2 seconds before next switch...${NC}"
                sleep 2
                echo ""
            fi
        done
        
        # Ask if user wants to continue with more switches
        if ! ask_continue; then
            break
        fi
        
        echo ""
    done
    
    # Show final summary
    show_summary
}

# Execute main function
main "$@"