#!/bin/bash
# Kali Linux Security Event Monitor (kali-sem)
# Author: dynamo (modified by assistant)
# Specialized for Kali 2024.1+ log structure

##############################################
#           KALI-SPECIFIC CONFIG             #
##############################################
LOG_SOURCES=("/var/log/auth.log")  # Kali uses auth.log instead of secure
BACKUP_ROOT="/var/log/security_archive"
ALERT_THRESHOLD=3                # More sensitive for Kali's pentesting role
HIGH_RISK_PROTOCOLS=("ssh" "su" "sudo" "msfconsole")

# Kali-specific log patterns
declare -A KALI_LOG_PATTERNS=(
    ["ssh"]="Failed password|sshd.*authentication failure"
    ["console"]="FAILED SU|LOGIN FAILURE|authentication failure"
    ["sudo"]="incorrect password attempts|sudo.*authentication error"
    ["services"]="authentication failure.*service="
)

# Colors (Kali terminal compatible)
CRIT="\e[1;91m"  # Red
HIGH="\e[1;93m"   # Yellow
MED="\e[1;96m"    # Cyan
NC="\e[0m"        # No Color

# Global variable to keep track of the last processed line number
LAST_LINE_COUNT=0

##############################################
#         KALI-SPECIFIC IMPLEMENTATION       #
##############################################

initialize_kali() {
    # Create secure backup location
    mkdir -p "$BACKUP_ROOT" || {
        echo -e "${CRIT}Failed to create backup directory${NC}"
        exit 1
    }
    chmod 0700 "$BACKUP_ROOT"

    # Check Kali-specific dependencies
    local required_tools=("inotifywait" "journalctl" "systemd-cat")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "${CRIT}Kali dependency missing: $tool${NC}"
            echo "Install with: sudo apt install inotify-tools systemd"
            exit 1
        fi
    done

    # Validate Kali log structure
    if [ ! -f "/var/log/auth.log" ]; then
        echo -e "${CRIT}Kali auth.log not found - abnormal system state${NC}"
        exit 1
    fi

    # Record the current end of the log file so we don't process historical entries
    LAST_LINE_COUNT=$(wc -l < /var/log/auth.log)
}

monitor_kali_auth() {
    # Real-time monitoring with inotifywait integration
    inotifywait -m -e modify --format '%w' "${LOG_SOURCES[@]}" | while read -r logfile; do
        process_kali_logs "$logfile"
    done
}

process_kali_logs() {
    local logfile="$1"
    local tmp_events="/tmp/kali_events.$$"

    # Get the current number of lines
    local current_line_count
    current_line_count=$(wc -l < "$logfile")

    # If no new lines have been added, nothing to do
    if [ "$current_line_count" -le "$LAST_LINE_COUNT" ]; then
        return
    fi

    # Calculate number of new lines added
    local new_lines=$((current_line_count - LAST_LINE_COUNT))

    # Extract only the new entries that match the interest patterns
    tail -n "$new_lines" "$logfile" | grep -Ei "failed|error|denied" > "$tmp_events"

    # Update the last processed line count
    LAST_LINE_COUNT=$current_line_count

    # Process the new log entries
    while read -r message; do
        local service=""
        if [[ "$message" =~ sshd ]]; then
            service="sshd"
        elif [[ "$message" =~ sudo ]]; then
            service="sudo"
        elif [[ "$message" =~ su ]]; then
            service="su"
        elif [[ "$message" =~ unix_chkpwd ]]; then
            service="sudo"  # treat password check failures as sudo
        elif [[ "$message" =~ gdm|gnome ]]; then
            service="gnome"
        else
            service="unknown"
        fi

        analyze_kali_event "$service" "alert" "$message"
    done < "$tmp_events"

    rm -f "$tmp_events"
}

handle_unknown_service() {
    local message="$1"
    echo -e "${HIGH}[Unknown Service]${NC} Unrecognized log source. Event: ${message}"
    generate_alert "unknown" "n/a" "$message"
}

analyze_kali_event() {
    local service="$1"
    local priority="$2"
    local message="$3"
    
    # Map Kali-specific services to monitoring categories
    case "$service" in
        "sshd") handle_ssh_event "$message" ;;
        "sudo") handle_privilege_event "$message" ;;
        "su") handle_console_event "$message" ;;
        "gnome") handle_gui_event "$message" ;;  # Kali X11 sessions
        "msfconsole") handle_metasploit_event "$message" ;;
        *) handle_unknown_service "$message" ;;
    esac
}

handle_ssh_event() {
    local message="$1"
    local ip
    ip=$(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" <<< "$message")
    
    [ -z "$ip" ] && return  # Skip non-IP events
    
    echo -e "${HIGH}[SSH Alert]${NC} Suspicious activity from ${MED}$ip${NC}"
    echo "Raw event: $message"
    generate_alert "ssh" "$ip" "$message"
}

handle_privilege_event() {
    local message="$1"
    local user
    user=$(grep -oP "user=\K\w+" <<< "$message" || echo "")
    [ -z "$user" ] && user=$(grep -oP "\(.*?\)" <<< "$message" | tr -d '()')
    [ -z "$user" ] && user="unknown"

    echo -e "${CRIT}[Priv Esc Attempt]${NC} Detected for user ${MED}$user${NC}"
    generate_alert "privilege" "$user" "$message"
}

handle_console_event() {
    local message="$1"
    local tty
    tty=$(grep -oP "tty=\K\d+" <<< "$message" || echo "unknown")
    
    echo -e "${HIGH}[Console Alert]${NC} Physical console event on ${MED}tty$tty${NC}"
    generate_alert "console" "$tty" "$message"
}

handle_gui_event() {
    local message="$1"
    echo -e "${MED}[GUI Alert]${NC} Event detected in GUI session. Event: $message"
    generate_alert "gui" "n/a" "$message"
}

handle_metasploit_event() {
    local message="$1"
    echo -e "${MED}[Metasploit Alert]${NC} Event detected from msfconsole. Event: $message"
    generate_alert "msfconsole" "n/a" "$message"
}

generate_alert() {
    local alert_type="$1"
    local target="$2"
    local raw_message="$3"
    local timestamp
    timestamp=$(date +"%Y-%m-%dT%H:%M:%S%z")
    
    # Kali-specific alert format
    cat <<- EOF
    [
      {
        "timestamp": "$timestamp",
        "alert_type": "$alert_type",
        "target": "$target",
        "risk_level": "$(calculate_risk "$alert_type")",
        "raw_log": "$(jq -aR <<< "$raw_message")"
      }
    ]
EOF
}

calculate_risk() {
    case "$1" in
        "ssh") echo -e "${HIGH}high${NC}" ;;
        "privilege") echo -e "${CRIT}critical${NC}" ;;
        "console") echo -e "${MED}medium${NC}" ;;
        *) echo -e "low" ;;
    esac
}

backup_kali_logs() {
    # Rotating backup with Kali's logrotate integration
    local timestamp
    timestamp=$(date +"%Y%m%d%H%M%S")
    local backup_file="$BACKUP_ROOT/authlog_${timestamp}.gz"
    
    cp /var/log/auth.log "/tmp/auth_tmp.$$" && \
    gzip -c "/tmp/auth_tmp.$$" > "$backup_file" && \
    chmod 0600 "$backup_file"
    
    rm -f "/tmp/auth_tmp.$$"
    echo -e "${MED}[Backup]${NC} Created secured backup: ${backup_file}"
}

##############################################
#             EXECUTION FLOW               #
##############################################

case "$1" in
    start)
        initialize_kali
        echo -e "${MED}Starting Kali Security Monitor${NC}"
        backup_kali_logs
        monitor_kali_auth
        ;;
    stop)
        echo -e "${MED}Stopping monitoring...${NC}"
        pkill -f "inotifywait.*auth.log"
        ;;
    *)
        echo -e "${HIGH}Kali Security Monitor Usage:${NC}"
        echo "  $0 start  - Begin monitoring auth.log"
        echo "  $0 stop   - Terminate monitoring"
        echo -e "\n${MED}Customized for Kali's offensive security role${NC}"
        ;;
esac
