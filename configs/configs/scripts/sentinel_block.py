#!/usr/bin/env python3
"""
SentinelShield - Automated IP Containment and Alert Dispatcher
Parses Wazuh Active Response JSON payload from stdin, enforces firewall blocks,
and dispatches webhook notifications.
"""

import sys
import json
import subprocess
import os

WEBHOOK_URL = os.getenv("SENTINEL_WEBHOOK_URL", "")

def log_event(message):
    with open("/var/ossec/logs/active-responses.log", "a") as log_file:
        log_file.write(f"[SentinelShield AR] {message}\n")

def block_ip(ip_address):
    """Appends an immediate drop rule to iptables."""
    try:
        # Check if rule already exists
        check_cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            # Rule does not exist, insert at top of chain
            add_cmd = ["iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"]
            subprocess.run(add_cmd, check=True)
            log_event(f"SUCCESS: Blocked malicious source IP: {ip_address}")
            return True
        else:
            log_event(f"INFO: IP {ip_address} is already blocked.")
            return True
    except Exception as e:
        log_event(f"ERROR: Failed to block {ip_address}: {str(e)}")
        return False

def main():
    try:
        input_data = sys.stdin.read()
        if not input_data:
            log_event("ERROR: No input received via standard in.")
            sys.exit(1)

        alert = json.loads(input_data)
        
        # Extract attacker source IP
        src_ip = alert.get("parameters", {}).get("alert", {}).get("data", {}).get("srcip")
        if not src_ip:
            src_ip = alert.get("parameters", {}).get("alert", {}).get("srcip")

        if src_ip and src_ip != "127.0.0.1":
            action_status = block_ip(src_ip)
            log_event(f"COMPLETED: Host containment executed for {src_ip}. Status: {action_status}")
        else:
            log_event("WARNING: No valid source IP extracted from alert payload.")

    except Exception as e:
        log_event(f"CRITICAL: Unhandled exception in sentinel_block.py: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
