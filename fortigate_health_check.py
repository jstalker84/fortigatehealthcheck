#!/usr/bin/env python3

import paramiko
import getpass
import re
import time
import logging
import argparse
import json
import csv
import concurrent.futures
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime
from colorama import init, Fore, Style
import sys
from pathlib import Path
import configparser
import os
from enum import Enum
import ipaddress # Added for IP validation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.textlabels import Label

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fortigate_health_check.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Severity Levels
class SeverityLevel(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self):
        return self.value

# FortiGate CLI Commands
FORTIGATE_CLI_COMMANDS = {
    # System Status & Basic Info
    "system_status": "get system status",
    "performance_status": "get system performance status", # Includes overall CPU, memory, conserve mode
    "license_status_basic": "get system status", # For basic license status from system_status parser
    "detailed_license_status": "get system forticare", # For more detailed license parsing, if available
    "ha_status": "get system ha status",
    "interface_status": "get system interface", # General interface config
    "interface_health": "diagnose hardware deviceinfo nic", # Detailed physical NIC status
    # "interface_errors": "diagnose hardware deviceinfo nic-errors", # Often covered by `nic` or specific interface stats
    # "interface_stats": "diagnose hardware deviceinfo nic-stats", # Often covered by `nic`
    "routing_table": "get router info routing-table all",
    
    # Memory and Resource Usage
    "top_memory_processes": "diagnose sys top-mem 10", # Changed from memory_usage to be specific
    "disk_usage": "diagnose sys df", # Changed from diagnose hardware sysinfo disk
    "top_cpu_processes": "diagnose sys top -n 10", # Changed from process_list for clarity, using -n 10
    "session_usage": "diagnose sys session stat",
    "log_disk_status": "diagnose log disk status", # Corrected command
    
    # Security Status
    "antivirus_status": "get antivirus status", # Corrected command
    "ips_status": "get ips status", # Corrected command
    "webfilter_status": "get webfilter status", # Corrected command
    "application_control_status": "get application-control status", # Corrected for status
    "firewall_policy_summary": "get firewall policy stats", # For a summary, actual listing is too verbose
    
    # VPN Status
    "vpn_ssl_settings": "get vpn ssl settings", # Renamed from vpn_ssl
    "vpn_ssl_stats": "diagnose vpn ssl stats",
    "vpn_ipsec_summary": "get vpn ipsec tunnel summary", # Renamed from vpn_ipsec
    
    # System Services
    "dns_status": "diagnose test application dnsproxy 7", # More specific DNS test
    "ntp_status": "diagnose sys ntp status",
    "fortiguard_status": "diagnose sys fortiguard status", # Used by license_fortiguard parser
    
    # Hardware Health
    "hardware_health": "diagnose hardware deviceinfo health",
    "ha_checksum_status": "diagnose sys ha checksum show", 
    
    # System Logs (Keep these simple, parsing logs is complex)
    # "system_log": "diagnose sys log last 10", # Log parsing is out of scope for now
    
    # Additional Security Checks
    "local_certificates": "get system certificate local", # Renamed from ssl_certificates
    "firmware_status": "get system status | grep Version", # More focused on firmware version
    "update_status": "diagnose autoupdate versions" # More comprehensive update status
}

class FortiGateHealthCheck:
    def __init__(self, max_retries: int = 3, retry_delay: int = 5):
        self.jumphost_client: Optional[paramiko.SSHClient] = None
        self.fortigate_shell: Optional[paramiko.Channel] = None
        self.direct_connection: bool = False
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.detected_prompt: Optional[str] = None
        self.PARSER_MAPPING = {
            "system_status": self.parse_system_status,                 # Uses 'get system status'
            "performance_status": self.parse_performance_status,       # Uses 'get system performance status'
            "detailed_license_status": self.parse_license_status,     # Uses 'get system forticare' 
            "fortiguard_status": self.parse_fortiguard_status,         # Uses 'diagnose sys fortiguard status'
            "local_certificates": self.parse_ssl_certificates,          # Uses 'get system certificate local'
            "vpn_ssl_settings": self.parse_ssl_vpn_certificates,      # Uses 'get vpn ssl settings'
            "interface_health": self.parse_interface_health,            # Uses 'diagnose hardware deviceinfo nic'
            "routing_table": self.parse_routing_table,                # Uses 'get router info routing-table all'
            "top_memory_processes": self.parse_memory_usage,          # Uses 'diagnose sys top-mem 10'
            "disk_usage": self.parse_disk_usage,                      # Uses 'diagnose sys df'
            "top_cpu_processes": self.parse_process_list,             # Uses 'diagnose sys top -n 10'
            "ha_checksum_status": self.parse_ha_checksum_status,        # Uses 'diagnose sys ha checksum show'
            
            # Security services using the generic parse_security_status
            "antivirus_status": lambda output: self.parse_security_status(output, "av_stats"),
            "ips_status": lambda output: self.parse_security_status(output, "ips_stats"),
            "webfilter_status": lambda output: self.parse_security_status(output, "webfilter_stats"),
            "application_control_status": lambda output: self.parse_security_status(output, "appcontrol_status"),
            # "update_status": lambda output: self.parse_security_status(output, "update_status"), # Uses diagnose autoupdate versions
            # Potentially add more if their output is simple key-value pairs suitable for parse_security_status
            # For example, if "firmware_status" output can be parsed this way:
            # "firmware_status": lambda output: self.parse_security_status(output, "firmware_info") 
        }

    def connect_with_retry(self, connect_func, *args, **kwargs) -> bool:
        """Execute a connection function with retry logic."""
        for attempt in range(self.max_retries):
            try:
                if connect_func(*args, **kwargs):
                    return True
            except Exception as e:
                if attempt < self.max_retries - 1:
                    logger.warning(f"Connection attempt {attempt + 1} failed: {str(e)}. Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"All connection attempts failed: {str(e)}")
        return False

    def connect_to_jumphost(self, hostname: str, username: str, password: str, verification_code: str = None) -> bool:
        """Establish SSH connection to jumphost."""
        try:
            logger.info(f"Connecting to jumphost {hostname}...")
            self.jumphost_client = paramiko.SSHClient()
            self.jumphost_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.jumphost_client.connect(
                hostname=hostname,
                username=username,
                password=password,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Handle verification code if provided
            if verification_code:
                logger.info("Sending verification code...")
                shell = self.jumphost_client.invoke_shell()
                time.sleep(2)  # Wait for prompt
                shell.send(f"{verification_code}\n")
                time.sleep(2)
                output = shell.recv(65535).decode('utf-8', errors='replace')
                if "verification failed" in output.lower():
                    logger.error("Verification code was incorrect")
                    return False
                shell.close()
            
            logger.info("Successfully connected to jumphost")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to jumphost: {str(e)}")
            return False

    def connect_direct_to_fortigate(self, hostname: str, username: str, password: str) -> bool:
        """Establish direct SSH connection to FortiGate and detect prompt."""
        try:
            logger.info(f"Connecting directly to FortiGate {hostname}...")
            self.jumphost_client = paramiko.SSHClient()
            self.jumphost_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.jumphost_client.connect(
                hostname=hostname,
                username=username,
                password=password,
                look_for_keys=False,
                allow_agent=False,
                timeout=15
            )
            self.fortigate_shell = self.jumphost_client.invoke_shell()
            self.direct_connection = True
            
            # Attempt to detect the prompt
            time.sleep(2)
            initial_output = ""
            if self.fortigate_shell.recv_ready():
                initial_output = self.fortigate_shell.recv(65535).decode('utf-8', errors='replace')
            
            # Crude prompt detection: last non-empty line ending with # or $
            lines = [line.strip() for line in initial_output.splitlines() if line.strip()]
            if lines:
                potential_prompt = lines[-1]
                if potential_prompt.endswith(('# ', '$ ', '> ')):
                    self.detected_prompt = potential_prompt
                    logger.info(f"Detected FortiGate prompt: {self.detected_prompt}")
                else:
                    logger.warning(f"Could not reliably detect prompt from initial output: {potential_prompt}. Falling back to generic prompt.")
            else:
                logger.warning("No initial output received to detect prompt. Using default detection in execute_command.")

            logger.info("Successfully connected to FortiGate")
            return True
        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for FortiGate {hostname}.")
            return False
        except paramiko.SSHException as ssh_ex:
            logger.error(f"SSH connection error for FortiGate {hostname}: {str(ssh_ex)}")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to FortiGate {hostname}: {str(e)}")
            return False

    def connect_to_fortigate(self, hostname: str, username: str, password: str) -> bool:
        """Establish SSH connection to FortiGate through jumphost and detect prompt."""
        if self.direct_connection:
            return True

        try:
            if not self.jumphost_client or not self.jumphost_client.get_transport() or not self.jumphost_client.get_transport().is_active():
                logger.error("Jumphost connection not established or active.")
                return False

            logger.info(f"Connecting to FortiGate {hostname} via jumphost...")
            self.fortigate_shell = self.jumphost_client.invoke_shell()
            
            time.sleep(1)
            if self.fortigate_shell.recv_ready():
                self.fortigate_shell.recv(65535)

            self.fortigate_shell.send(f'ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa {username}@{hostname}\n')
            
            output_buffer = ""
            timeout_seconds = 15
            start_time = time.time()
            
            while time.time() - start_time < timeout_seconds:
                if self.fortigate_shell.recv_ready():
                    chunk = self.fortigate_shell.recv(1024).decode('utf-8', errors='replace')
                    output_buffer += chunk
                    if "password:" in output_buffer.lower():
                        self.fortigate_shell.send(f"{password}\n")
                        break
                    if re.search(r"[\w.-]+(#|>|\$) $", output_buffer.splitlines()[-1] if output_buffer.splitlines() else ""):
                        break 
                time.sleep(0.2)
            
            if "password:" not in output_buffer.lower() and not (self.fortigate_shell.recv_ready() or re.search(r"[\w.-]+(#|>|\$) $", output_buffer.splitlines()[-1] if output_buffer.splitlines() else "")):
                time.sleep(1)
                if self.fortigate_shell.recv_ready():
                     output_buffer += self.fortigate_shell.recv(65535).decode('utf-8', errors='replace')

                if "password:" in output_buffer.lower():
                     self.fortigate_shell.send(f"{password}\n")
                elif "permission denied" in output_buffer.lower() or "authentication failed" in output_buffer.lower():
                    logger.error(f"FortiGate authentication failed for {username}@{hostname} via jumphost: Permission denied.")
                    return False
            
            time.sleep(2) 
            login_confirmation_output = ""
            read_attempts = 0
            while read_attempts < 5 and not self.detected_prompt:
                if self.fortigate_shell.recv_ready():
                    chunk = self.fortigate_shell.recv(65535).decode('utf-8', errors='replace')
                    login_confirmation_output += chunk
                    lines = [line.strip() for line in login_confirmation_output.splitlines() if line.strip()]
                    if lines:
                        potential_prompt = lines[-1]
                        prompt_regex = r"([\w\.-]+(\(\S+\))?\s?[#\$>]\s*$)" 
                        match = re.search(prompt_regex, potential_prompt)
                        if match:
                            self.detected_prompt = match.group(1)
                            logger.info(f"Detected FortiGate prompt via jumphost: {self.detected_prompt}")
                            break 
                time.sleep(0.5)
                read_attempts +=1

            if not self.detected_prompt:
                logger.warning(f"Could not reliably detect prompt for {hostname} via jumphost. Using fallback. Output: {login_confirmation_output[-200:]}")
                lines = [line.strip() for line in login_confirmation_output.splitlines() if line.strip()]
                if lines and lines[-1].endswith(('# ', '$ ', '> ')):
                    self.detected_prompt = lines[-1]
                    logger.info(f"Fallback prompt detection: {self.detected_prompt}")
                else:
                    self.detected_prompt = f"{hostname} #"
                    logger.warning(f"Using generic fallback prompt: {self.detected_prompt}")

            if "login incorrect" in login_confirmation_output.lower() or \
               "authentication failed" in login_confirmation_output.lower() or \
               ("login:" in login_confirmation_output.lower() and not username in login_confirmation_output):
                logger.error(f"Failed to authenticate with FortiGate {hostname} via jumphost.")
                return False
                
            logger.info(f"Successfully connected to FortiGate {hostname} via jumphost.")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to FortiGate {hostname} via jumphost: {str(e)}")
            if self.fortigate_shell:
                self.fortigate_shell.close()
            self.fortigate_shell = None
            return False

    def execute_command(self, command: str, timeout: int = 10) -> str:
        """Execute a command on the FortiGate and return the output."""
        if not self.fortigate_shell:
            raise Exception("FortiGate connection not established")

        try:
            while self.fortigate_shell.recv_ready():
                self.fortigate_shell.recv(65535)

            self.fortigate_shell.send(f"{command}\n")
            
            output = ""
            start_time = time.time()
            
            buffer = ""
            command_sent_time = time.time()

            while time.time() - start_time < timeout:
                if self.fortigate_shell.recv_ready():
                    chunk = self.fortigate_shell.recv(4096).decode('utf-8', errors='replace')
                    buffer += chunk
                    
                    normalized_buffer = buffer.replace('\\r\\n', '\\n').replace('\\r', '\\n')
                    
                    lines = normalized_buffer.split('\\n')
                    
                    last_line_stripped = lines[-1].strip() if lines and lines[-1].strip() else (lines[-2].strip() if len(lines) > 1 and lines[-2].strip() else None)

                    if self.detected_prompt and last_line_stripped == self.detected_prompt.strip():
                        if normalized_buffer.strip().startswith(command):
                            output_after_command = normalized_buffer.strip()[len(command):].strip()
                            if output_after_command.endswith(self.detected_prompt.strip()):
                                output = output_after_command[:-len(self.detected_prompt.strip())].strip()
                            else:
                                output = output_after_command
                        else:
                            if normalized_buffer.strip().endswith(self.detected_prompt.strip()):
                                output = normalized_buffer.strip()[:-len(self.detected_prompt.strip())].strip()
                            else:
                                output = normalized_buffer.strip()
                        
                        if not output.strip() and buffer.strip() != self.detected_prompt.strip():
                             output = buffer
                        
                        if "--More--" in last_line_stripped or "--More--" in output:
                            output = output.replace("--More--", "").strip()
                            self.fortigate_shell.send(" ")
                        else:
                            break
                    elif time.time() - command_sent_time > 2 and not self.fortigate_shell.recv_ready() and not self.detected_prompt: 
                        logger.debug(f"No new data and no prompt detected for command {repr(command)}, assuming completion.")
                        output = buffer 
                        break
                        
                time.sleep(0.1)
            
            if not output.strip() and buffer.strip():
                output = buffer
            
            if self.detected_prompt and output.endswith(self.detected_prompt.strip()):
                output = output[:-len(self.detected_prompt.strip())].strip()
            
            if output.startswith(command):
                output = output[len(command):].strip()
                
            return output.strip()

        except Exception as e:
            logger.error(f"Error executing command '{command}': {str(e)}")
            return f"Error executing command: {str(e)}"

    def execute_commands_concurrent(self, commands: Dict[str, str], max_workers: int = 1) -> Dict[str, str]:
        """Execute multiple commands. Concurrency set to 1 for prompt stability."""
        if max_workers > 1:
            logger.warning("Setting max_workers to 1 for execute_commands_concurrent due to interactive shell prompt detection. True concurrency would require separate channels.")
            max_workers = 1
            
        results = {}
        
        def execute_single_command(cmd_name: str, cmd: str) -> Tuple[str, str]:
            try:
                output = self.execute_command(cmd)
                return cmd_name, output
            except Exception as e:
                logger.error(f"Error executing {cmd_name}: {str(e)}")
                return cmd_name, ""

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_cmd = {
                executor.submit(execute_single_command, name, cmd): name
                for name, cmd in commands.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_cmd):
                cmd_name, output = future.result()
                results[cmd_name] = output
                
        return results

    def setup_fortigate_session(self) -> bool:
        """Configure FortiGate session settings."""
        try:
            logger.info("Setting up FortiGate session...")
            self.execute_command("config system console")
            self.execute_command("set output standard")
            self.execute_command("end")
            logger.info("FortiGate session configured successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to setup FortiGate session: {str(e)}")
            return False

    def parse_system_status(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'get system status' command."""
        data = {
            "check_name": "System Status",
            "findings": [],
            "raw_output": output,
            "overall_status": SeverityLevel.INFO
        }
        parsed_metrics = {}

        # Firmware Version
        version_match = re.search(r"Version:\s+FortiOS[^\n]+", output)
        if version_match:
            parsed_metrics['firmware_version'] = version_match.group(0).split(':', 1)[1].strip()
            data["findings"].append({
                "description": "Firmware Version",
                "value": parsed_metrics['firmware_version'],
                "severity": SeverityLevel.INFO
            })
        else:
            data["findings"].append({"description": "Firmware Version", "value": "Not found", "severity": SeverityLevel.MEDIUM})

        # License Status
        license_match = re.search(r"License Status:\s+(\w+)", output)
        if license_match:
            status = license_match.group(1)
            parsed_metrics['license_status'] = status
            sev = SeverityLevel.INFO if status.lower() == 'valid' else SeverityLevel.CRITICAL
            if sev == SeverityLevel.CRITICAL: data["overall_status"] = SeverityLevel.CRITICAL
            data["findings"].append({
                "description": "License Status",
                "value": status,
                "severity": sev,
                "recommendation": "If license is invalid or expired, renew it immediately to ensure full functionality and support."
            })
        else:
            data["findings"].append({"description": "License Status", "value": "Not found", "severity": SeverityLevel.MEDIUM})
            if data["overall_status"] != SeverityLevel.CRITICAL: data["overall_status"] = SeverityLevel.MEDIUM
        
        # System Time
        time_match = re.search(r"System Time:\s+([^\n]+)", output)
        if time_match:
            parsed_metrics['system_time'] = time_match.group(1)
            data["findings"].append({
                "description": "System Time",
                "value": parsed_metrics['system_time'],
                "severity": SeverityLevel.INFO
            })
        else:
            data["findings"].append({"description": "System Time", "value": "Not found", "severity": SeverityLevel.LOW})

        # Hostname (Example, regex might need adjustment)
        hostname_match = re.search(r"Hostname:\s*(\S+)", output, re.IGNORECASE)
        if hostname_match:
            parsed_metrics['hostname'] = hostname_match.group(1)
            data["findings"].append({"description": "Hostname", "value": parsed_metrics['hostname'], "severity": SeverityLevel.INFO})
        
        # Model (Example)
        model_match = re.search(r"BIOS version:\s*(\S+)\n", output) # Often BIOS version implies model indirectly or model is elsewhere
        # A more direct model regex would be better if available in 'get system status'
        # For instance: re.search(r"FortiGate-(\w+)\", output) or r"Model Name:\s*(.*)\"
        if model_match: # This is a placeholder, adjust regex for actual model info if present
            parsed_metrics['model_inferred'] = model_match.group(1) 
            data["findings"].append({"description": "Device Model (Inferred from BIOS)", "value": parsed_metrics['model_inferred'], "severity": SeverityLevel.INFO})

        # Serial Number
        serial_match = re.search(r"Serial Number:\s*(\S+)", output, re.IGNORECASE)
        if serial_match:
            parsed_metrics['serial_number'] = serial_match.group(1)
            data["findings"].append({"description": "Serial Number", "value": parsed_metrics['serial_number'], "severity": SeverityLevel.INFO})

        # HA Status (Basic from system status)
        ha_match = re.search(r"Current HA mode:\s*(.*?)(?:\n|$)", output, re.IGNORECASE) # Corrected regex
        if ha_match:
            ha_mode = ha_match.group(1).strip()
            parsed_metrics['ha_mode'] = ha_mode
            sev = SeverityLevel.INFO if 'standalone' not in ha_mode.lower() else SeverityLevel.INFO # Or warn if expected to be in HA
            data["findings"].append({"description": "HA Mode", "value": ha_mode, "severity": sev})
        
        # Conserve Mode (from 'get system performance status', but sometimes mentioned in 'get system status')
        conserve_mode_match = re.search(r"System is in conserve mode!", output, re.IGNORECASE)
        if conserve_mode_match:
            parsed_metrics['conserve_mode_status'] = "Active"
            data["findings"].append({
                "description": "Conserve Mode",
                "value": "Active",
                "severity": SeverityLevel.CRITICAL,
                "recommendation": "System is in conserve mode due to high resource usage. Investigate immediately."
            })
            data["overall_status"] = SeverityLevel.CRITICAL
        else:
             # Check if system status indicates it's NOT in conserve mode, if output format supports it
            not_conserve_match = re.search(r"System is not in conserve mode", output, re.IGNORECASE)
            if not_conserve_match:
                parsed_metrics['conserve_mode_status'] = "Inactive"
                data["findings"].append({"description": "Conserve Mode", "value": "Inactive", "severity": SeverityLevel.INFO})

        # Add parsed metrics to the main data dictionary for easier access if needed elsewhere
        data['parsed_metrics'] = parsed_metrics
        return data

    def parse_performance_status(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'get system performance status' command."""
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_metrics = {}
        recommendations = {
            "cpu_high": "CPU usage is high. Investigate processes consuming high CPU resources. Consider optimizing configurations or upgrading hardware if consistently high.",
            "memory_high": "Memory usage is high. Investigate processes consuming high memory. Check for memory leaks or consider a hardware upgrade.",
            "conserve_mode": "System is in conserve mode. This indicates critical resource exhaustion (usually memory). Investigate immediately to prevent service disruption. Identify and stop resource-intensive processes or reboot if necessary."
        }

        # CPU Usage
        cpu_match = re.search(r"CPU states:\s*\d+%\s*user\s*\d+%\s*system\s*\d+%\s*nice\s*(\d+)%\s*idle", output)
        if cpu_match:
            cpu_idle = int(cpu_match.group(1))
            cpu_usage = 100 - cpu_idle
            parsed_metrics['cpu_usage'] = cpu_usage
            parsed_metrics['cpu_idle'] = cpu_idle
            
            sev = SeverityLevel.INFO
            rec = None
            if cpu_usage >= 90:
                sev = SeverityLevel.CRITICAL
                rec = recommendations["cpu_high"]
            elif cpu_usage >= 75:
                sev = SeverityLevel.HIGH
                rec = recommendations["cpu_high"]
            elif cpu_usage >= 60:
                sev = SeverityLevel.MEDIUM
            
            findings.append({
                "description": "CPU Usage", 
                "value": f"{cpu_usage}% (Idle: {cpu_idle}%)", 
                "severity": sev,
                "recommendation": rec
            })
            if sev > overall_status: overall_status = sev
        else:
            findings.append({"description": "CPU Usage", "value": "Not found", "severity": SeverityLevel.MEDIUM})
            if SeverityLevel.MEDIUM > overall_status: overall_status = SeverityLevel.MEDIUM
        
        # Memory Usage
        memory_match = re.search(r"Memory:\s*(\d+)%\s*used", output)
        if memory_match:
            memory_usage_percent = int(memory_match.group(1))
            parsed_metrics['memory_usage_percent'] = memory_usage_percent

            sev = SeverityLevel.INFO
            rec = None
            if memory_usage_percent >= 90:
                sev = SeverityLevel.CRITICAL
                rec = recommendations["memory_high"]
            elif memory_usage_percent >= 75:
                sev = SeverityLevel.HIGH
                rec = recommendations["memory_high"]
            elif memory_usage_percent >= 60:
                sev = SeverityLevel.MEDIUM

            findings.append({
                "description": "Memory Usage", 
                "value": f"{memory_usage_percent}% used", 
                "severity": sev,
                "recommendation": rec
            })
            if sev > overall_status: overall_status = sev
        else:
            findings.append({"description": "Memory Usage", "value": "Not found", "severity": SeverityLevel.MEDIUM})
            if SeverityLevel.MEDIUM > overall_status: overall_status = SeverityLevel.MEDIUM
        
        # Conserve Mode
        conserve_match = re.search(r"memory-conserve-mode:\s*(\d)", output)
        conserve_mode_value = "Not found"
        conserve_sev = SeverityLevel.MEDIUM
        conserve_rec = None

        if conserve_match:
            mode_map = {"0": "Normal", "1": "Conserve", "2": "Extreme Conserve"}
            conserve_mode_value = mode_map.get(conserve_match.group(1), "Unknown")
            parsed_metrics['conserve_mode'] = conserve_mode_value
            
            if conserve_mode_value == "Conserve":
                conserve_sev = SeverityLevel.HIGH
                conserve_rec = recommendations["conserve_mode"]
            elif conserve_mode_value == "Extreme Conserve":
                conserve_sev = SeverityLevel.CRITICAL
                conserve_rec = recommendations["conserve_mode"]
            elif conserve_mode_value == "Normal":
                conserve_sev = SeverityLevel.INFO
            else: # Unknown
                conserve_sev = SeverityLevel.MEDIUM
        
        findings.append({
            "description": "Memory Conserve Mode", 
            "value": conserve_mode_value, 
            "severity": conserve_sev,
            "recommendation": conserve_rec
        })
        if conserve_sev > overall_status: overall_status = conserve_sev
        
        return {
            "check_name": "Performance Status",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "parsed_metrics": parsed_metrics
        }

    def parse_license_status(self, output: str) -> Dict[str, Any]: # Assumes output from a detailed license command
        """Parse the output of license status commands (e.g., FortiCare, specific service licenses)."""
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_licenses = {}

        # This parser is generic. Actual parsing logic depends heavily on the specific license command output.
        # Example: Looking for lines like "Service: FortiGuard AV, Status: Licensed, Expiry: 2024-12-31"
        # For now, we will assume a simple structure from a hypothetical detailed command or `get system fortiguard` (old command).
        # The `get system status` gives a general license status, this one might be for more details.

        # Regex for a common pattern: "Description   : Value" or "Description: Value"
        for line in output.splitlines():
            line = line.strip()
            if not line: continue

            # Try to match common license attributes
            # This is highly dependent on the actual command output for detailed licenses.
            # This is a placeholder for more specific regexes based on actual command.
            service_match = re.search(r"(?:Service|License Type|Contract Number|Account ID):\s*(.*)", line, re.IGNORECASE)
            status_match = re.search(r"Status:\s*(.*)", line, re.IGNORECASE)
            expiry_match = re.search(r"(?:Expires On|Expiration Date|Expiry):\s*(.*)", line, re.IGNORECASE)
            
            # Rudimentary way to group, assuming one license per block or clearly defined attributes
            # This will likely need significant adjustment based on actual command output.
            if service_match:
                service_name = service_match.group(1).strip()
                if service_name not in parsed_licenses: parsed_licenses[service_name] = {}
                current_service_findings = []
                current_overall_sev = SeverityLevel.INFO

                # Look for status and expiry for this service in subsequent lines or same line if format allows
                # This is a simplified example. Real output might require block parsing.
                temp_status = "Not found"
                temp_expiry = "Not found"
                days_remaining_str = "N/A"
                sev = SeverityLevel.INFO
                rec = None

                # Check the current line itself for status/expiry if it also matched service
                if status_match and service_match.string == status_match.string: # if status is on the same line
                    temp_status = status_match.group(1).strip()
                if expiry_match and service_match.string == expiry_match.string:
                    temp_expiry = expiry_match.group(1).strip()
                
                # This is where more robust parsing for multi-line entries would go.
                # For now, we'll assume a simple case where details are found quickly.

                if temp_status.lower() not in ["licensed", "valid", "active", "registered"]:
                    sev = SeverityLevel.HIGH if temp_status.lower() == "unreachable" else SeverityLevel.CRITICAL
                    rec = f"The license for '{service_name}' is '{temp_status}'. Please investigate and renew/fix immediately."
                
                if temp_expiry != "Not found" and temp_expiry.lower() != "n/a":
                    try:
                        exp_date = datetime.strptime(temp_expiry, '%Y-%m-%d') # Common format
                        days_remaining = (exp_date - datetime.now()).days
                        days_remaining_str = f"{days_remaining} days"
                        if days_remaining <= 0:
                            sev = max(sev, SeverityLevel.CRITICAL)
                            rec = f"License for '{service_name}' has expired. Renew immediately."
                        elif days_remaining <= 30:
                            sev = max(sev, SeverityLevel.HIGH)
                            rec = f"License for '{service_name}' expires in {days_remaining} days. Plan renewal."
                        elif days_remaining <= 90:
                            sev = max(sev, SeverityLevel.MEDIUM)
                    except ValueError:
                        # Try other common date formats if needed
                        pass 
                
                findings.append({
                    "description": f"License: {service_name}",
                    "value": f"Status: {temp_status}, Expiry: {temp_expiry} (Remaining: {days_remaining_str})",
                    "severity": sev,
                    "recommendation": rec
                })
                if sev > overall_status: overall_status = sev
        
        if not findings: # If no specific licenses parsed, add a generic note
            findings.append({"description": "Detailed License Information", "value": "No specific license details parsed. Output might be empty or in an unrecognized format.", "severity": SeverityLevel.INFO})

        return {
            "check_name": "Detailed License Status",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output
        }

    def parse_fortiguard_status(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'diagnose sys fortiguard status' command."""
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_metrics = {}
        recommendations = {
            "unreachable": "FortiGuard services are unreachable. Check internet connectivity, DNS resolution, and firewall policies allowing FortiGuard communication (typically TCP/UDP 443, 53, 8888).",
            "not_licensed": "A FortiGuard service is reported as not licensed. Verify your FortiCare contract and ensure licenses are active and applied.",
            "update_failed": "A FortiGuard database update has failed. Check connectivity and for error messages in logs. Manual update might be required.",
            "old_db": "A FortiGuard database is significantly outdated. Ensure automatic updates are working or perform a manual update."
        }

        # FortiGuard Service Status (Overall reachability)
        service_status_match = re.search(r"FortiGuard\s+Service\s+Status:\s*(.*)", output, re.IGNORECASE)
        if service_status_match:
            status_val = service_status_match.group(1).strip()
            parsed_metrics['overall_service_status'] = status_val
            sev = SeverityLevel.INFO
            rec = None
            if status_val.lower() != "connected" and "available" not in status_val.lower(): # Checking for variations like "Connected via FortiManager"
                sev = SeverityLevel.CRITICAL
                rec = recommendations["unreachable"]
            findings.append({
                "description": "FortiGuard Overall Service Status",
                "value": status_val,
                "severity": sev,
                "recommendation": rec
            })
            if sev > overall_status: overall_status = sev
        else:
            findings.append({"description": "FortiGuard Overall Service Status", "value": "Not found", "severity": SeverityLevel.MEDIUM})
            if SeverityLevel.MEDIUM > overall_status: overall_status = SeverityLevel.MEDIUM

        # Account Status (Example, if present)
        account_status_match = re.search(r"Account\s+Status\s*:\s*(.*)", output, re.IGNORECASE)
        if account_status_match:
            status_val = account_status_match.group(1).strip()
            parsed_metrics['account_status'] = status_val
            sev = SeverityLevel.INFO
            rec = None
            if status_val.lower() != "licensed" and status_val.lower() != "registered":
                sev = SeverityLevel.HIGH
                rec = recommendations["not_licensed"]
            findings.append({
                "description": "FortiGuard Account Status",
                "value": status_val,
                "severity": sev,
                "recommendation": rec
            })
            if sev > overall_status: overall_status = sev

        # Last Update and Version for various services (AV, IPS, etc.)
        # This pattern is more for `diagnose autoupdate versions` but some info might be in `diag sys fortiguard status`
        db_services = ["AntiVirus", "IPS Attack", "IPS Malicious URL", "Application Control", "Web Filtering", "AntiSpam"]
        for service_name in db_services:
            # Search for a block related to the service
            service_block_match = re.search(fr"{service_name}\s*Definitions(?:\s*:(.*?))?(?:\n\s*Version:\s*(.*?))?(?:\n\s*Last\s*Updated:\s*(.*?))?", output, re.IGNORECASE | re.DOTALL)
            
            if service_block_match:
                version = service_block_match.group(2).strip() if service_block_match.group(2) else "N/A"
                last_update_str = service_block_match.group(3).strip() if service_block_match.group(3) else "N/A"
                parsed_metrics[f'{service_name.lower().replace(" ", "_")}_version'] = version
                parsed_metrics[f'{service_name.lower().replace(" ", "_")}_last_update'] = last_update_str

                sev = SeverityLevel.INFO
                rec = None
                # Check last update time (example: if older than 7 days)
                if last_update_str != "N/A":
                    try:
                        # FortiGuard dates can be like "Mon Jan 1 12:00:00 2023" or "YYYY-MM-DD HH:MM:SS"
                        # Trying a common one first
                        try:
                            update_dt = datetime.strptime(last_update_str, '%a %b %d %H:%M:%S %Y')
                        except ValueError:
                            update_dt = datetime.strptime(last_update_str, '%Y-%m-%d %H:%M:%S') # Try another format
                        
                        if (datetime.now() - update_dt).days > 7:
                            sev = SeverityLevel.MEDIUM
                            rec = recommendations["old_db"]
                        if (datetime.now() - update_dt).days > 30: # Even older
                            sev = SeverityLevel.HIGH
                            rec = recommendations["old_db"]
                    except ValueError:
                        sev = SeverityLevel.LOW # Cannot parse date, just informational
                else: # Last update N/A
                    sev = SeverityLevel.LOW
                
                findings.append({
                    "description": f"{service_name} Definitions",
                    "value": f"Version: {version}, Last Updated: {last_update_str}",
                    "severity": sev,
                    "recommendation": rec
                })
                if sev > overall_status: overall_status = sev
        
        # Fallback for other lines if any specific pattern is missed (e.g. specific DB versions)
        # This part can be expanded with more regexes for specific fields if needed.

        return {
            "check_name": "FortiGuard Status",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "parsed_metrics": parsed_metrics
        }

    def parse_ha_checksum_status(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'diagnose sys ha checksum show' command."""
        findings = []
        overall_status = SeverityLevel.INFO
        recommendation = "Ensure configurations are synchronized across HA members."

        if "The HA checksums are different" in output:
            overall_status = SeverityLevel.HIGH
            findings.append({
                "description": "HA checksums are different between HA members.",
                "severity": SeverityLevel.HIGH,
                "recommendation": "Configuration is not synchronized. Investigate and synchronize HA cluster.",
                "details": output # Full output for details
            })
        elif "The HA checksums are the same" in output:
            findings.append({
                "description": "HA checksums are the same.",
                "severity": SeverityLevel.INFO,
                "details": "Configurations appear synchronized."
            })
        elif "This system is not in HA mode" in output:
            overall_status = SeverityLevel.INFO # Not an error, just informational
            findings.append({
                "description": "System is not in HA mode.",
                "severity": SeverityLevel.INFO,
                "details": "HA checksum command is not applicable."
            })
            recommendation = "N/A (System not in HA mode)"
        else:
            overall_status = SeverityLevel.MEDIUM # Unknown output
            findings.append({
                "description": "Could not determine HA checksum status from output.",
                "severity": SeverityLevel.MEDIUM,
                "recommendation": "Review raw output to determine HA checksum status manually.",
                "details": output
            })

        return {
            "check_name": "HA Checksum Status",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "recommendation": recommendation
        }

    def parse_ssl_certificates(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'get system certificate local' command."""
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_certs = [] # List to store details of each parsed certificate

        # FortiOS `get system certificate local` output is a list of `config system certificate local` blocks.
        # Each certificate entry starts with `edit "<cert_name>"` and ends with `next`.
        # We need to process it block by block.

        # Split the output by 'edit ' which usually precedes the certificate name block
        # This is a common way FortiOS configuration is dumped.
        # Add a common starting pattern to help split, like "config system certificate local"
        if not output.strip().startswith("config system certificate local"):
            # If the command output doesn't have the expected header, we might be looking at a different format.
            # For now, assume it might be just the blocks.
            pass # Continue with current block splitting logic

        # A more robust way is to find `edit "cert_name"` blocks
        # Regex to find individual certificate blocks: edit "name" ... next
        cert_blocks_matches = re.finditer(r"edit\s+\"(?P<name>[^\"]+)\"(?P<content>.*?)(?:next|end)(?=\s*(?:edit\s+\"|$))", output, re.DOTALL | re.IGNORECASE)
        
        for match in cert_blocks_matches:
            cert_name = match.group("name")
            content = match.group("content")
            
            cert_details = {"name": cert_name, "issuer": "N/A", "subject": "N/A", 
                            "valid_from": "N/A", "valid_to": "N/A", "status": "Unknown"}
            days_remaining_str = "N/A"
            sev = SeverityLevel.INFO
            rec = None

            # Extract details from the content block
            issuer_match = re.search(r"set\s+issuer\s+\"(.*?)\"", content, re.IGNORECASE)
            if issuer_match: cert_details["issuer"] = issuer_match.group(1)
            
            subject_match = re.search(r"set\s+subject\s+\"(.*?)\"", content, re.IGNORECASE)
            if subject_match: cert_details["subject"] = subject_match.group(1)
            
            # The actual validity dates are usually not in `get system certificate local` directly.
            # That command shows configuration. `diagnose vpn certificate local details <name>` would show dates.
            # For now, we'll mark them as N/A from this command, unless a format is found.
            # However, some FortiOS versions might show it under `diagnose hardware sysinfo cert` or similar.
            # This parser is specific to `get system certificate local`.
            # If the output contains validity, regexes would be added here.
            # E.g. valid_from_match = re.search(r"Valid From:\s*(.*)", content)

            # Since `get system certificate local` doesn't show expiry, we can't assess it here directly.
            # This finding is more informational about its presence.
            sev = SeverityLevel.INFO # Default for just listing configured certs
            cert_details["status"] = "Configured"
            
            # Placeholder if expiry date was found in some versions of the command output:
            # if cert_details["valid_to"] != "N/A":
            #     try:
            #         exp_date = datetime.strptime(cert_details["valid_to"], '%b %d %H:%M:%S %Y GMT') # Example format
            #         days_remaining = (exp_date - datetime.now()).days
            #         days_remaining_str = f"{days_remaining} days"
            #         if days_remaining <= 0:
            #             sev = SeverityLevel.CRITICAL; rec = f"Local certificate '{cert_name}' has expired."; cert_details["status"] = "Expired"
            #         elif days_remaining <= 30:
            #             sev = SeverityLevel.HIGH; rec = f"Local certificate '{cert_name}' expires in {days_remaining} days."; cert_details["status"] = "Expires Soon"
            #         elif days_remaining <= 90:
            #             sev = SeverityLevel.MEDIUM; cert_details["status"] = "OK"
            #         else:
            #             cert_details["status"] = "OK"
            #     except ValueError:
            #         days_remaining_str = "Invalid Date Format"
            #         sev = SeverityLevel.LOW

            findings.append({
                "description": f"Local Certificate: {cert_name}",
                "value": f"Issuer: {cert_details['issuer']}, Subject: {cert_details['subject']}, Status: {cert_details['status']}",
                "severity": sev,
                "recommendation": rec
            })
            parsed_certs.append(cert_details)
            if sev > overall_status: overall_status = sev

        if not findings:
            findings.append({"description": "Local SSL Certificates", "value": "No local certificates found or output unrecognized.", "severity": SeverityLevel.INFO})

        return {
            "check_name": "Local SSL Certificates",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "parsed_certificates": parsed_certs
        }

    def parse_ssl_vpn_certificates(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'get vpn ssl settings' for certificate info."""
        # This command output is a block of `config vpn ssl settings`
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_settings = {}
        default_recommendation = "Ensure SSL VPN server certificate is valid, trusted, and not expired. Replace self-signed certificates with CA-signed certificates in production environments for better security."

        # Server Certificate
        server_cert_match = re.search(r"set\s+servercert\s+\"(.*?)\"", output, re.IGNORECASE)
        if server_cert_match:
            cert_name = server_cert_match.group(1)
            parsed_settings['ssl_vpn_server_certificate'] = cert_name
            sev = SeverityLevel.INFO
            rec = default_recommendation
            val_details = f"Server Certificate: {cert_name}"

            if cert_name.lower() == "fortinet_factory" or "self-signed" in cert_name.lower():
                sev = SeverityLevel.MEDIUM
                rec = "Default or self-signed SSL VPN server certificate in use. Replace with a trusted CA-signed certificate for production environments to avoid browser warnings and enhance security."
            
            # To check expiry, we'd need to cross-reference with `diagnose vpn certificate local details <cert_name>`
            # This parser only sees the name from `get vpn ssl settings`.
            # For now, we cannot assess expiry directly here.

            findings.append({
                "description": "SSL VPN Server Certificate",
                "value": val_details,
                "severity": sev,
                "recommendation": rec
            })
            if sev > overall_status: overall_status = sev
        else:
            findings.append({"description": "SSL VPN Server Certificate", "value": "Not found in settings", "severity": SeverityLevel.MEDIUM, "recommendation": "SSL VPN server certificate is not configured. SSL VPN will not function correctly."})
            if SeverityLevel.MEDIUM > overall_status: overall_status = SeverityLevel.MEDIUM
        
        # Client Certificate Requirement (Optional based on config)
        req_client_cert_match = re.search(r"set\s+reqclientcert\s+(enable|disable)", output, re.IGNORECASE)
        if req_client_cert_match:
            status = req_client_cert_match.group(1).lower()
            parsed_settings['client_certificate_required'] = status
            findings.append({
                "description": "SSL VPN Client Certificate Requirement",
                "value": f"Client certificate authentication is {status}",
                "severity": SeverityLevel.INFO
            })
        
        # Check for other relevant SSL VPN settings if needed...

        return {
            "check_name": "SSL VPN Certificate Settings",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "parsed_settings": parsed_settings
        }

    def parse_routing_table(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'get router info routing-table all' command."""
        findings = []
        overall_status = SeverityLevel.INFO # Default, can be raised by specific findings
        parsed_routes = []
        summary = {
            'total_routes': 0,
            'static_routes': 0,
            'connected_routes': 0,
            'bgp_routes': 0,
            'ospf_routes': 0,
            'rip_routes': 0,
            'isis_routes': 0,
            'kernel_routes': 0, # Routes installed by kernel, not dynamic protocols
            'recursive_routes': 0, # Routes whose next-hop requires another lookup
            'blackhole_routes': 0
        }
        # More specific recommendations could be added based on route types or issues found.
        default_recommendation = "Review routing table for correctness, ensure reachability to critical networks, and remove any unnecessary or problematic routes. Check for routing loops or blackholes."

        # Regex to capture common route entry patterns. FortiOS output can vary slightly.
        # Example: C    192.168.1.0/24 is directly connected, port1
        #          S*   0.0.0.0/0 [10/0] via 1.2.3.4, wan1
        #          B    10.0.0.0/8 [20/0] via 5.6.7.8 (recursive)
        #          O    172.16.0.0/12 [110/10] via 9.10.11.12, port2, 00:01:23, ospf1
        route_pattern = re.compile(
            r"^(?P<code>[CSBORKI?])\s*" + # Route code (C, S, B, O, R, K, I, ?)
            r"(?:\*\s*)?" +  # Optional asterisk for default route
            r"(?P<destination>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}|[a-fA-F0-9:]+:/\d{1,3})\s+" + # Destination Prefix (IPv4 or IPv6)
            r"(?:is\s+directly\s+connected,\s+(?P<interface_conn>[^,\s]+)|" + # Connected route part
            r"\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<nexthop>[^,\s]+)(?:,\s*(?P<interface_dyn>[^,\s]+))?)" + # Dynamic/Static route part
            r"(?:\s*\((?P<recursive>recursive)\))?" + # Optional recursive flag
            r"(?:,\s*(?P<uptime>[\dhmsoce:]+))?" + # Optional uptime for dynamic routes
            r"(?:,\s*(?P<tag_ Prozess>[^,\s]+))?" # Optional tag/process for dynamic routes
            , re.IGNORECASE
        )

        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("Routing table for") or line.startswith("Codes:") or line.startswith("------"):
                continue

            match = route_pattern.match(line)
            if match:
                route_data = match.groupdict()
                summary['total_routes'] += 1
                sev = SeverityLevel.INFO
                rec = None
                details_str = f"Dest: {route_data['destination']}"

                protocol_code = route_data['code'].upper()
                protocol_name = "Unknown"
                
                if protocol_code == 'C':
                    protocol_name = "Connected"
                    summary['connected_routes'] += 1
                    details_str += f", Interface: {route_data['interface_conn']}"
                elif protocol_code == 'S':
                    protocol_name = "Static"
                    summary['static_routes'] += 1
                    details_str += f", Next-Hop: {route_data['nexthop']}, Interface: {route_data['interface_dyn'] or 'N/A'}, AD/Metric: {route_data['ad']}/{route_data['metric']}"
                    if route_data['destination'] == "0.0.0.0/0" or route_data['destination'] == "::/0":
                        findings.append({"description": "Default Route Present", "value": line, "severity": SeverityLevel.INFO})
                elif protocol_code == 'B':
                    protocol_name = "BGP"
                    summary['bgp_routes'] += 1
                    details_str += f", Next-Hop: {route_data['nexthop']}, Interface: {route_data['interface_dyn'] or 'N/A'}, AD/Metric: {route_data['ad']}/{route_data['metric']}"
                elif protocol_code == 'O':
                    protocol_name = "OSPF"
                    summary['ospf_routes'] += 1
                    details_str += f", Next-Hop: {route_data['nexthop']}, Interface: {route_data['interface_dyn'] or 'N/A'}, AD/Metric: {route_data['ad']}/{route_data['metric']}"
                # Add other protocols (R-RIP, I-ISIS, K-Kernel) if needed
                
                route_data['protocol_name'] = protocol_name
                parsed_routes.append(route_data)

                if route_data.get('recursive'):
                    summary['recursive_routes'] += 1
                    sev = SeverityLevel.LOW # Recursive routes are not inherently bad but can indicate complexity
                    rec = "Recursive route found. Ensure next-hop is resolvable and not causing routing issues."
                    details_str += " (Recursive)"
                
                # Check for blackhole routes (Often AD 255 or specific next-hop/interface)
                if route_data.get('ad') == '255' or (route_data.get('nexthop') == '0.0.0.0' and route_data.get('interface_dyn', '').lower() == 'blackhole'):
                    summary['blackhole_routes'] +=1
                    sev = SeverityLevel.MEDIUM
                    rec = "Blackhole route configured. Verify if this is intentional (e.g., for null routing) or a misconfiguration."
                    details_str += " (Blackhole)"
                    if sev > overall_status: overall_status = sev

                # Individual route entries are usually INFO unless a specific issue identified above
                findings.append({
                    "description": f"{protocol_name} Route",
                    "value": details_str,
                    "severity": sev,
                    "recommendation": rec,
                    "details": line # Raw line for this route
                })
            elif line.strip(): # Non-empty line that didn't match the route pattern
                findings.append({"description": "Unparsed Routing Line", "value": line, "severity": SeverityLevel.LOW, "details": "This line from routing table was not parsed by the regex."})
                if SeverityLevel.LOW > overall_status: overall_status = SeverityLevel.LOW
        
        if summary['total_routes'] == 0 and output.strip(): # Output was there, but no routes parsed
            overall_status = SeverityLevel.MEDIUM
            findings.append({"description": "Routing Table Parsing", "value": "No routes parsed. The table might be empty or format unrecognized.", "severity": overall_status, "recommendation": "Verify routing configuration and command output format."})
        elif not output.strip():
            overall_status = SeverityLevel.HIGH
            findings.append({"description": "Routing Table Empty", "value": "Command returned no output.", "severity": overall_status, "recommendation": "Routing table appears empty. Investigate routing configuration immediately."})

        # Add summary findings
        findings.insert(0, {"description": "Routing Table Summary", "value": f"Total: {summary['total_routes']}, Static: {summary['static_routes']}, Connected: {summary['connected_routes']}, BGP: {summary['bgp_routes']}, OSPF: {summary['ospf_routes']}, Recursive: {summary['recursive_routes']}, Blackhole: {summary['blackhole_routes']}", "severity": SeverityLevel.INFO})

        return {
            "check_name": "Routing Table",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "parsed_routes_summary": summary,
            "parsed_routes_list": parsed_routes,
            "recommendation": default_recommendation
        }

    def parse_interface_health(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'diagnose hardware deviceinfo nic' command."""
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_interfaces = {}
        summary = {
            "total_interfaces": 0,
            "up_interfaces": 0,
            "down_interfaces": 0,
            "admin_down_interfaces": 0,
            "interfaces_with_errors": 0,
            "interfaces_with_high_discards": 0
        }
        default_recommendation = "Review interface statuses. Investigate any down interfaces or interfaces with errors/discards. Ensure physical connectivity and correct configuration (speed/duplex)."

        # FortiOS output for `diagnose hardware deviceinfo nic <interface_name>` is per interface.
        # If the input `output` is from a command that lists all interfaces (like `get system interface physical`), 
        # then it needs to be split per interface block.
        # This parser assumes the output is for MULTIPLE interfaces as listed by `diagnose hardware deviceinfo nic` (no specific name)
        # or if it was a single interface, it will just process that one.

        # A common pattern for each interface block starts with the interface name line, e.g., "Interface Name: port1"
        # Or simply the interface name at the beginning of its section, e.g. "port1         Link:Up ..."
        # The command `diagnose hardware deviceinfo nic` lists all interfaces sequentially.
        # We can split by a line that looks like an interface name header or a known delimiter if one exists.
        # For `diagnose hardware deviceinfo nic`, it's a continuous stream, so we iterate line by line looking for interface headers.

        current_interface_name = None
        interface_data = {}
        interface_findings = []

        # Regex to identify the start of an interface block (interface name)
        # Example: "port1 Link:Up ..." or "wan1 Link:Up ..."
        # This also tries to capture if the interface is part of a switch-fabric or software switch.
        interface_header_re = re.compile(r"^(?P<name>[a-zA-Z0-9\._-]+(?:\s*\(sw\))?)\s+(?:Link\s*:\s*(?P<link_status>Up|Down|Not Present|Unknown))?", re.IGNORECASE)
        # Regex for details like speed, duplex, errors, discards
        details_re = {
            "speed_duplex": re.compile(r"Speed\s*:\s*(?P<speed>\S+)\s+Duplex\s*:\s*(?P<duplex>\S+)", re.IGNORECASE),
            "state": re.compile(r"State\s*:\s*(up|down|admin_down|not present|unknown)", re.IGNORECASE),
            "admin_status": re.compile(r"Admin\s*:\s*(up|down)", re.IGNORECASE), # from 'get system interface'
            "link_status_alt": re.compile(r"Link\s*status\s*:\s*(up|down)", re.IGNORECASE), # from 'get system interface'
            "errors": re.compile(r"RX\s+errors\s*:\s*(?P<rx_err>\d+)\s+TX\s+errors\s*:\s*(?P<tx_err>\d+)", re.IGNORECASE),
            "discards": re.compile(r"RX\s+dropped\s*:\s*(?P<rx_drop>\d+)\s+TX\s+dropped\s*:\s*(?P<tx_drop>\d+)", re.IGNORECASE),
            "rx_packets": re.compile(r"RX\s+Packets\s*:\s*(\d+)"),
            "tx_packets": re.compile(r"TX\s+Packets\s*:\s*(\d+)"),
            "rx_bytes": re.compile(r"RX\s+Bytes\s*:\s*(\d+)"),
            "tx_bytes": re.compile(r"TX\s+Bytes\s*:\s*(\d+)"),
        }

        def process_current_interface():
            nonlocal overall_status, interface_data, interface_findings, current_interface_name
            if not current_interface_name or not interface_data: return

            summary["total_interfaces"] += 1
            if_status = interface_data.get("status", "unknown").lower()
            if_sev = SeverityLevel.INFO
            if_rec = None

            if if_status == "down":
                summary["down_interfaces"] += 1
                if interface_data.get("admin_status", "up") == "up": # Link is down but admin is up
                    if_sev = SeverityLevel.HIGH
                    if_rec = f"Interface {current_interface_name} is down. Check physical connection, cable, and peer device."
                else: # Admin down
                    summary["admin_down_interfaces"] +=1
                    if_sev = SeverityLevel.LOW # Admin down is often intentional
                    if_rec = f"Interface {current_interface_name} is administratively down."
            elif if_status == "up":
                summary["up_interfaces"] += 1
            else: # unknown, not present etc.
                if_sev = SeverityLevel.MEDIUM
                if_rec = f"Interface {current_interface_name} status is '{if_status}'. Investigate."
            
            rx_err = int(interface_data.get("rx_errors", 0))
            tx_err = int(interface_data.get("tx_errors", 0))
            if rx_err > 0 or tx_err > 0:
                summary["interfaces_with_errors"] += 1
                err_sev = SeverityLevel.MEDIUM if (rx_err < 100 and tx_err < 100) else SeverityLevel.HIGH
                if_sev = max(if_sev, err_sev)
                interface_findings.append({
                    "description": "Interface Errors", 
                    "value": f"RX: {rx_err}, TX: {tx_err}", 
                    "severity": err_sev, 
                    "recommendation": f"Interface {current_interface_name} has errors. Check cabling, SFP, or hardware issues. High errors can degrade performance."
                })

            rx_drop = int(interface_data.get("rx_discards", 0))
            tx_drop = int(interface_data.get("tx_discards", 0))
            # Discards need context of total packets to be truly meaningful, but high absolute numbers are a flag
            if rx_drop > 1000 or tx_drop > 1000: # Arbitrary threshold for "high"
                summary["interfaces_with_high_discards"] +=1
                drop_sev = SeverityLevel.MEDIUM
                if_sev = max(if_sev, drop_sev)
                interface_findings.append({
                    "description": "Interface Discards", 
                    "value": f"RX: {rx_drop}, TX: {tx_drop}", 
                    "severity": drop_sev, 
                    "recommendation": f"Interface {current_interface_name} has high discards. This may indicate congestion, QoS issues, or buffer problems. Investigate further."
                })
            
            interface_data["findings"] = interface_findings
            interface_data["overall_severity"] = if_sev # Store severity for this specific interface
            parsed_interfaces[current_interface_name] = interface_data
            if if_sev > overall_status: overall_status = if_sev
            
            # Reset for next interface
            interface_data = {}
            interface_findings = []
            current_interface_name = None

        for line in output.splitlines():
            line = line.strip()
            if not line: continue

            header_match = interface_header_re.match(line)
            if header_match:
                process_current_interface() # Process previous interface data before starting new one
                current_interface_name = header_match.group("name")
                interface_data = {"name": current_interface_name, "status": "unknown", "speed": "N/A", "duplex": "N/A"}
                if header_match.group("link_status"): 
                    interface_data["status"] = header_match.group("link_status").lower()
                interface_findings = []
            
            if not current_interface_name: continue # Skip lines until an interface header is found

            # Try to match various detail lines
            m = details_re["speed_duplex"].search(line)
            if m: 
                interface_data["speed"] = m.group("speed")
                interface_data["duplex"] = m.group("duplex")
                continue
            m = details_re["state"].search(line) # More direct state, e.g. admin_down
            if m: interface_data["status"] = m.group(1).lower(); continue
            m = details_re["admin_status"].search(line) # For 'get sys int' type output if mixed
            if m: interface_data["admin_status"] = m.group(1).lower(); continue 
            m = details_re["link_status_alt"].search(line)
            if m and interface_data["status"] == "unknown": interface_data["status"] = m.group(1).lower(); continue

            m = details_re["errors"].search(line)
            if m: 
                interface_data["rx_errors"] = m.group("rx_err")
                interface_data["tx_errors"] = m.group("tx_err")
                continue
            m = details_re["discards"].search(line)
            if m: 
                interface_data["rx_discards"] = m.group("rx_drop")
                interface_data["tx_discards"] = m.group("tx_drop")
                continue
            # Add other stats if needed (rx_packets, etc.)
            for key, reg in details_re.items():
                if key in ["speed_duplex", "state", "admin_status", "link_status_alt", "errors", "discards"]: continue
                stat_match = reg.search(line)
                if stat_match:
                    interface_data[key] = stat_match.group(1); break # Found a stat, move to next line
        
        process_current_interface() # Process the last interface in the log

        # Consolidate findings for the main findings list
        if summary['down_interfaces'] > 0:
            sev = SeverityLevel.HIGH
            if summary['down_interfaces'] == summary['admin_down_interfaces']: # All down interfaces are admin down
                sev = SeverityLevel.LOW
            findings.append({
                "description": "Down Interfaces", 
                "value": f"{summary['down_interfaces']} (Admin Down: {summary['admin_down_interfaces']})", 
                "severity": sev,
                "recommendation": "Investigate any non-administratively down interfaces. Check physical connections and configurations."
            })
        if summary['interfaces_with_errors'] > 0:
            findings.append({"description": "Interfaces with Errors", "value": summary['interfaces_with_errors'], "severity": SeverityLevel.HIGH, "recommendation": "Check specific interfaces reporting errors. This could indicate Layer 1/2 issues."})
        if summary['interfaces_with_high_discards'] > 0:
            findings.append({"description": "Interfaces with High Discards", "value": summary['interfaces_with_high_discards'], "severity": SeverityLevel.MEDIUM, "recommendation": "Investigate interfaces with high discard rates, as this can indicate network congestion or misconfigurations."})

        if not parsed_interfaces and output.strip():
            overall_status = SeverityLevel.MEDIUM
            findings.append({"description": "Interface Parsing", "value": "No interfaces parsed. Output may be empty or format unrecognized.", "severity": overall_status})
        elif not output.strip():
            overall_status = SeverityLevel.HIGH
            findings.append({"description": "Interface Health Output", "value": "Command returned no output.", "severity": overall_status})

        return {
            "check_name": "Interface Health",
            "overall_status": overall_status,
            "findings": findings, # Overall findings for the section
            "interfaces": parsed_interfaces, # Detailed per-interface data and findings
            "summary": summary,
            "raw_output": output,
            "recommendation": default_recommendation
        }

    def parse_memory_usage(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'diagnose sys top-mem <N>' command (e.g., top 10 memory processes)."""
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_processes = []
        recommendation = "Review top memory-consuming processes. High memory usage by unexpected processes might indicate issues like memory leaks or malware. Sustained high total memory usage may require optimization or hardware upgrade."

        # Example `diagnose sys top-mem` output lines:
        # newcli (12345): 10.5% (100MB)
        # httpsd (5678): 5.2% (50MB)
        # Header might exist showing total memory, like: "Memory: Free: 1234MB Used: 2345MB Total: 3579MB"

        total_memory_mb = None
        used_memory_mb = None
        
        # Try to parse overall memory stats if available in the header
        mem_header_match = re.search(r"Memory:\s*(?:Free:\s*\d+MB\s*)?Used:\s*(\d+)MB\s*Total:\s*(\d+)MB", output, re.IGNORECASE)
        if mem_header_match:
            used_memory_mb = int(mem_header_match.group(1))
            total_memory_mb = int(mem_header_match.group(2))
            if total_memory_mb > 0:
                mem_usage_percent = (used_memory_mb / total_memory_mb) * 100
                sev = SeverityLevel.INFO
                if mem_usage_percent > 90:
                    sev = SeverityLevel.CRITICAL
                elif mem_usage_percent > 75:
                    sev = SeverityLevel.HIGH
                elif mem_usage_percent > 60:
                    sev = SeverityLevel.MEDIUM
                findings.append({
                    "description": "Overall Memory Usage", 
                    "value": f"{mem_usage_percent:.2f}% used ({used_memory_mb}MB / {total_memory_mb}MB)",
                    "severity": sev
                })
                if sev > overall_status: overall_status = sev
        
        # Process list from `diagnose sys top-mem N`
        # Format: process_name (pid): X.X% (Y.YMB) or X.X% (YK) or X.X% (YG)
        # Regex to capture process name, PID, memory percentage, and absolute memory (MB, KB, GB)
        process_line_re = re.compile(r"^\s*([\w\.\-\/]+)\s*\((\d+)\):\s*(\d+\.\d+)%\s*\((\d+\.?\d*)([MKBG])\)", re.IGNORECASE)
        lines = output.splitlines()
        for line in lines:
            match = process_line_re.search(line)
            if match:
                name, pid, mem_percent_str, mem_abs_str, mem_unit = match.groups()
                mem_percent = float(mem_percent_str)
                mem_abs = float(mem_abs_str)
                mem_abs_mb = mem_abs

                if mem_unit.upper() == 'K':
                    mem_abs_mb = mem_abs / 1024
                elif mem_unit.upper() == 'G':
                    mem_abs_mb = mem_abs * 1024
                # M is already MB

                parsed_processes.append({
                    "name": name,
                    "pid": int(pid),
                    "memory_percent": mem_percent,
                    "memory_mb": round(mem_abs_mb, 2)
                })

                sev = SeverityLevel.INFO
                rec_proc = None
                # Individual process memory thresholds (example)
                if mem_percent > 20: # A single process using >20% memory might be notable
                    sev = SeverityLevel.MEDIUM
                    rec_proc = f"Process '{name}' (PID: {pid}) is using {mem_percent}% memory. Investigate if this is expected."
                if mem_percent > 50:
                    sev = SeverityLevel.HIGH
                    rec_proc = f"Process '{name}' (PID: {pid}) is using {mem_percent}% memory. This is very high, investigate immediately."

                findings.append({
                    "description": f"Process: {name} (PID: {pid})",
                    "value": f"Memory: {mem_percent}% ({round(mem_abs_mb,2)} MB)",
                    "severity": sev,
                    "recommendation": rec_proc
                })
                if sev > overall_status: overall_status = sev

        if not parsed_processes and output.strip() and not mem_header_match:
             # No processes parsed, and no general memory stats found, maybe format issue
            overall_status = max(overall_status, SeverityLevel.LOW) # Not necessarily an error, could be 0 processes reported
            findings.append({"description": "Memory Process List", "value": "No processes parsed or unrecognized format.", "severity": SeverityLevel.LOW})
        elif not output.strip():
            overall_status = SeverityLevel.MEDIUM
            findings.append({"description": "Memory Usage Output", "value": "Command returned no output.", "severity": overall_status})

        return {
            "check_name": "Memory Usage (Top Processes)",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "parsed_top_memory_processes": parsed_processes,
            "recommendation": recommendation
        }

    def parse_disk_usage(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'diagnose sys df' (disk free) command."""
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_filesystems = []
        recommendation = "Review disk usage for all partitions. High disk usage (especially for /var/log or /data) can lead to system instability or log loss. Investigate and clear unnecessary files or expand disk space if needed."

        # `diagnose sys df` output is similar to Linux `df` command.
        # Example lines:
        # Filesystem      1K-blocks      Used Available Use% Mounted on
        # /dev/rootA         123456     67890    55566  55% /
        # /dev/log           543210    500000    43210  92% /var/log
        # tmpfs              102400      1024   101376   1% /tmp

        lines = output.splitlines()
        header_found = False
        for line in lines:
            line = line.strip()
            if not line: continue

            if line.startswith("Filesystem"): # Header line
                header_found = True
                continue
            
            if not header_found and not (line.startswith("/") or line.startswith("tmpfs") or line.startswith("none")):
                # Skip lines until a potential header or a filesystem entry is found
                # This helps to ignore potential preceding non-df output if the command output is messy
                continue

            # Regex for df output lines (handles spaces in Filesystem names if any, though uncommon in FortiOS)
            # Allows for flexible spacing between columns
            df_match = re.match(r"^(?P<filesystem>\S+)\s+(?P<blocks>\d+)\s+(?P<used>\d+)\s+(?P<available>\d+)\s+(?P<use_percent>\d+)%\s+(?P<mount_point>\S+)", line)
            
            if df_match:
                fs_data = df_match.groupdict()
                fs_name = fs_data['filesystem']
                mount_point = fs_data['mount_point']
                use_percent = int(fs_data['use_percent'])
                used_kb = int(fs_data['used'])
                available_kb = int(fs_data['available'])
                total_kb = int(fs_data['blocks'])

                parsed_filesystems.append({
                    "filesystem": fs_name,
                    "mount_point": mount_point,
                    "total_kb": total_kb,
                    "used_kb": used_kb,
                    "available_kb": available_kb,
                    "use_percent": use_percent
                })

                sev = SeverityLevel.INFO
                rec_fs = None
                if use_percent >= 95:
                    sev = SeverityLevel.CRITICAL
                    rec_fs = f"Disk usage for '{mount_point}' ({fs_name}) is critical at {use_percent}%. Immediate action required to free up space to prevent system failure."
                elif use_percent >= 85:
                    sev = SeverityLevel.HIGH
                    rec_fs = f"Disk usage for '{mount_point}' ({fs_name}) is high at {use_percent}%. Free up space soon to avoid issues."
                elif use_percent >= 70:
                    sev = SeverityLevel.MEDIUM
                    rec_fs = f"Disk usage for '{mount_point}' ({fs_name}) is at {use_percent}%. Monitor usage."
                
                findings.append({
                    "description": f"Disk Partition: {mount_point} ({fs_name})",
                    "value": f"Usage: {use_percent}% (Used: {used_kb}KB, Available: {available_kb}KB, Total: {total_kb}KB)",
                    "severity": sev,
                    "recommendation": rec_fs
                })
                if sev > overall_status: overall_status = sev
            elif header_found: # If header was found, but this line didn't match, it might be an issue or an unparsed line.
                findings.append({"description": "Unparsed Disk Usage Line", "value": line, "severity": SeverityLevel.LOW, "details": "This line after disk usage header was not parsed."})
                if SeverityLevel.LOW > overall_status: overall_status = SeverityLevel.LOW

        if not parsed_filesystems and output.strip():
            overall_status = SeverityLevel.MEDIUM
            findings.append({"description": "Disk Usage Parsing", "value": "No disk partitions parsed. Output may be empty or format unrecognized.", "severity": overall_status, "recommendation": "Verify 'diagnose sys df' command output format."})
        elif not output.strip():
            overall_status = SeverityLevel.HIGH
            findings.append({"description": "Disk Usage Output", "value": "Command returned no output.", "severity": overall_status})

        return {
            "check_name": "Disk Usage",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "parsed_filesystems": parsed_filesystems,
            "recommendation": recommendation
        }

    def parse_process_list(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'diagnose sys top -n <N>' (CPU top processes)."""
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_processes = []
        recommendation = "Review top CPU-consuming processes. Consistently high CPU usage by specific processes might indicate performance bottlenecks, misconfigurations, or resource-intensive tasks. If overall CPU is high, consider optimization or hardware upgrade."

        # `diagnose sys top` output format:
        # Run Time:  10 days, 2 hours and 50 minutes
        # 0U, 0N, 0S, 100I, 0WA, 0HI, 0SI, 0ST (Overall CPU usage)
        # newcli     12345      R      10.5    0.1    some info
        # httpsd      5678      S       5.2    1.5    other info
        # ... (N processes)

        overall_cpu_usage_parsed = False
        # Try to parse overall CPU stats
        # Example: 0U, 0N, 0S, 100I, 0WA, 0HI, 0SI, 0ST
        # We are primarily interested in Idle (I) to calculate usage.
        cpu_overall_match = re.search(r"(\d+)U,\s*(\d+)N,\s*(\d+)S,\s*(\d+)I,\s*(\d+)WA,\s*(\d+)HI,\s*(\d+)SI,\s*(\d+)ST", output, re.IGNORECASE)
        if cpu_overall_match:
            idle_cpu = int(cpu_overall_match.group(4))
            total_cpu_usage = 100 - idle_cpu
            overall_cpu_usage_parsed = True
            sev = SeverityLevel.INFO
            if total_cpu_usage > 90:
                sev = SeverityLevel.CRITICAL
            elif total_cpu_usage > 75:
                sev = SeverityLevel.HIGH
            elif total_cpu_usage > 60:
                sev = SeverityLevel.MEDIUM
            findings.append({
                "description": "Overall CPU Utilization",
                "value": f"{total_cpu_usage}% used ({idle_cpu}% idle)",
                "severity": sev
            })
            if sev > overall_status: overall_status = sev

        # Process list from `diagnose sys top -n N`
        # Fields: Process, PID, State, CPU%, MEM%
        # Regex: Name, PID, State (S/R/D/Z/T), CPU_percent, MEM_percent, Description (optional)
        process_line_re = re.compile(
            r"^\s*([\w\.\-\/]+)\s+" +  # Process name
            r"(\d+)\s+" +             # PID
            r"([SRDZTW<>NLs])\s+" +     # State (e.g., S, R, D, Z, T, W, N, L, s, <, >)
            r"(\d+\.\d+)\s+" +         # CPU %
            r"(\d+\.\d+)" +           # MEM %
            r"(?:\s+.*)?$"             # Optional rest of the line (like command args)
        , re.IGNORECASE)

        lines = output.splitlines()
        processes_started = False
        for line in lines:
            # Skip header lines until process list starts
            if not processes_started:
                if line.strip().startswith("PID") or process_line_re.search(line.strip()): # Common headers or first process line
                    processes_started = True
                elif cpu_overall_match and line.strip() == cpu_overall_match.group(0): # Line after CPU overall stats
                    processes_started = True # Likely next lines are processes
                if not processes_started:
                    continue
            
            match = process_line_re.search(line.strip()) # Search because fields might not start at beginning
            if match:
                name, pid, state, cpu_percent_str, mem_percent_str = match.groups()[:5]
                cpu_percent = float(cpu_percent_str)
                mem_percent = float(mem_percent_str)

                parsed_processes.append({
                    "name": name,
                    "pid": int(pid),
                    "state": state,
                    "cpu_percent": cpu_percent,
                    "memory_percent": mem_percent
                })

                sev_proc = SeverityLevel.INFO
                rec_proc = None
                # Individual process CPU thresholds
                if cpu_percent > 50: # A single process using >50% CPU is high
                    sev_proc = SeverityLevel.HIGH
                    rec_proc = f"Process '{name}' (PID: {pid}) is using {cpu_percent}% CPU. This is high, investigate."
                elif cpu_percent > 25:
                    sev_proc = SeverityLevel.MEDIUM
                    rec_proc = f"Process '{name}' (PID: {pid}) is using {cpu_percent}% CPU. Monitor if this is expected."

                findings.append({
                    "description": f"Process: {name} (PID: {pid})",
                    "value": f"CPU: {cpu_percent}%, MEM: {mem_percent}%, State: {state}",
                    "severity": sev_proc,
                    "recommendation": rec_proc
                })
                if sev_proc > overall_status: overall_status = sev_proc
        
        if not parsed_processes and output.strip() and not overall_cpu_usage_parsed:
            # No processes parsed, and no general CPU stats found
            overall_status = max(overall_status, SeverityLevel.LOW)
            findings.append({"description": "CPU Top Process List", "value": "No processes parsed or unrecognized format.", "severity": SeverityLevel.LOW})
        elif not output.strip():
            overall_status = SeverityLevel.MEDIUM
            findings.append({"description": "CPU Top Process Output", "value": "Command returned no output.", "severity": overall_status})

        return {
            "check_name": "CPU Usage (Top Processes)",
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "parsed_top_cpu_processes": parsed_processes,
            "recommendation": recommendation
        }

    def parse_security_status(self, output: str, check_type: str) -> Dict[str, Any]:
        """Generic parser for security status commands (IPS, AV, Webfilter, Spamfilter stats)."""
        findings = []
        overall_status = SeverityLevel.INFO
        parsed_stats = {}
        check_name_map = {
            "ips_stats": "IPS Engine & Signature Status",
            "av_stats": "AntiVirus Engine & Signature Status",
            "webfilter_stats": "Web Filter Service Status",
            "spamfilter_stats": "AntiSpam Service Status",
            "dlp_status": "DLP Engine & Signature Status", # Example for future expansion
            "appcontrol_status": "Application Control Signature Status" # Example
        }
        check_display_name = check_name_map.get(check_type, check_type.replace('_', ' ').title())
        recommendation = f"Ensure {check_display_name} is enabled, services are reachable, and definitions are up-to-date. Monitor for significant error counts or blocked threats."

        # This parser needs to be robust to handle slightly different formats for each check_type.
        # Common patterns: Key: Value, or section headers.
        # Example for IPS: IPS Engine version: 5.00123, IPS DB version: 15.00321
        # Example for AV: AV Engine version: 6.00123, AV DB version: 20.00321
        # Example for Web Filter: FortiGuard Web Filter: Enabled, Service: Reachable, Cache entries: 1000

        # General Key-Value Pair Regex (handles spaces in keys and values)
        # Looks for lines like "Key Name  : Value String" or "Key Name:Value String"
        kv_pair_re = re.compile(r"^\s*([\w\s\(\)/-]+?)\s*:\s*(.+?)\s*$", re.IGNORECASE)
        
        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            if not line: continue

            match = kv_pair_re.match(line)
            if match:
                key = match.group(1).strip().lower().replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
                value = match.group(2).strip()
                parsed_stats[key] = value
                sev = SeverityLevel.INFO
                rec_item = None

                # Common checks for engine/db versions and status
                if "engine_version" in key or "db_version" in key or "signature_version" in key:
                    if not value or value.lower() in ["n/a", "0.00000", "unknown"]:
                        sev = SeverityLevel.HIGH
                        rec_item = f"{key.replace('_',' ').title()} is invalid or not available. Investigate."
                elif "status" in key or "service" in key:
                    if value.lower() in ["disabled", "error", "unreachable", "not running"]:
                        sev = SeverityLevel.CRITICAL
                        rec_item = f"{check_display_name} {key.replace('_',' ').title()} is '{value}'. This service may not be functional. Investigate immediately."
                    elif value.lower() in ["warning", "expired"]:
                         sev = SeverityLevel.HIGH
                         rec_item = f"{check_display_name} {key.replace('_',' ').title()} is '{value}'. Service may be degraded."
                elif "last_update" in key:
                    try:
                        # Attempt to parse common date formats
                        update_dt = None
                        for fmt in ('%a %b %d %H:%M:%S %Y', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M'):
                            try:
                                update_dt = datetime.strptime(value, fmt)
                                break
                            except ValueError:
                                continue
                        if update_dt and (datetime.now() - update_dt).days > 7:
                            sev = SeverityLevel.MEDIUM
                            rec_item = f"{check_display_name} definitions were last updated on {value} (more than 7 days ago). Ensure updates are current."
                        if update_dt and (datetime.now() - update_dt).days > 30:
                            sev = SeverityLevel.HIGH
                            rec_item = f"{check_display_name} definitions were last updated on {value} (more than 30 days ago). This is critical, update immediately."
                    except ValueError:
                        sev = SeverityLevel.LOW # Can't parse date
                elif ("errors" in key or "failures" in key) and value.isdigit() and int(value) > 0:
                    error_count = int(value)
                    sev = SeverityLevel.MEDIUM if error_count < 100 else SeverityLevel.HIGH
                    rec_item = f"{check_display_name} reports {error_count} {key.replace('_', ' ')}. Investigate logs for details."
                
                findings.append({
                    "description": f"{check_display_name}: {key.replace('_', ' ').title()}",
                    "value": value,
                    "severity": sev,
                    "recommendation": rec_item
                })
                if sev > overall_status: overall_status = sev
            elif line.strip(): # Non-empty line that wasn't a K-V pair, could be a header or misc info
                findings.append({"description": f"{check_display_name} Info", "value": line, "severity": SeverityLevel.INFO})

        if not parsed_stats and output.strip(): # No key-value pairs parsed from non-empty output
            overall_status = max(overall_status, SeverityLevel.LOW)
            findings.append({"description": f"{check_display_name} Parsing", "value": "No specific stats parsed. Output might be in an unrecognized format or only contain general info.", "severity": SeverityLevel.LOW})
        elif not output.strip():
            overall_status = SeverityLevel.MEDIUM
            findings.append({"description": f"{check_display_name} Output", "value": "Command returned no output.", "severity": overall_status})
        
        return {
            "check_name": check_display_name,
            "overall_status": overall_status,
            "findings": findings,
            "raw_output": output,
            "parsed_stats": parsed_stats,
            "recommendation": recommendation
        }

    def run_health_check(self) -> Dict[str, Any]:
        """Run all health check commands and collect results."""
        health_data = {}
        
        try:
            # Execute commands concurrently
            command_outputs = self.execute_commands_concurrent(FORTIGATE_CLI_COMMANDS)
            
            # Parse outputs
            for check_name, output in command_outputs.items():
                logger.info(f"Parsing health check: {check_name}")
                
                if check_name in self.PARSER_MAPPING:
                    health_data[check_name] = self.PARSER_MAPPING[check_name](output)
                else:
                    health_data[check_name] = {"raw_output": output}
            
            return health_data
        except Exception as e:
            logger.error(f"Error during health check: {str(e)}")
            return {}

    def export_to_json(self, data: Dict[str, Any], filename: str):
        """Export health check data to JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Data exported to {filename}")
        except Exception as e:
            logger.error(f"Error exporting to JSON: {str(e)}")

    def export_to_csv(self, data: Dict[str, Any], filename: str):
        """Export health check data to CSV file."""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Check', 'Metric', 'Value'])
                
                for check_name, check_data in data.items():
                    if isinstance(check_data, dict):
                        for key, value in check_data.items():
                            if isinstance(value, (dict, list)):
                                writer.writerow([check_name, key, str(value)])
                            else:
                                writer.writerow([check_name, key, value])
                    else:
                        writer.writerow([check_name, 'raw_output', str(check_data)])
            
            logger.info(f"Data exported to {filename}")
        except Exception as e:
            logger.error(f"Error exporting to CSV: {str(e)}")

    def close_connections(self):
        """Close all SSH connections."""
        if self.fortigate_shell:
            self.fortigate_shell.close()
        if self.jumphost_client:
            self.jumphost_client.close()
        logger.info("All connections closed")

def print_colored_output(data: Dict[str, Any]):
    """Print health check data with color coding based on severity."""
    print(f"\n{Fore.CYAN}=== FortiGate Health Check Report ==={Style.RESET_ALL}")

    # Sort data to have 'system_status' first, then others alphabetically
    sorted_check_names = sorted(data.keys(), key=lambda x: (x != 'system_status', x))

    for check_name in sorted_check_names:
        check_data = data[check_name]
        title = check_data.get("check_name", check_name.replace('_', ' ').title())
        overall_status = check_data.get("overall_status")
        
        status_color = Fore.GREEN
        if overall_status == SeverityLevel.LOW: status_color = Fore.YELLOW
        elif overall_status == SeverityLevel.MEDIUM: status_color = Fore.YELLOW
        elif overall_status == SeverityLevel.HIGH: status_color = Fore.RED
        elif overall_status == SeverityLevel.CRITICAL: status_color = Fore.MAGENTA

        print(f"\n{status_color}--- {title} (Overall: {overall_status or 'N/A'}) ---{Style.RESET_ALL}")

        if isinstance(check_data, dict):
            parsing_error = check_data.get("parsing_error")
            raw_output = check_data.get("raw_output")

            if parsing_error:
                print(f"  {Fore.RED}Error parsing this section: {parsing_error}{Style.RESET_ALL}")
                if raw_output:
                    raw_output_preview = raw_output[:500]
                    if len(raw_output) > 500:
                        raw_output_preview += "..."
                    print(f"    {Fore.YELLOW}Raw output:{Style.RESET_ALL}\n{raw_output_preview}")
                continue # Skip to the next check_name if there was a parsing error
            
            if "findings" in check_data and isinstance(check_data["findings"], list):
                for finding in check_data["findings"]:
                    desc = finding.get("description", "N/A")
                    val = finding.get("value", "")
                    sev = finding.get("severity", SeverityLevel.INFO)
                    rec = finding.get("recommendation")
                    details = finding.get("details")

                    item_color = Fore.GREEN
                    if sev == SeverityLevel.LOW: item_color = Fore.YELLOW
                    elif sev == SeverityLevel.MEDIUM: item_color = Fore.YELLOW
                    elif sev == SeverityLevel.HIGH: item_color = Fore.RED
                    elif sev == SeverityLevel.CRITICAL: item_color = Fore.MAGENTA

                    print(f"  {item_color}{desc}{f': {val}' if val else ''} (Severity: {sev}){Style.RESET_ALL}")
                    if rec:
                        print(f"    {Fore.CYAN}Recommendation: {rec}{Style.RESET_ALL}")
                    if details and not val: # If no specific value, details might be useful
                         print(f"    {Fore.WHITE}Details: {str(details)[:200]}{Style.RESET_ALL}")
            
            if check_name == "interface_health" and "interfaces" in check_data:
                print(f"  {Fore.BLUE}Interface Details:{Style.RESET_ALL}")
                for if_name, if_data in check_data["interfaces"].items():
                    if_status = if_data.get("status", "Unknown")
                    if_color = Fore.GREEN if if_status == "up" or if_status == "ok" else Fore.RED
                    print(f"    {if_color}{if_name}: Status - {if_status}, Speed - {if_data.get('speed','N/A')}, Duplex - {if_data.get('duplex','N/A')}{Style.RESET_ALL}")
                    if "findings" in if_data:
                        for if_finding in if_data["findings"]:
                            if_desc = if_finding.get("description", "N/A")
                            if_val = if_finding.get("value", "")
                            if_sev = if_finding.get("severity", SeverityLevel.INFO)
                            if_rec = if_finding.get("recommendation")

                            if_item_color = Fore.GREEN
                            if if_sev == SeverityLevel.LOW: if_item_color = Fore.YELLOW
                            elif if_sev == SeverityLevel.MEDIUM: if_item_color = Fore.YELLOW
                            elif if_sev == SeverityLevel.HIGH: if_item_color = Fore.RED
                            
                            print(f"      {if_item_color}{if_desc}{f': {if_val}' if if_val else ''} (Severity: {if_sev}){Style.RESET_ALL}")
                            if if_rec:
                                print(f"        {Fore.CYAN}Recommendation: {if_rec}{Style.RESET_ALL}")
            elif "raw_output" in check_data and not check_data.get("findings") and not check_data.get("interfaces"):
                print(f"  {Fore.WHITE}Raw Data: {str(check_data['raw_output'])[:1000]}{'...' if len(str(check_data['raw_output'])) > 1000 else ''}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.WHITE}Data: {str(check_data)[:1000]}{'...' if len(str(check_data)) > 1000 else ''}{Style.RESET_ALL}")

def generate_text_report(data: Dict[str, Any], filename: str):
    """Generate a text report from health check data."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("FortiGate Health Check Report\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            system_status_data = data.get('system_status', {})
            if system_status_data:
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"SYSTEM STATUS (Overall: {system_status_data.get('overall_status', 'N/A')})\n")
                f.write("=" * 80 + "\n")
                if "parsing_error" in system_status_data:
                    f.write(f"Error parsing System Status: {system_status_data['parsing_error']}\n")
                    f.write(f"Raw Output:\n{system_status_data.get('raw_output', 'N/A')}\n\n")
                elif "findings" in system_status_data:
                    for finding in system_status_data["findings"]:
                        f.write(f"- {finding.get('description', 'N/A')}: {finding.get('value', 'N/A')} (Severity: {finding.get('severity', 'N/A')})\n")
                        if finding.get('recommendation'):
                            f.write(f"  Recommendation: {finding['recommendation']}\n")
                    f.write("\n")
                else: 
                    hostname_val = system_status_data.get('hostname', system_status_data.get('parsed_metrics',{}).get('hostname','N/A'))
                    f.write(f"Hostname: {hostname_val}\n")
                    model_val = system_status_data.get('model', system_status_data.get('parsed_metrics',{}).get('model_inferred','N/A'))
                    f.write(f"Model: {model_val}\n")
                    serial_val = system_status_data.get('serial_number', system_status_data.get('parsed_metrics',{}).get('serial_number','N/A'))
                    f.write(f"Serial Number: {serial_val}\n\n")

            performance_status_data = data.get('performance_status', {})
            if performance_status_data: 
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"PERFORMANCE STATUS (Overall: {performance_status_data.get('overall_status', 'INFO')})\n") 
                f.write("=" * 80 + "\n")
                if "parsing_error" in performance_status_data:
                    f.write(f"Error parsing Performance Status: {performance_status_data['parsing_error']}\n")
                    f.write(f"Raw Output:\n{performance_status_data.get('raw_output', 'N/A')}\n\n")
                elif "findings" in performance_status_data: 
                    for finding in performance_status_data["findings"]:
                        f.write(f"- {finding.get('description', 'N/A')}: {finding.get('value', 'N/A')} (Severity: {finding.get('severity', 'N/A')})\n")
                        if finding.get('recommendation'):
                            f.write(f"  Recommendation: {finding['recommendation']}\n")
                    f.write("\n")
                else: 
                    f.write(f"CPU Idle: {performance_status_data.get('cpu_idle', 'N/A')} %\n")
                    f.write(f"CPU Usage: {performance_status_data.get('cpu_usage', 'N/A')} %\n")
                    f.write(f"Memory Usage: {performance_status_data.get('memory_usage_percent', 'N/A')} %\n")
                    f.write(f"Conserve Mode: {performance_status_data.get('conserve_mode', 'N/A')}\n\n")

            interface_health_data = data.get('interface_health', {})
            if interface_health_data:
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"INTERFACE HEALTH (Overall: {interface_health_data.get('overall_status', 'N/A')})\n")
                f.write("=" * 80 + "\n")
                if "parsing_error" in interface_health_data:
                    f.write(f"Error parsing Interface Health: {interface_health_data['parsing_error']}\n")
                    f.write(f"Raw Output:\n{interface_health_data.get('raw_output', 'N/A')}\n\n")
                else:
                    summary = interface_health_data.get('summary', {})
                    f.write("Interface Summary:\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"Total Interfaces: {summary.get('total_interfaces', 'N/A')}\n")
                    f.write(f"Up Interfaces: {summary.get('up_interfaces', 'N/A')}\n")
                    f.write(f"Down Interfaces: {summary.get('down_interfaces', 'N/A')}\n")
                    f.write(f"Interfaces with Errors: {summary.get('interfaces_with_errors', 'N/A')}\n")
                    f.write(f"Interfaces with High Discards: {summary.get('interfaces_with_high_discards', 'N/A')}\n\n")

                    interfaces = interface_health_data.get('interfaces', {})
                    if interfaces:
                        f.write("Detailed Interface Information:\n")
                        f.write("-" * 40 + "\n")
                        for name, interface in interfaces.items():
                            f.write(f"Interface: {name}\n")
                            f.write(f"  Status: {interface.get('status', 'N/A')}\n")
                            f.write(f"  Speed: {interface.get('speed', 'N/A')}\n")
                            f.write(f"  Duplex: {interface.get('duplex', 'N/A')}\n")
                            
                            if "findings" in interface and interface["findings"]:
                                f.write("  Findings:\n")
                                for finding in interface["findings"]:
                                    f.write(f"    - {finding.get('description', 'N/A')}: {finding.get('value', 'N/A')} (Severity: {finding.get('severity', 'N/A')})\n")
                                    if finding.get('recommendation'):
                                        f.write(f"      Recommendation: {finding['recommendation']}\n")
                            f.write("\n" + "-" * 20 + "\n") 
                        f.write("\n") 
            
            for check_name, check_content in data.items():
                if check_name in ['system_status', 'interface_health', 'performance_status']:
                    continue 

                f.write("\n" + "=" * 80 + "\n")
                title = check_content.get("check_name", check_name.replace('_', ' ').upper())
                overall_sev = check_content.get("overall_status", "N/A") 
                f.write(f"{title} (Overall: {overall_sev})\n")
                f.write("=" * 80 + "\n")

                if isinstance(check_content, dict):
                    if "parsing_error" in check_content:
                        f.write(f"Error parsing this section: {check_content['parsing_error']}\n")
                        f.write(f"Raw Output:\n{check_content.get('raw_output', 'N/A')}\n\n")
                    elif "findings" in check_content and isinstance(check_content["findings"], list):
                        for finding in check_content["findings"]:
                            f.write(f"- {finding.get('description', 'N/A')}: {finding.get('value', 'N/A')} (Severity: {finding.get('severity', 'N/A')})\n")
                            if finding.get('recommendation'):
                                f.write(f"  Recommendation: {finding['recommendation']}\n")
                            if finding.get('details') and not finding.get('value'): 
                                f.write(f"  Details: {str(finding['details'])}\n")
                        f.write("\n")
                        if check_content.get("recommendation") and len(check_content["findings"]) > 0 :
                             f.write(f"Overall Recommendation for {title}: {check_content['recommendation']}\n\n")
                    elif "raw_output" in check_content and len(check_content) == 1: 
                         f.write(f"Raw Output:\n{check_content.get('raw_output', 'N/A')}\n\n")
                    else: 
                        for key, value in check_content.items():
                            if key in ["raw_output", "check_name", "overall_status", "findings", "parsed_metrics"] : continue 
                            f.write(f"{key.replace('_', ' ').title()}:\n")
                            if isinstance(value, dict):
                                for sub_k, sub_v in value.items():
                                    f.write(f"  {sub_k.replace('_', ' ').title()}: {sub_v}\n")
                            elif isinstance(value, list):
                                for item in value:
                                    if isinstance(item, dict):
                                        for sub_k, sub_v in item.items():
                                             f.write(f"    {sub_k.replace('_', ' ').title()}: {sub_v}\n")
                                        f.write("\n") 
                                    else:
                                        f.write(f"  - {item}\n")
                            else:
                                f.write(f"  {value}\n")
                            f.write("\n") 
                else: 
                    f.write(f"Data: {check_content}\n\n")

        logger.info(f"Text report generated: {filename}")
        return True
    except Exception as e:
        logger.error(f"Error generating text report: {str(e)}")
        return False

def load_config(config_file: str = 'fortigate_config.ini') -> dict:
    """Load configuration from file."""
    config = {
        'jumphost': None,
        'jumphost_user': None,
        'fortigate': [], # Initialize as empty list
        'fortigate_user': None,
        'max_retries': 3,
        'retry_delay': 5,
        'max_workers': 5
    }
    
    if os.path.exists(config_file):
        parser = configparser.ConfigParser()
        parser.read(config_file)
        
        if 'Connection' in parser:
            config.update({
                'jumphost': parser['Connection'].get('jumphost'),
                'jumphost_user': parser['Connection'].get('jumphost_user'),
                'fortigate_user': parser['Connection'].get('fortigate_user')
            })
            fortigate_ips_str = parser['Connection'].get('fortigate')
            if fortigate_ips_str:
                raw_ips = [ip.strip() for ip in fortigate_ips_str.split(',') if ip.strip()]
                config['fortigate'] = [ip for ip in raw_ips if is_valid_ip_or_hostname(ip)]
                for invalid_ip in set(raw_ips) - set(config['fortigate']):
                    logger.warning(f"Invalid IP/hostname '{invalid_ip}' found in config file. Skipping.")
        
        if 'Settings' in parser:
            config.update({
                'max_retries': parser['Settings'].getint('max_retries', 3),
                'retry_delay': parser['Settings'].getint('retry_delay', 5),
                'max_workers': parser['Settings'].getint('max_workers', 5)
            })
    
    return config

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='FortiGate Health Check Script')
    
    # Connection options
    parser.add_argument('--jumphost', help='Jumphost IP/Hostname')
    parser.add_argument('--jumphost-user', help='Jumphost username')
    parser.add_argument('--fortigate', help='FortiGate IP/Hostname(s), comma-separated for multiple')
    parser.add_argument('--fortigate-user', help='FortiGate username')
    
    # Export options
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--no-pdf', action='store_true', help='Disable automatic PDF report generation')
    parser.add_argument('--pdf-dir', help='Directory to save PDF reports (default: current directory)')
    
    # Configuration options
    parser.add_argument('--config', help='Path to configuration file', default='fortigate_config.ini')
    parser.add_argument('--save-config', action='store_true', help='Save current settings to config file')
    
    # Other options
    parser.add_argument('--max-retries', type=int, help='Maximum connection retry attempts')
    parser.add_argument('--retry-delay', type=int, help='Delay between retry attempts in seconds')
    parser.add_argument('--max-workers', type=int, help='Maximum concurrent command executions')
    parser.add_argument('--quiet', action='store_true', help='Suppress console output')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--generate-sample-ip-file', action='store_true', help='Generate a sample IP list file and exit')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with command line arguments
    for key, value in vars(args).items():
        if value is not None and key != 'config' and key != 'save_config' and key != 'generate_sample_ip_file':
            if key == 'fortigate': # Special handling for fortigate IPs
                raw_ips = [ip.strip() for ip in value.split(',') if ip.strip()]
                config[key] = [ip for ip in raw_ips if is_valid_ip_or_hostname(ip)]
                for invalid_ip in set(raw_ips) - set(config[key]):
                    logger.warning(f"Invalid IP/hostname '{invalid_ip}' from command line. Skipping.")
            else:
                config[key] = value
    
    # Ensure config['fortigate'] is a list, even if loaded as None initially and not overridden by args
    if not isinstance(config.get('fortigate'), list):
        if config.get('fortigate'): # If it was a single string from old config or bad manual edit
            config['fortigate'] = [ip.strip() for ip in str(config['fortigate']).split(',') if ip.strip()]
        else:
            config['fortigate'] = []
            
    return args, config

def save_config(config: dict, config_file: str = 'fortigate_config.ini'):
    """Save configuration to file."""
    parser = configparser.ConfigParser()
    
    # Connection settings
    fortigate_ips_str = ",".join(config.get('fortigate', [])) if isinstance(config.get('fortigate'), list) else config.get('fortigate', '')
    parser['Connection'] = {
        'jumphost': config.get('jumphost', '') or '', # Ensure empty string if None
        'jumphost_user': config.get('jumphost_user', '') or '',
        'fortigate': fortigate_ips_str,
        'fortigate_user': config.get('fortigate_user', '') or ''
    }
    
    # General settings
    parser['Settings'] = {
        'max_retries': str(config.get('max_retries', 3)),
        'retry_delay': str(config.get('retry_delay', 5)),
        'max_workers': str(config.get('max_workers', 5))
    }
    
    with open(config_file, 'w') as f:
        parser.write(f)
    logger.info(f"Configuration saved to {config_file}")

def load_ips_from_text_file(filepath: str) -> List[str]:
    """Load IP addresses from a text file (one IP per line, ignores comments and empty lines)."""
    ips = []
    validated_ips = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                entry = line.strip()
                if entry and not entry.startswith('#'):
                    if is_valid_ip_or_hostname(entry):
                        validated_ips.append(entry)
                    else:
                        logger.warning(f"Invalid IP/hostname '{entry}' found in {filepath} at line {line_num}. Skipping.")
        if not validated_ips:
            logger.warning(f"No valid IPs/hostnames found in file: {filepath}")
        else:
            logger.info(f"Loaded {len(validated_ips)} valid IPs/hostnames from {filepath}")
    except FileNotFoundError:
        # This case will be handled by the new interactive prompt in main()
        # logger.error(f"IP list file not found: {filepath}") 
        pass # Return empty list, main will prompt to create it
    except Exception as e:
        logger.error(f"Error reading IP list file {filepath}: {str(e)}")
    return validated_ips

def create_sample_ip_file(filepath: str) -> bool:
    """Creates a sample IP list file at the given path."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# FortiGate IP Address List\n")
            f.write("# Enter one IP address or hostname per line.\n")
            f.write("# Lines starting with # are comments and will be ignored.\n")
            f.write("# Empty lines are also ignored.\n")
            f.write("\n")
            f.write("# Example entries (replace with your actual IPs/hostnames):\n")
            f.write("# 192.168.1.1\n")
            f.write("# 10.0.0.5\n")
            f.write("# your-fortigate.example.com\n")
            f.write("# 2001:db8:85a3::8a2e:370:7334\n")
        logger.info(f"Sample IP list file '{filepath}' created successfully. Please edit it with your IPs/hostnames and then re-run the script to load them.")
        return True
    except Exception as e:
        logger.error(f"Could not create sample IP list file '{filepath}': {str(e)}")
        return False

def is_valid_ip_or_hostname(entry: str) -> bool:
    """Validate if the entry is a valid IP address (v4 or v6) or a plausible hostname."""
    if not entry:
        return False
    try:
        ipaddress.ip_address(entry) # Validates IPv4 and IPv6
        return True
    except ValueError:
        # Not a valid IP address, check if it's a plausible hostname
        # RFC 1035, but simplified: allows letters, numbers, hyphens, and dots.
        # Must not start or end with a hyphen or dot.
        # Segments (between dots) must not be empty and must not start/end with hyphen.
        if len(entry) > 255:
            return False # Too long for a hostname
        if entry.startswith(".") or entry.endswith(".") or entry.startswith("-") or entry.endswith("-"):
            return False
        # Regex for basic hostname structure (simplified)
        # Allows for internationalized domain names (IDN) by not being too strict on characters
        hostname_pattern = re.compile(r"^([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
        if hostname_pattern.match(entry):
            return True
    return False

def generate_pdf_report(data: Dict[str, Any], filename: str, fortigate_ip: str):
    """Generate a PDF report from health check data."""
    # Placeholder: Implementation for PDF generation is needed.
    # This function would use reportlab to create a structured PDF document.
    log_message = f"PDF report generation for {fortigate_ip} requested at {filename}, but not yet implemented."
    logger.info(log_message)
    # Example of how it might start:
    # doc = SimpleDocTemplate(filename, pagesize=landscape(letter))

def main():
    args, config = parse_arguments()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)

    # --generate-sample-ip-file is handled by parse_arguments if called alone and exits.
    # If combined with other args, its presence is noted by args.generate_sample_ip_file but primary logic proceeds.
    # We make the sample file generation interactive if chosen during IP input phase.

    jumphost_ip = config.get('jumphost')
    jumphost_user = config.get('jumphost_user')
    fortigate_ips = config.get('fortigate', []) # Already validated if from config/CLI
    fortigate_user = config.get('fortigate_user')

    if not fortigate_ips:
        while True:
            ip_input_method = input("How do you want to provide FortiGate IPs/Hostnames?\n1. Enter comma-separated list\n2. Load from a text file\nEnter choice (1 or 2): ").strip()
            if ip_input_method == '1':
                fortigate_ips_str = input("Enter FortiGate IP(s)/Hostname(s) (comma-separated for multiple): ")
                if fortigate_ips_str:
                    raw_ips = [ip.strip() for ip in fortigate_ips_str.split(',') if ip.strip()]
                    fortigate_ips = [ip for ip in raw_ips if is_valid_ip_or_hostname(ip)]
                    for invalid_ip in set(raw_ips) - set(fortigate_ips):
                        logger.warning(f"Invalid IP/hostname '{invalid_ip}' entered interactively. Skipping.")
                break
            elif ip_input_method == '2':
                ip_file_path = input("Enter the path to the text file containing IPs/Hostnames: ").strip()
                if ip_file_path:
                    loaded_ips = load_ips_from_text_file(ip_file_path) # Already validates internally
                    if not loaded_ips and not os.path.exists(ip_file_path):
                        create_choice = input(f"File '{ip_file_path}' not found. Create a sample file here? (yes/no): ").lower()
                        if create_choice in ['yes', 'y']:
                            if create_sample_ip_file(ip_file_path):
                                logger.info("Please edit the sample file and then re-run the script.")
                            return # Exit for user to edit the file
                        else:
                            logger.info("Skipping IP loading from file.")
                    fortigate_ips = loaded_ips
                break
            else:
                print("Invalid choice. Please enter 1 or 2.")
        
        if not fortigate_ips:
            logger.error("No valid FortiGate IPs/Hostnames provided or loaded. Exiting...")
            return

    # Single jumphost client for all FortiGate connections if jumphost is used
    shared_jumphost_client = None
    jumphost_connected = False

    try:
        use_jumphost = bool(jumphost_ip)
        if not use_jumphost and any(fortigate_ips):
             # If IPs are provided but no jumphost, ask if one is needed ONLY IF not directly connecting to all
            if not config.get('direct_connection_preferred', False): # Assuming you might add such a config later
                jumphost_response = input("Do you need to connect through a jumphost for these IPs? (yes/no): ").lower()
                use_jumphost = jumphost_response in ['yes', 'y']

        if use_jumphost:
            if not jumphost_ip:
                jumphost_ip = input("Enter Jumphost IP/Hostname: ")
            if not jumphost_user:
                jumphost_user = input(f"Enter Jumphost Username for {jumphost_ip}: ")
            jumphost_password = getpass.getpass(f"Enter Password for {jumphost_user}@{jumphost_ip}: ")
            verification_code = input("Enter jumphost verification code (if required, press Enter to skip): ") or None
            
            # Create a temporary health_checker to use its connect_to_jumphost method
            temp_health_checker_for_jumphost = FortiGateHealthCheck(
                max_retries=config['max_retries'], 
                retry_delay=config['retry_delay']
            )
            if temp_health_checker_for_jumphost.connect_with_retry(
                temp_health_checker_for_jumphost.connect_to_jumphost,
                jumphost_ip, jumphost_user, jumphost_password, verification_code
            ):
                shared_jumphost_client = temp_health_checker_for_jumphost.jumphost_client
                jumphost_connected = True
            else:
                logger.error("Failed to connect to jumphost. Exiting...")
                return
        
        # Common FortiGate user for all targets, if provided
        if not fortigate_user and any(fortigate_ips):
            fortigate_user = input(f"Enter FortiGate Username (this will be used for all target FortiGates): ")

        for fortigate_ip in fortigate_ips:
            logger.info(f"Processing FortiGate: {fortigate_ip} ===")
            
            # Create a new health_checker instance for each FortiGate IP
            health_checker = FortiGateHealthCheck(
                max_retries=config['max_retries'],
                retry_delay=config['retry_delay']
            )

            try:
                if use_jumphost and jumphost_connected and shared_jumphost_client:
                    health_checker.jumphost_client = shared_jumphost_client # Use the shared client
                    # The connect_to_fortigate method will use this existing client
                    current_fortigate_password = getpass.getpass(f"Enter FortiGate Password for {fortigate_user}@{fortigate_ip} (via jumphost): ")
                    if not health_checker.connect_with_retry(
                        health_checker.connect_to_fortigate, # This method uses the assigned jumphost_client
                        fortigate_ip, fortigate_user, current_fortigate_password
                    ):
                        logger.error(f"Failed to connect to FortiGate {fortigate_ip} via jumphost. Skipping...")
                        continue
                elif not use_jumphost:
                    current_fortigate_password = getpass.getpass(f"Enter FortiGate Password for {fortigate_user}@{fortigate_ip} (direct): ")
                    if not health_checker.connect_with_retry(
                        health_checker.connect_direct_to_fortigate,
                        fortigate_ip, fortigate_user, current_fortigate_password
                    ):
                        logger.error(f"Failed to connect directly to FortiGate {fortigate_ip}. Skipping...")
                        continue
                else: # Jumphost was intended but connection failed
                    logger.error(f"Jumphost connection not available for FortiGate {fortigate_ip}. Skipping...")
                    continue

                if not health_checker.setup_fortigate_session():
                    logger.error(f"Failed to setup FortiGate session for {fortigate_ip}. Skipping...")
                    continue
                
                health_data = health_checker.run_health_check()
                
                if not args.quiet:
                    print(f"\n{Fore.BLUE}--- Health Check Results for {fortigate_ip} ---{Style.RESET_ALL}")
                    print_colored_output(health_data)
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_filename_base = f"fortigate_health_report_{fortigate_ip.replace('.', '_')}_{timestamp}"
                
                text_report_filename = f"{report_filename_base}.txt"
                if generate_text_report(health_data, text_report_filename):
                    print(f"\nText report for {fortigate_ip} generated: {text_report_filename}")
                else:
                    print(f"\nFailed to generate text report for {fortigate_ip}")
                
                if args.export_json:
                    json_filename = f"{args.export_json.rsplit('.',1)[0]}_{fortigate_ip.replace('.', '_')}.json" if '.json' in args.export_json else f"{args.export_json}_{fortigate_ip.replace('.', '_')}.json"
                    health_checker.export_to_json(health_data, json_filename)
                if args.export_csv:
                    csv_filename = f"{args.export_csv.rsplit('.',1)[0]}_{fortigate_ip.replace('.', '_')}.csv" if '.csv' in args.export_csv else f"{args.export_csv}_{fortigate_ip.replace('.', '_')}.csv"
                    health_checker.export_to_csv(health_data, csv_filename)
                
                # PDF report generation would also use fortigate_ip in filename
                if not args.no_pdf:
                    pdf_dir = args.pdf_dir or "."
                    Path(pdf_dir).mkdir(parents=True, exist_ok=True)
                    pdf_filename = Path(pdf_dir) / f"{report_filename_base}.pdf"
                    generate_pdf_report(health_data, str(pdf_filename), fortigate_ip)

            except Exception as e_ip:
                logger.error(f"An error occurred while processing FortiGate {fortigate_ip}: {str(e_ip)}")
            finally:
                if health_checker and not use_jumphost: # If direct, close its specific connection
                     health_checker.close_connections()
                elif health_checker and use_jumphost: # If via jumphost, only close the shell, not the shared client
                    if health_checker.fortigate_shell:
                        health_checker.fortigate_shell.close()
                        health_checker.fortigate_shell = None
                    # The shared_jumphost_client is closed after the loop

        # Save configuration if requested, after all IPs processed
        if args.save_config:
            # Ensure config dictionary has the latest IPs used if they were prompted
            if fortigate_ips: config['fortigate'] = fortigate_ips
            if jumphost_ip: config['jumphost'] = jumphost_ip
            if jumphost_user: config['jumphost_user'] = jumphost_user
            if fortigate_user: config['fortigate_user'] = fortigate_user
            save_config(config, args.config)
    
    except KeyboardInterrupt:
        logger.info("Health check process interrupted by user")
    except Exception as e_main:
        logger.error(f"An unexpected error occurred in the main process: {str(e_main)}")
    finally:
        if shared_jumphost_client and jumphost_connected: # Close the shared jumphost client at the very end
            logger.info("Closing shared jumphost connection.")
            shared_jumphost_client.close()
        elif not use_jumphost: # If no jumphost was used at all.
            pass # Individual connections were closed in the loop
        logger.info("FortiGate health check process finished.")

if __name__ == "__main__":
    main() 