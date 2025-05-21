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

# FortiGate CLI Commands
FORTIGATE_CLI_COMMANDS = {
    # System Status
    "system_status": "get system status",
    "performance_status": "get system performance status",
    "ha_status": "get system ha status",
    "interface_status": "get system interface",
    "interface_health": "diagnose hardware deviceinfo nic",
    "interface_errors": "diagnose hardware deviceinfo nic-errors",
    "interface_stats": "diagnose hardware deviceinfo nic-stats",
    "interface_bandwidth": "diagnose hardware deviceinfo nic-bandwidth",
    "interface_duplex": "diagnose hardware deviceinfo nic-duplex",
    "interface_speed": "diagnose hardware deviceinfo nic-speed",
    "interface_autonegotiation": "diagnose hardware deviceinfo nic-autonegotiation",
    "interface_flow_control": "diagnose hardware deviceinfo nic-flow-control",
    "routing_table": "get router info routing-table all",
    "routing_summary": "get router info routing-table summary",
    
    # Memory and Resource Usage
    "memory_usage": "diagnose hardware sysinfo memory",
    "disk_usage": "diagnose hardware sysinfo disk",
    "cpu_usage": "diagnose hardware sysinfo cpu",
    "process_list": "diagnose sys top",
    "session_usage": "diagnose sys session stat",
    "log_disk_status": "diagnose sys logdisk status",
    
    # Security Status
    "antivirus_status": "diagnose antivirus status",
    "ips_status": "diagnose ips status",
    "webfilter_status": "diagnose webfilter status",
    "application_control": "diagnose application control status",
    "firewall_policy": "get firewall policy",
    "firewall_consolidated": "diagnose firewall consolidated-policy list",
    "firewall_ippool": "get firewall ippool",
    "firewall_address": "get firewall address",
    "firewall_service": "get firewall service custom",
    
    # VPN Status
    "vpn_ssl": "get vpn ssl settings",
    "vpn_ssl_stats": "diagnose vpn ssl stats",
    "vpn_ssl_tunnel": "diagnose vpn ssl tunnel list",
    "vpn_ipsec": "get vpn ipsec tunnel summary",
    "vpn_ike_gateway": "diagnose vpn ike gateway list",
    "vpn_tunnel_list": "diagnose vpn tunnel list",
    
    # System Services
    "dns_status": "diagnose sys dns status",
    "ntp_status": "diagnose sys ntp status",
    "fortiguard_status": "diagnose sys fortiguard status",
    "admin_administrators": "get system admin administrator",
    "admin_radius": "get system admin radius",
    "admin_tacacs": "get system admin tacacs",
    
    # Hardware Health
    "hardware_health": "diagnose hardware deviceinfo health",
    "fan_status": "diagnose hardware sysinfo fan",
    "temperature": "diagnose hardware sysinfo temperature",
    "power_supply": "diagnose hardware sysinfo power-supply",
    
    # System Logs
    "system_log": "diagnose sys log last 10",
    "alert_log": "diagnose sys log last 10 alert",
    "error_log": "diagnose sys log last 10 error",
    "traffic_log": "diagnose sys log last 10 traffic",
    "virus_log": "diagnose sys log last 10 virus",
    "attack_log": "diagnose sys log last 10 attack",
    
    # Additional Security Checks
    "ssl_certificates": "get system certificate local",
    "ssl_vpn_certificates": "get vpn ssl settings",
    "snmp_status": "get system snmp sysinfo",
    "firmware_status": "get system firmware",
    "update_status": "diagnose system update status"
}

class FortiGateHealthCheck:
    def __init__(self, max_retries: int = 3, retry_delay: int = 5):
        self.jumphost_client: Optional[paramiko.SSHClient] = None
        self.fortigate_shell: Optional[paramiko.Channel] = None
        self.direct_connection: bool = False
        self.max_retries = max_retries
        self.retry_delay = retry_delay

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
        """Establish direct SSH connection to FortiGate."""
        try:
            logger.info(f"Connecting directly to FortiGate {hostname}...")
            self.jumphost_client = paramiko.SSHClient()
            self.jumphost_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.jumphost_client.connect(
                hostname=hostname,
                username=username,
                password=password,
                look_for_keys=False,
                allow_agent=False
            )
            self.fortigate_shell = self.jumphost_client.invoke_shell()
            self.direct_connection = True
            logger.info("Successfully connected to FortiGate")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to FortiGate: {str(e)}")
            return False

    def connect_to_fortigate(self, hostname: str, username: str, password: str) -> bool:
        """Establish SSH connection to FortiGate through jumphost."""
        if self.direct_connection:
            return True

        try:
            if not self.jumphost_client:
                raise Exception("Jumphost connection not established")

            logger.info(f"Connecting to FortiGate {hostname} via jumphost...")
            self.fortigate_shell = self.jumphost_client.invoke_shell()
            
            # Wait for shell to be ready
            time.sleep(2)
            
            # Send SSH command to FortiGate
            self.fortigate_shell.send(f'ssh -o StrictHostKeyChecking=no {username}@{hostname}\n')
            time.sleep(2)
            
            # Read initial output
            output = self.fortigate_shell.recv(65535).decode('utf-8', errors='replace')
            
            # Handle password prompt
            if "password:" in output.lower():
                self.fortigate_shell.send(f"{password}\n")
                time.sleep(2)
                
                # Verify login success
                output = self.fortigate_shell.recv(65535).decode('utf-8', errors='replace')
                if "login:" in output.lower():
                    logger.error("Failed to authenticate with FortiGate")
                    return False
                
                logger.info("Successfully connected to FortiGate")
                return True
            else:
                logger.error("Password prompt not detected")
                return False

        except Exception as e:
            logger.error(f"Failed to connect to FortiGate: {str(e)}")
            return False

    def execute_command(self, command: str, timeout: int = 10) -> str:
        """Execute a command on the FortiGate and return the output."""
        if not self.fortigate_shell:
            raise Exception("FortiGate connection not established")

        try:
            self.fortigate_shell.send(f"{command}\n")
            time.sleep(1)  # Wait for command to start
            
            output = ""
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                if self.fortigate_shell.recv_ready():
                    chunk = self.fortigate_shell.recv(65535).decode('utf-8', errors='replace')
                    output += chunk
                    if "FortiGate" in chunk:  # Command prompt detected
                        break
                time.sleep(0.1)
            
            return output
        except Exception as e:
            logger.error(f"Error executing command '{command}': {str(e)}")
            return ""

    def execute_commands_concurrent(self, commands: Dict[str, str], max_workers: int = 5) -> Dict[str, str]:
        """Execute multiple commands concurrently."""
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
        data = {}
        
        # Firmware Version
        version_match = re.search(r"Version:\s+FortiOS[^\n]+", output)
        if version_match:
            data['firmware_version'] = version_match.group(0).split(':', 1)[1].strip()
        
        # License Status
        license_match = re.search(r"License Status:\s+(\w+)", output)
        if license_match:
            data['license_status'] = license_match.group(1)
        
        # System Time
        time_match = re.search(r"System Time:\s+([^\n]+)", output)
        if time_match:
            data['system_time'] = time_match.group(1)
        
        return data

    def parse_performance_status(self, output: str) -> Dict[str, Any]:
        """Parse the output of 'get system performance status' command."""
        data = {}
        
        # CPU Usage
        cpu_match = re.search(r"CPU states:\s*\d+%\s*user\s*\d+%\s*system\s*\d+%\s*nice\s*(\d+)%\s*idle", output)
        if cpu_match:
            data['cpu_idle'] = int(cpu_match.group(1))
            data['cpu_usage'] = 100 - int(cpu_match.group(1))
        
        # Memory Usage
        memory_match = re.search(r"Memory:\s*(\d+)%\s*used", output)
        if memory_match:
            data['memory_usage_percent'] = int(memory_match.group(1))
        
        # Conserve Mode
        conserve_match = re.search(r"memory-conserve-mode:\s*(\d)", output)
        if conserve_match:
            mode_map = {"0": "Normal", "1": "Conserve", "2": "Extreme Conserve"}
            data['conserve_mode'] = mode_map.get(conserve_match.group(1), "Unknown")
        
        return data

    def parse_license_status(self, output: str) -> Dict[str, Any]:
        """Parse the output of license status commands."""
        data = {
            'licenses': {},
            'fortiguard': {
                'services': {}
            }
        }
        
        # Parse main license status
        license_sections = output.split('License Information:')
        if len(license_sections) > 1:
            license_info = license_sections[1]
            
            # Extract license details
            current_license = None
            for line in license_info.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    
                    if key == 'license_type':
                        current_license = value
                        data['licenses'][current_license] = {
                            'status': 'Unknown',
                            'expiration_date': 'N/A',
                            'days_remaining': 'N/A'
                        }
                    elif current_license:
                        if key == 'status':
                            data['licenses'][current_license]['status'] = value
                        elif key == 'expiration_date':
                            data['licenses'][current_license]['expiration_date'] = value
                            try:
                                exp_date = datetime.strptime(value, '%Y-%m-%d')
                                days = (exp_date - datetime.now()).days
                                data['licenses'][current_license]['days_remaining'] = str(days)
                                if days <= 30:
                                    data['licenses'][current_license]['status'] = 'Warning'
                            except ValueError:
                                pass

        # Parse FortiGuard services
        fortiguard_section = output.split('FortiGuard Services:')
        if len(fortiguard_section) > 1:
            fortiguard_info = fortiguard_section[1]
            
            current_service = None
            for line in fortiguard_info.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    
                    if key == 'service':
                        current_service = value
                        data['fortiguard']['services'][current_service] = {
                            'status': 'Unknown',
                            'last_update': 'N/A',
                            'version': 'N/A'
                        }
                    elif current_service:
                        if key == 'status':
                            data['fortiguard']['services'][current_service]['status'] = value
                        elif key == 'last_update':
                            data['fortiguard']['services'][current_service]['last_update'] = value
                        elif key == 'version':
                            data['fortiguard']['services'][current_service]['version'] = value

        return data

    def parse_fortiguard_status(self, output: str) -> Dict[str, Any]:
        """Parse the output of FortiGuard status command."""
        data = {}
        
        # Extract FortiGuard service status
        service_match = re.search(r"FortiGuard Service Status:\s+(\w+)", output)
        if service_match:
            data['service_status'] = service_match.group(1)
        
        # Extract last update time
        update_match = re.search(r"Last Update:\s+([^\n]+)", output)
        if update_match:
            data['last_update'] = update_match.group(1)
        
        # Extract database versions
        db_versions = {}
        for db_type in ['Virus', 'IPS', 'Webfilter', 'Antispam']:
            version_match = re.search(fr"{db_type} Database Version:\s+([^\n]+)", output)
            if version_match:
                db_versions[db_type.lower()] = version_match.group(1)
        if db_versions:
            data['database_versions'] = db_versions
        
        return data

    def parse_ssl_certificates(self, output: str) -> Dict[str, Any]:
        """Parse the output of SSL certificate commands."""
        data = {
            'local_certificates': [],
            'ssl_vpn_certificates': {}
        }
        
        # Parse local certificates
        cert_blocks = output.split('Certificate Information:')
        for block in cert_blocks[1:]:  # Skip the first split which is before any certificate
            cert_data = {}
            
            # Extract certificate name
            name_match = re.search(r"Name:\s+([^\n]+)", block)
            if name_match:
                cert_data['name'] = name_match.group(1)
            
            # Extract validity period
            valid_from_match = re.search(r"Valid From:\s+([^\n]+)", block)
            valid_to_match = re.search(r"Valid To:\s+([^\n]+)", block)
            if valid_from_match and valid_to_match:
                cert_data['valid_from'] = valid_from_match.group(1)
                cert_data['valid_to'] = valid_to_match.group(1)
                
                # Calculate days until expiration
                try:
                    valid_to_date = datetime.strptime(cert_data['valid_to'], '%Y-%m-%d %H:%M:%S')
                    days_remaining = (valid_to_date - datetime.now()).days
                    cert_data['days_remaining'] = days_remaining
                    
                    # Add warning if certificate is expiring soon
                    if days_remaining <= 30:
                        cert_data['warning'] = f"Certificate expires in {days_remaining} days"
                except ValueError:
                    cert_data['warning'] = "Could not parse expiration date"
            
            if cert_data:
                data['local_certificates'].append(cert_data)
        
        return data

    def parse_ssl_vpn_certificates(self, output: str) -> Dict[str, Any]:
        """Parse the output of SSL VPN certificate settings."""
        data = {}
        
        # Extract server certificate
        server_cert_match = re.search(r"Server Certificate:\s+([^\n]+)", output)
        if server_cert_match:
            data['server_certificate'] = server_cert_match.group(1)
        
        # Extract client certificate requirements
        client_cert_match = re.search(r"Client Certificate Required:\s+(\w+)", output)
        if client_cert_match:
            data['client_certificate_required'] = client_cert_match.group(1)
        
        return data

    def parse_routing_table(self, output: str) -> Dict[str, Any]:
        """Parse the output of routing table commands."""
        data = {
            'routes': [],
            'summary': {
                'total_routes': 0,
                'static_routes': 0,
                'dynamic_routes': 0,
                'connected_routes': 0,
                'routes_by_protocol': {}
            }
        }
        
        current_route = {}
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Check for route entry
            if line.startswith('S') or line.startswith('C') or line.startswith('O') or line.startswith('B'):
                if current_route:
                    data['routes'].append(current_route)
                    # Update summary
                    data['summary']['total_routes'] += 1
                    protocol = current_route.get('protocol', 'Unknown')
                    data['summary']['routes_by_protocol'][protocol] = data['summary']['routes_by_protocol'].get(protocol, 0) + 1
                    
                    if protocol == 'Static':
                        data['summary']['static_routes'] += 1
                    elif protocol == 'Connected':
                        data['summary']['connected_routes'] += 1
                    else:
                        data['summary']['dynamic_routes'] += 1
                
                # Parse new route
                parts = line.split()
                if len(parts) >= 4:
                    current_route = {
                        'protocol': 'Static' if parts[0] == 'S' else 'Connected' if parts[0] == 'C' else 'OSPF' if parts[0] == 'O' else 'BGP',
                        'destination': parts[1],
                        'next_hop': parts[2],
                        'interface': parts[3],
                        'distance': parts[4] if len(parts) > 4 else 'N/A',
                        'metric': parts[5] if len(parts) > 5 else 'N/A'
                    }
            elif current_route:
                # Additional route information
                if ':' in line:
                    key, value = line.split(':', 1)
                    current_route[key.strip().lower()] = value.strip()
        
        # Add the last route
        if current_route:
            data['routes'].append(current_route)
            data['summary']['total_routes'] += 1
            protocol = current_route.get('protocol', 'Unknown')
            data['summary']['routes_by_protocol'][protocol] = data['summary']['routes_by_protocol'].get(protocol, 0) + 1
            
            if protocol == 'Static':
                data['summary']['static_routes'] += 1
            elif protocol == 'Connected':
                data['summary']['connected_routes'] += 1
            else:
                data['summary']['dynamic_routes'] += 1
        
        return data

    def parse_interface_health(self, output: str) -> Dict[str, Any]:
        """Parse the output of interface health commands."""
        data = {
            'interfaces': {},
            'summary': {
                'total_interfaces': 0,
                'healthy_interfaces': 0,
                'warning_interfaces': 0,
                'error_interfaces': 0
            }
        }
        
        current_interface = None
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Check for interface name
            if 'name:' in line.lower():
                current_interface = line.split(':', 1)[1].strip()
                data['interfaces'][current_interface] = {
                    'status': 'Unknown',
                    'health': 'Unknown',
                    'errors': {},
                    'stats': {},
                    'warnings': [],
                    'bandwidth': 'N/A',
                    'duplex': 'N/A',
                    'speed': 'N/A',
                    'autonegotiation': 'N/A',
                    'flow_control': 'N/A'
                }
                data['summary']['total_interfaces'] += 1
                continue
            
            if current_interface:
                # Parse health status
                if 'status:' in line.lower():
                    status = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['status'] = status
                    if status.lower() == 'up':
                        data['interfaces'][current_interface]['health'] = 'Healthy'
                        data['summary']['healthy_interfaces'] += 1
                    else:
                        data['interfaces'][current_interface]['health'] = 'Error'
                        data['summary']['error_interfaces'] += 1
                        data['interfaces'][current_interface]['warnings'].append(f"Interface is {status}")
                
                # Parse error counters
                if 'errors:' in line.lower():
                    errors = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['errors']['total'] = errors
                
                # Parse statistics
                if 'rx_bytes:' in line.lower():
                    rx_bytes = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['stats']['rx_bytes'] = rx_bytes
                elif 'tx_bytes:' in line.lower():
                    tx_bytes = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['stats']['tx_bytes'] = tx_bytes
                elif 'rx_errors:' in line.lower():
                    rx_errors = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['errors']['rx_errors'] = rx_errors
                    if int(rx_errors) > 0:
                        data['interfaces'][current_interface]['health'] = 'Warning'
                        data['summary']['warning_interfaces'] += 1
                        data['interfaces'][current_interface]['warnings'].append(f"RX errors: {rx_errors}")
                elif 'tx_errors:' in line.lower():
                    tx_errors = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['errors']['tx_errors'] = tx_errors
                    if int(tx_errors) > 0:
                        data['interfaces'][current_interface]['health'] = 'Warning'
                        data['summary']['warning_interfaces'] += 1
                        data['interfaces'][current_interface]['warnings'].append(f"TX errors: {tx_errors}")
                # Parse additional metrics
                elif 'bandwidth:' in line.lower():
                    bandwidth = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['bandwidth'] = bandwidth
                elif 'duplex:' in line.lower():
                    duplex = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['duplex'] = duplex
                elif 'speed:' in line.lower():
                    speed = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['speed'] = speed
                elif 'autonegotiation:' in line.lower():
                    autoneg = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['autonegotiation'] = autoneg
                elif 'flow_control:' in line.lower():
                    flow_control = line.split(':', 1)[1].strip()
                    data['interfaces'][current_interface]['flow_control'] = flow_control
        
        return data

    def parse_memory_usage(self, output: str) -> Dict[str, Any]:
        """Parse the output of memory usage command."""
        data = {
            'memory': {
                'total': 'N/A',
                'used': 'N/A',
                'free': 'N/A',
                'usage_percent': 0,
                'buffer': 'N/A',
                'cache': 'N/A'
            },
            'swap': {
                'total': 'N/A',
                'used': 'N/A',
                'free': 'N/A',
                'usage_percent': 0
            },
            'warnings': []
        }
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            if 'Mem:' in line:
                parts = line.split()
                if len(parts) >= 7:
                    data['memory']['total'] = parts[1]
                    data['memory']['used'] = parts[2]
                    data['memory']['free'] = parts[3]
                    data['memory']['buffer'] = parts[5]
                    data['memory']['cache'] = parts[6]
                    
                    # Calculate usage percentage
                    try:
                        total = int(parts[1])
                        used = int(parts[2])
                        data['memory']['usage_percent'] = (used / total) * 100
                        
                        # Add warning if memory usage is high
                        if data['memory']['usage_percent'] > 80:
                            data['warnings'].append(f"High memory usage: {data['memory']['usage_percent']:.1f}%")
                    except ValueError:
                        pass
                    
            elif 'Swap:' in line:
                parts = line.split()
                if len(parts) >= 4:
                    data['swap']['total'] = parts[1]
                    data['swap']['used'] = parts[2]
                    data['swap']['free'] = parts[3]
                    
                    # Calculate swap usage percentage
                    try:
                        total = int(parts[1])
                        used = int(parts[2])
                        data['swap']['usage_percent'] = (used / total) * 100
                        
                        # Add warning if swap usage is high
                        if data['swap']['usage_percent'] > 50:
                            data['warnings'].append(f"High swap usage: {data['swap']['usage_percent']:.1f}%")
                    except ValueError:
                        pass
        
        return data

    def parse_disk_usage(self, output: str) -> Dict[str, Any]:
        """Parse the output of disk usage command."""
        data = {
            'disks': [],
            'warnings': []
        }
        
        current_disk = {}
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('/'):
                if current_disk:
                    data['disks'].append(current_disk)
                
                parts = line.split()
                if len(parts) >= 5:
                    current_disk = {
                        'filesystem': parts[0],
                        'size': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'use_percent': parts[4].rstrip('%'),
                        'mount_point': parts[5] if len(parts) > 5 else 'N/A'
                    }
                    
                    # Add warning if disk usage is high
                    try:
                        use_percent = float(current_disk['use_percent'])
                        if use_percent > 80:
                            data['warnings'].append(f"High disk usage on {current_disk['filesystem']}: {use_percent}%")
                    except ValueError:
                        pass
        
        # Add the last disk
        if current_disk:
            data['disks'].append(current_disk)
        
        return data

    def parse_process_list(self, output: str) -> Dict[str, Any]:
        """Parse the output of process list command."""
        data = {
            'processes': [],
            'summary': {
                'total_processes': 0,
                'high_cpu_processes': 0,
                'high_memory_processes': 0
            },
            'warnings': []
        }
        
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('PID'):
                continue
            
            parts = line.split()
            if len(parts) >= 6:
                process = {
                    'pid': parts[0],
                    'user': parts[1],
                    'cpu_percent': parts[2],
                    'memory_percent': parts[3],
                    'vsz': parts[4],
                    'rss': parts[5],
                    'command': ' '.join(parts[6:])
                }
                
                data['processes'].append(process)
                data['summary']['total_processes'] += 1
                
                # Check for high resource usage
                try:
                    cpu_percent = float(process['cpu_percent'])
                    memory_percent = float(process['memory_percent'])
                    
                    if cpu_percent > 50:
                        data['summary']['high_cpu_processes'] += 1
                        data['warnings'].append(f"High CPU usage by {process['command']}: {cpu_percent}%")
                    
                    if memory_percent > 10:
                        data['summary']['high_memory_processes'] += 1
                        data['warnings'].append(f"High memory usage by {process['command']}: {memory_percent}%")
                except ValueError:
                    pass
        
        return data

    def parse_security_status(self, output: str, check_type: str) -> Dict[str, Any]:
        """Parse the output of security status commands."""
        data = {
            'status': 'Unknown',
            'last_update': 'N/A',
            'version': 'N/A',
            'signatures': 'N/A',
            'warnings': []
        }
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            if 'status:' in line.lower():
                data['status'] = line.split(':', 1)[1].strip()
                if data['status'].lower() != 'active':
                    data['warnings'].append(f"{check_type} status is not active: {data['status']}")
            elif 'last update:' in line.lower():
                data['last_update'] = line.split(':', 1)[1].strip()
            elif 'version:' in line.lower():
                data['version'] = line.split(':', 1)[1].strip()
            elif 'signatures:' in line.lower():
                data['signatures'] = line.split(':', 1)[1].strip()
        
        return data

    def run_health_check(self) -> Dict[str, Any]:
        """Run all health check commands and collect results."""
        health_data = {}
        
        try:
            # Execute commands concurrently
            command_outputs = self.execute_commands_concurrent(FORTIGATE_CLI_COMMANDS)
            
            # Parse outputs
            for check_name, output in command_outputs.items():
                logger.info(f"Parsing health check: {check_name}")
                
                if check_name == "system_status":
                    health_data[check_name] = self.parse_system_status(output)
                elif check_name == "performance_status":
                    health_data[check_name] = self.parse_performance_status(output)
                elif check_name == "license_status":
                    health_data[check_name] = self.parse_license_status(output)
                elif check_name == "license_fortiguard":
                    health_data[check_name] = self.parse_fortiguard_status(output)
                elif check_name == "ssl_certificates":
                    health_data[check_name] = self.parse_ssl_certificates(output)
                elif check_name == "ssl_vpn_certificates":
                    health_data[check_name] = self.parse_ssl_vpn_certificates(output)
                elif check_name == "interface_health":
                    health_data[check_name] = self.parse_interface_health(output)
                elif check_name == "routing_table":
                    health_data[check_name] = self.parse_routing_table(output)
                elif check_name == "memory_usage":
                    health_data[check_name] = self.parse_memory_usage(output)
                elif check_name == "disk_usage":
                    health_data[check_name] = self.parse_disk_usage(output)
                elif check_name == "process_list":
                    health_data[check_name] = self.parse_process_list(output)
                elif check_name in ["antivirus_status", "ips_status", "webfilter_status", "application_control"]:
                    health_data[check_name] = self.parse_security_status(output, check_name)
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
    """Print health check data with color coding."""
    print(f"\n{Fore.CYAN}=== FortiGate Health Check Report ==={Style.RESET_ALL}")
    
    for check_name, check_data in data.items():
        print(f"\n{Fore.GREEN}--- {check_name.replace('_', ' ').title()} ---{Style.RESET_ALL}")
        
        if isinstance(check_data, dict):
            for key, value in check_data.items():
                if isinstance(value, list):
                    print(f"\n{Fore.YELLOW}{key.replace('_', ' ').title()}:{Style.RESET_ALL}")
                    for item in value:
                        if isinstance(item, dict):
                            for subkey, subvalue in item.items():
                                color = Fore.RED if 'warning' in subkey.lower() else Fore.WHITE
                                print(f"  {color}{subkey.replace('_', ' ').title()}: {subvalue}{Style.RESET_ALL}")
                        else:
                            print(f"  {Fore.WHITE}{item}{Style.RESET_ALL}")
                elif isinstance(value, dict):
                    print(f"\n{Fore.YELLOW}{key.replace('_', ' ').title()}:{Style.RESET_ALL}")
                    for subkey, subvalue in value.items():
                        color = Fore.RED if 'warning' in subkey.lower() else Fore.WHITE
                        print(f"  {color}{subkey.replace('_', ' ').title()}: {subvalue}{Style.RESET_ALL}")
                else:
                    color = Fore.RED if 'warning' in key.lower() else Fore.WHITE
                    print(f"{color}{key.replace('_', ' ').title()}: {value}{Style.RESET_ALL}")
        else:
            print(f"{Fore.WHITE}Raw Data: {check_data}{Style.RESET_ALL}")

def load_config(config_file: str = 'fortigate_config.ini') -> dict:
    """Load configuration from file."""
    config = {
        'jumphost': None,
        'jumphost_user': None,
        'fortigate': None,
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
                'fortigate': parser['Connection'].get('fortigate'),
                'fortigate_user': parser['Connection'].get('fortigate_user')
            })
        
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
    parser.add_argument('--fortigate', help='FortiGate IP/Hostname')
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
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with command line arguments
    for key, value in vars(args).items():
        if value is not None and key != 'config' and key != 'save_config':
            config[key] = value
    
    return args, config

def save_config(config: dict, config_file: str = 'fortigate_config.ini'):
    """Save configuration to file."""
    parser = configparser.ConfigParser()
    
    # Connection settings
    parser['Connection'] = {
        'jumphost': config.get('jumphost', ''),
        'jumphost_user': config.get('jumphost_user', ''),
        'fortigate': config.get('fortigate', ''),
        'fortigate_user': config.get('fortigate_user', '')
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

def generate_text_report(data: Dict[str, Any], filename: str):
    """Generate a text report from health check data."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            # Write header
            f.write("=" * 80 + "\n")
            f.write("FortiGate Health Check Report\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # System Resources Section
            if 'memory_usage' in data:
                f.write("\n" + "=" * 80 + "\n")
                f.write("SYSTEM RESOURCES\n")
                f.write("=" * 80 + "\n")
                f.write(f"Data collected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                # Memory Usage
                f.write("Memory Usage:\n")
                f.write("-" * 40 + "\n")
                memory_data = data['memory_usage']
                f.write(f"Total Memory: {memory_data['memory']['total']}\n")
                f.write(f"Used Memory: {memory_data['memory']['used']}\n")
                f.write(f"Free Memory: {memory_data['memory']['free']}\n")
                f.write(f"Memory Usage: {memory_data['memory']['usage_percent']:.1f}%\n")
                f.write(f"Buffer: {memory_data['memory']['buffer']}\n")
                f.write(f"Cache: {memory_data['memory']['cache']}\n\n")

                # Swap Usage
                f.write("Swap Usage:\n")
                f.write("-" * 40 + "\n")
                f.write(f"Total Swap: {memory_data['swap']['total']}\n")
                f.write(f"Used Swap: {memory_data['swap']['used']}\n")
                f.write(f"Free Swap: {memory_data['swap']['free']}\n")
                f.write(f"Swap Usage: {memory_data['swap']['usage_percent']:.1f}%\n\n")

                # Warnings
                if memory_data['warnings']:
                    f.write("Memory Warnings:\n")
                    for warning in memory_data['warnings']:
                        f.write(f"  - {warning}\n")
                    f.write("\n")

            # Disk Usage Section
            if 'disk_usage' in data:
                f.write("\nDisk Usage:\n")
                f.write("-" * 40 + "\n")
                disk_data = data['disk_usage']
                for disk in disk_data['disks']:
                    f.write(f"Filesystem: {disk['filesystem']}\n")
                    f.write(f"Size: {disk['size']}\n")
                    f.write(f"Used: {disk['used']}\n")
                    f.write(f"Available: {disk['available']}\n")
                    f.write(f"Use%: {disk['use_percent']}%\n")
                    f.write(f"Mount Point: {disk['mount_point']}\n")
                    f.write("-" * 40 + "\n")

                if disk_data['warnings']:
                    f.write("\nDisk Warnings:\n")
                    for warning in disk_data['warnings']:
                        f.write(f"  - {warning}\n")
                    f.write("\n")

            # Process List Section
            if 'process_list' in data:
                f.write("\nProcess List:\n")
                f.write("-" * 40 + "\n")
                process_data = data['process_list']
                f.write(f"Total Processes: {process_data['summary']['total_processes']}\n")
                f.write(f"High CPU Processes: {process_data['summary']['high_cpu_processes']}\n")
                f.write(f"High Memory Processes: {process_data['summary']['high_memory_processes']}\n\n")

                f.write("Top Processes:\n")
                for process in process_data['processes'][:10]:  # Show top 10 processes
                    f.write(f"PID: {process['pid']}\n")
                    f.write(f"User: {process['user']}\n")
                    f.write(f"CPU%: {process['cpu_percent']}\n")
                    f.write(f"Memory%: {process['memory_percent']}\n")
                    f.write(f"Command: {process['command']}\n")
                    f.write("-" * 40 + "\n")

                if process_data['warnings']:
                    f.write("\nProcess Warnings:\n")
                    for warning in process_data['warnings']:
                        f.write(f"  - {warning}\n")
                    f.write("\n")

            # Security Status Section
            if any(key in data for key in ['antivirus_status', 'ips_status', 'webfilter_status', 'application_control']):
                f.write("\n" + "=" * 80 + "\n")
                f.write("SECURITY STATUS\n")
                f.write("=" * 80 + "\n")
                f.write(f"Data collected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                for check_type in ['antivirus_status', 'ips_status', 'webfilter_status', 'application_control']:
                    if check_type in data:
                        f.write(f"{check_type.replace('_', ' ').title()}:\n")
                        f.write("-" * 40 + "\n")
                        security_data = data[check_type]
                        f.write(f"Status: {security_data['status']}\n")
                        f.write(f"Last Update: {security_data['last_update']}\n")
                        f.write(f"Version: {security_data['version']}\n")
                        f.write(f"Signatures: {security_data['signatures']}\n")
                        
                        if security_data['warnings']:
                            f.write("\nWarnings:\n")
                            for warning in security_data['warnings']:
                                f.write(f"  - {warning}\n")
                        f.write("\n")

            # Rest of the report sections...
            # ... (keep the existing code for other sections)

        logger.info(f"Text report generated: {filename}")
        return True
    except Exception as e:
        logger.error(f"Error generating text report: {str(e)}")
        return False

def main():
    args, config = parse_arguments()
    
    # Set up logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    health_checker = FortiGateHealthCheck(
        max_retries=config['max_retries'],
        retry_delay=config['retry_delay']
    )
    
    try:
        # If jumphost is specified in config or args, use it
        use_jumphost = bool(config['jumphost'])
        
        # If no jumphost specified, ask the user
        if not use_jumphost:
            jumphost_response = input("Do you need to connect through a jumphost? (yes/no): ").lower()
            use_jumphost = jumphost_response in ['yes', 'y']
        
        if use_jumphost:
            # Get jumphost details from config or prompt
            jumphost_ip = config['jumphost'] or input("Enter Jumphost IP/Hostname: ")
            jumphost_user = config['jumphost_user'] or input("Enter Jumphost Username: ")
            jumphost_password = getpass.getpass(f"Enter Password for {jumphost_user}@{jumphost_ip}: ")
            
            # Prompt for verification code
            verification_code = input("Enter verification code (if required, press Enter to skip): ")
            if not verification_code:
                verification_code = None
            
            # Connect to jumphost
            if not health_checker.connect_with_retry(
                health_checker.connect_to_jumphost,
                jumphost_ip, jumphost_user, jumphost_password, verification_code
            ):
                logger.error("Failed to connect to jumphost. Exiting...")
                return
            
            # Get FortiGate details
            fortigate_ip = config['fortigate'] or input("Enter FortiGate IP: ")
            fortigate_user = config['fortigate_user'] or input(f"Enter FortiGate Username for {fortigate_ip}: ")
            fortigate_password = getpass.getpass(f"Enter FortiGate Password for {fortigate_user}@{fortigate_ip}: ")
            
            # Connect to FortiGate through jumphost
            if not health_checker.connect_with_retry(
                health_checker.connect_to_fortigate,
                fortigate_ip, fortigate_user, fortigate_password
            ):
                logger.error("Failed to connect to FortiGate. Exiting...")
                return
        else:
            # Get FortiGate details for direct connection
            fortigate_ip = config['fortigate'] or input("Enter FortiGate IP: ")
            fortigate_user = config['fortigate_user'] or input(f"Enter FortiGate Username for {fortigate_ip}: ")
            fortigate_password = getpass.getpass(f"Enter FortiGate Password for {fortigate_user}@{fortigate_ip}: ")
            
            # Connect directly to FortiGate
            if not health_checker.connect_with_retry(
                health_checker.connect_direct_to_fortigate,
                fortigate_ip, fortigate_user, fortigate_password
            ):
                logger.error("Failed to connect to FortiGate. Exiting...")
                return
        
        # Setup FortiGate session
        if not health_checker.setup_fortigate_session():
            logger.error("Failed to setup FortiGate session. Exiting...")
            return
        
        # Run health check
        health_data = health_checker.run_health_check()
        
        # Display results if not in quiet mode
        if not args.quiet:
            print_colored_output(health_data)
        
        # Generate text report
        report_filename = f"fortigate_health_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        if generate_text_report(health_data, report_filename):
            print(f"\nText report generated: {report_filename}")
        else:
            print("\nFailed to generate text report")
        
        # Export results if requested
        if args.export_json:
            health_checker.export_to_json(health_data, args.export_json)
        if args.export_csv:
            health_checker.export_to_csv(health_data, args.export_csv)
        
        # Save configuration if requested
        if args.save_config:
            save_config(config, args.config)
    
    except KeyboardInterrupt:
        logger.info("Health check interrupted by user")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
    finally:
        health_checker.close_connections()

if __name__ == "__main__":
    main() 