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
    "system_status": "get system status",
    "performance_status": "get system performance status",
    "ha_status": "get system ha status",
    "interface_status": "get system interface",
    "ipsec_summary": "get vpn ipsec tunnel summary",
    "routing_table": "get router info routing-table all",
    "vpn_ike_gateway": "diagnose vpn ike gateway list",
    "vpn_tunnel_list": "diagnose vpn tunnel list",
    "hardware_health": "diagnose hardware deviceinfo health",
    "memory_status": "diagnose hardware sysinfo memory",
    "session_stats": "diagnose sys session stat",
    "log_disk_status": "diagnose sys logdisk status",
    "ntp_status": "diagnose sys ntp status",
    "license_status": "get system license status",
    "license_fortiguard": "get system fortiguard",
    "ssl_certificates": "get system certificate local",
    "ssl_vpn_certificates": "get vpn ssl settings"
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

    def connect_to_jumphost(self, hostname: str, username: str, password: str) -> bool:
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
            'fortiguard': {}
        }
        
        # Parse main license status
        license_sections = output.split('License Information:')
        if len(license_sections) > 1:
            license_info = license_sections[1]
            
            # Extract license details
            for line in license_info.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    if key and value:
                        data['licenses'][key] = value

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
            version_match = re.search(f"{db_type} Database Version:\s+([^\n]+)", output)
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
    
    # Other options
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum connection retry attempts')
    parser.add_argument('--retry-delay', type=int, default=5, help='Delay between retry attempts in seconds')
    parser.add_argument('--max-workers', type=int, default=5, help='Maximum concurrent command executions')
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    health_checker = FortiGateHealthCheck(max_retries=args.max_retries, retry_delay=args.retry_delay)
    
    try:
        # Determine connection method
        use_jumphost = bool(args.jumphost)
        
        if use_jumphost:
            # Get jumphost details from args or prompt
            jumphost_ip = args.jumphost or input("Enter Jumphost IP/Hostname: ")
            jumphost_user = args.jumphost_user or input("Enter Jumphost Username: ")
            jumphost_password = getpass.getpass(f"Enter Password for {jumphost_user}@{jumphost_ip}: ")
            
            # Connect to jumphost
            if not health_checker.connect_with_retry(
                health_checker.connect_to_jumphost,
                jumphost_ip, jumphost_user, jumphost_password
            ):
                logger.error("Failed to connect to jumphost. Exiting...")
                return
            
            # Get FortiGate details
            fortigate_ip = args.fortigate or input("Enter FortiGate IP: ")
            fortigate_user = args.fortigate_user or input(f"Enter FortiGate Username for {fortigate_ip}: ")
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
            fortigate_ip = args.fortigate or input("Enter FortiGate IP: ")
            fortigate_user = args.fortigate_user or input(f"Enter FortiGate Username for {fortigate_ip}: ")
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
        
        # Display results
        print_colored_output(health_data)
        
        # Export results if requested
        if args.export_json:
            health_checker.export_to_json(health_data, args.export_json)
        if args.export_csv:
            health_checker.export_to_csv(health_data, args.export_csv)
    
    except KeyboardInterrupt:
        logger.info("Health check interrupted by user")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
    finally:
        health_checker.close_connections()

if __name__ == "__main__":
    main() 