#!/usr/bin/env python3

import paramiko
import getpass
import re
import time
import logging
from typing import Dict, Any, Optional, Tuple

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
    "ntp_status": "diagnose sys ntp status"
}

class FortiGateHealthCheck:
    def __init__(self):
        self.jumphost_client: Optional[paramiko.SSHClient] = None
        self.fortigate_shell: Optional[paramiko.Channel] = None

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

    def connect_to_fortigate(self, hostname: str, username: str, password: str) -> bool:
        """Establish SSH connection to FortiGate through jumphost."""
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

    def run_health_check(self) -> Dict[str, Any]:
        """Run all health check commands and collect results."""
        health_data = {}
        
        try:
            for check_name, command in FORTIGATE_CLI_COMMANDS.items():
                logger.info(f"Running health check: {check_name}")
                output = self.execute_command(command)
                
                if check_name == "system_status":
                    health_data[check_name] = self.parse_system_status(output)
                elif check_name == "performance_status":
                    health_data[check_name] = self.parse_performance_status(output)
                else:
                    health_data[check_name] = {"raw_output": output}
                
                time.sleep(1)  # Prevent overwhelming the device
            
            return health_data
        except Exception as e:
            logger.error(f"Error during health check: {str(e)}")
            return {}

    def close_connections(self):
        """Close all SSH connections."""
        if self.fortigate_shell:
            self.fortigate_shell.close()
        if self.jumphost_client:
            self.jumphost_client.close()
        logger.info("All connections closed")

def main():
    health_checker = FortiGateHealthCheck()
    
    try:
        # Get jumphost details
        jumphost_ip = input("Enter Jumphost IP/Hostname: ")
        jumphost_user = input("Enter Jumphost Username: ")
        jumphost_password = getpass.getpass(f"Enter Password for {jumphost_user}@{jumphost_ip}: ")
        
        # Connect to jumphost
        if not health_checker.connect_to_jumphost(jumphost_ip, jumphost_user, jumphost_password):
            logger.error("Failed to connect to jumphost. Exiting...")
            return
        
        # Get FortiGate details
        fortigate_ip = input("Enter FortiGate IP: ")
        fortigate_user = input(f"Enter FortiGate Username for {fortigate_ip}: ")
        fortigate_password = getpass.getpass(f"Enter FortiGate Password for {fortigate_user}@{fortigate_ip}: ")
        
        # Connect to FortiGate
        if not health_checker.connect_to_fortigate(fortigate_ip, fortigate_user, fortigate_password):
            logger.error("Failed to connect to FortiGate. Exiting...")
            return
        
        # Setup FortiGate session
        if not health_checker.setup_fortigate_session():
            logger.error("Failed to setup FortiGate session. Exiting...")
            return
        
        # Run health check
        health_data = health_checker.run_health_check()
        
        # Display results
        print("\n=== FortiGate Health Check Report ===")
        for check_name, data in health_data.items():
            print(f"\n--- {check_name.replace('_', ' ').title()} ---")
            if isinstance(data, dict):
                for key, value in data.items():
                    print(f"{key.replace('_', ' ').title()}: {value}")
            else:
                print(f"Raw Data: {data}")
    
    except KeyboardInterrupt:
        logger.info("Health check interrupted by user")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
    finally:
        health_checker.close_connections()

if __name__ == "__main__":
    main() 