# FortiGate Health Check Tool

This tool performs a comprehensive health check on FortiGate devices, collecting and analyzing various system metrics, performance data, and configuration information.

## Prerequisites

- Python 3.6 or higher
- Required Python packages:
  - paramiko
  - colorama
  - typing
  - logging
  - argparse
  - json
  - csv
  - concurrent.futures

Install the required packages using pip:
```bash
pip install paramiko colorama reportlab
```

## Features

- Direct connection to FortiGate or connection through a jumphost
- Support for verification codes when connecting through jumphost
- **Dynamic SSH Prompt Detection**: More robust handling of FortiGate prompts
- **Configuration File**: Supports `fortigate_config.ini` for persistent storage of connection details and script settings
- **Comprehensive Health Checks**:
  - **System Status**: Firmware, basic license, uptime, HA details, hostname, model, serial number
  - **Performance Metrics**: Overall CPU, memory usage, and conserve mode status
  - **Detailed License Status**: In-depth FortiCare license information and FortiGuard service status (reachability, account status, DB versions)
  - **HA Status & Checksum**: General HA status and `diagnose sys ha checksum show` for configuration synchronization
  - **Interface Health**: Detailed physical NIC status from `diagnose hardware deviceinfo nic`, including link status, speed/duplex, errors, and discards
  - **Routing Table Analysis**: Parses `get router info routing-table all` for connected, static, BGP, OSPF routes, and flags recursive or blackhole routes
  - **Resource Usage**:
    - Top Memory Consuming Processes (`diagnose sys top-mem 10`)
    - Disk Usage (`diagnose sys df`) for all partitions
    - Top CPU Consuming Processes (`diagnose sys top -n 10`)
    - Session Usage (`diagnose sys session stat`)
    - Log Disk Status (`diagnose log disk status`)
  - **Security Service Status**:
    - Antivirus, IPS, Webfilter, Application Control status and signature versions
  - **VPN Status**:
    - SSL VPN settings (including server certificate in use via `get vpn ssl settings`)
    - SSL VPN statistics
    - IPsec tunnel summary
  - **System Services**: DNS, NTP, FortiGuard connectivity
  - **Hardware Health**: Overall hardware health status
  - **Certificate Information**: Lists local SSL certificates (`get system certificate local`)
  - **Firmware & Update Status**: Firmware version and `diagnose autoupdate versions`
- **Severity Levels & Recommendations**:
  - Findings are categorized by severity: INFO, LOW, MEDIUM, HIGH, CRITICAL
  - Actionable recommendations are provided for many findings
- **Output Options**:
  - **Colored Console Output**: Rich, color-coded terminal output for immediate insights, with overall status per check
  - **Detailed Text Report**: Generates a comprehensive plain text file (e.g., `fortigate_health_report_YYYYMMDD_HHMMSS.txt`)
  - **JSON Export**: Machine-readable output of all collected data
  - **CSV Export**: Basic export of key metrics
  - (PDF Report generation is a planned feature, currently a placeholder)
- **Concurrency**: Uses `concurrent.futures` for running commands (currently limited to serial execution for prompt stability)
- **Detailed Logging**: Comprehensive logging to `fortigate_health_check.log`
- **Argument Parsing**: Flexible command-line arguments using `argparse`
- **Error Handling**: Improved error messages within parsers and connection logic

- **Flexible IP/Hostname Input**:
  - Multiple target devices (IPs or FQDNs) can be processed in a single run.
  - IPs/Hostnames can be provided via:
    - Comma-separated list in `fortigate_config.ini` (e.g., `fortigate = 1.1.1.1, device.example.com, 2.2.2.2`).
    - Comma-separated list via the `--fortigate` command-line argument.
    - Interactive prompt: Choose to enter a comma-separated list or specify a path to a text file.
  - **Text File Input**: Load IPs/Hostnames from a `.txt` file (one entry per line; comments with `#` and empty lines ignored).
  - **Sample File Generation**: If loading from a non-existent text file, the script offers to create a sample file with formatting instructions.
  - **Input Validation**: All IP/Hostname inputs are validated for correct syntax (IPv4, IPv6, basic FQDN). Invalid entries are logged and skipped.

## Usage

### Providing Target FortiGate IPs/Hostnames

There are several ways to specify the FortiGate devices to check:

1.  **Configuration File (`fortigate_config.ini`)**: This is recommended for managing a list of devices.
    ```ini
    [Connection]
    jumphost = your.jumphost.ip_or_hostname  ; Optional
    jumphost_user = your_jumphost_username    ; Optional
    fortigate = 192.168.1.10, device1.example.com, 10.0.5.30 ; Comma-separated IPs/Hostnames
    fortigate_user = admin                    ; Common username for all FortiGates
    ```
2.  **Command-Line Argument (`--fortigate`)**:
    ```bash
    python fortigate_health_check.py --fortigate "192.168.1.10,device.example.com"
    ```
3.  **Interactive Prompt**: If no IPs/Hostnames are found from the config file or CLI, the script will ask:
    ```
    How do you want to provide FortiGate IPs/Hostnames?
    1. Enter comma-separated list
    2. Load from a text file
    Enter choice (1 or 2):
    ```
    - If you choose `1`, you'll be prompted to type or paste a comma-separated list.
    - If you choose `2`, you'll be prompted for the path to a text file. If the file doesn't exist, you'll be asked if you want to create a sample file at that path. The script will then exit for you to populate the file.
      Example `your_ips.txt` content:
      ```
      # My FortiGates
      192.168.1.10
      device1.example.com
      # 10.0.5.30  (This one is commented out)
      ```

### Configuration File (Recommended)

1. Run the script:
```bash
python fortigate_health_check.py
```

2. Follow the interactive prompts:
   - Enter jumphost details (if using jumphost):
     - Jumphost IP/Hostname
     - Jumphost Username
     - Jumphost Password
     - Verification Code (if required)
   - Enter FortiGate details:
     - FortiGate IP
     - FortiGate Username
     - FortiGate Password
   - **Save Configuration**: Optionally save these settings to `fortigate_config.ini` for future use

### Command Line Arguments

The script supports various command-line arguments to customize its behavior and provide connection details directly
Use `python fortigate_health_check.py --help` for a full list

Key arguments:
- `--jumphost <ip>`: Jumphost IP/Hostname
- `--jumphost-user <user>`: Jumphost username
- `--fortigate <ip_or_hostname_list>`: Comma-separated list of FortiGate IPs/Hostnames.
- `--fortigate-user <user>`: FortiGate username.
- `--config <file_path>`: Path to a custom configuration file (default: `fortigate_config.ini`).
- `--save-config`: Save the current connection and settings (from prompts or arguments) to the configuration file
- `--export-json <filename.json>`: Export results to a JSON file
- `--export-csv <filename.csv>`: Export results to a CSV file
- `--no-pdf`: Disable the placeholder PDF report generation
- `--pdf-dir <directory>`: Specify a directory to save PDF reports (when implemented)
- `--max-retries <num>`: Maximum connection retry attempts (default: 3)
- `--retry-delay <sec>`: Delay between retry attempts in seconds (default: 5)
- `--max-workers <num>`: Maximum concurrent command executions (default set to 1 for stability, see note in features)
- `--quiet`: Suppress console output (reports will still be generated)
- `--debug`: Enable debug level logging for more verbose output in the log file
- `--generate-sample-ip-file`: Standalone command to generate `sample_ip_list.txt` and exit. (Interactive creation is also available as described above).

### Examples

1. **First-time run, save configuration for multiple devices:**
   ```bash
   python fortigate_health_check.py --save-config
   ```
   (Follow prompts for jumphost (if any) and FortiGate details)

2. **Using a saved configuration (with multiple IPs in it) and exporting to JSON:**
   ```bash
   python fortigate_health_check.py --export-json report_output
   ```
   (This will generate `report_output_IP1.json`, `report_output_IP2.json`, etc.)

3. **Direct connection to a list of FortiGates, overriding saved config:**
   ```bash
   python fortigate_health_check.py --fortigate "192.168.1.1,192.168.1.2" --fortigate-user admin
   ```

4. **Connection through jumphost, loading IPs from a text file:**
   ```bash
   # First, ensure my_fortigates.txt exists and has IPs/hostnames, one per line.
   # If not, run and choose option 2 for IP input, then enter path, and script will offer to create it.
   python fortigate_health_check.py --jumphost 10.0.0.1 --jumphost-user jumpuser --fortigate-user admin
   ```
   (When prompted for IP input method, choose '2' and provide the path to `my_fortigates.txt`)

5. **Generate a sample IP list file directly:**
   ```bash
   python fortigate_health_check.py --generate-sample-ip-file
   ```

## Output

The script provides output in several formats:

1.  **Console Output**: Color-coded and structured display of health check results with severity levels and recommendations. Suppress with `--quiet`
2.  **Text Report**: A comprehensive plain text report saved to a timestamped file (e.g., `fortigate_health_report_YYYYMMDD_HHMMSS.txt`)
3.  **Log File**: Detailed operational logs saved to `fortigate_health_check.log`. Debug mode (`--debug`) increases verbosity
4.  **JSON File**: If `--export-json` is used, a JSON file containing all collected data, including raw outputs and parsed findings
5.  **CSV File**: If `--export-csv` is used, a CSV file with a summarized view of the data
6.  **(PDF File)**: Placeholder for future PDF report generation

### Sample Console Output Snippet

```
=== FortiGate Health Check Report ===

--- System Status (Overall: LOW) ---
  Firmware Version: FortiOS v6.4.5 build1828 (GA) (Severity: INFO)
  License Status: Valid (Severity: INFO)
    Recommendation: If license is invalid or expired, renew it immediately...
  Log Hard Disk: Need format (Severity: LOW)
    Recommendation: Format log disk if new or troubleshoot if it previously worked.

--- Interface Health (Overall: HIGH) ---
  Down Interfaces: 1 (Admin Down: 0) (Severity: HIGH)
    Recommendation: Investigate any non-administratively down interfaces...
  Interface Details:
    port2: Status - down, Speed - auto, Duplex - auto

--- Disk Usage (Overall: CRITICAL) ---
  Disk Partition: /var/log (/dev/log): Usage: 95% (Severity: CRITICAL)
    Recommendation: Disk usage for '/var/log' is critical...

[... additional sections ...]
```

### Sample Text Report Snippet

```
=== FortiGate Health Check Report ===

--- System Status (Overall: LOW) ---
  Firmware Version: FortiOS v6.4.5 build1828 (GA) (Severity: INFO)
  License Status: Valid (Severity: INFO)
    Recommendation: If license is invalid or expired, renew it immediately...
  Log Hard Disk: Need format (Severity: LOW)
    Recommendation: Format log disk if new or troubleshoot if it previously worked.

--- Interface Health (Overall: HIGH) ---
  Down Interfaces: 1 (Admin Down: 0) (Severity: HIGH)
    Recommendation: Investigate any non-administratively down interfaces...
  Interface Details:
    port2: Status - down, Speed - auto, Duplex - auto

--- Disk Usage (Overall: CRITICAL) ---
  Disk Partition: /var/log (/dev/log): Usage: 95% (Severity: CRITICAL)
    Recommendation: Disk usage for '/var/log' is critical...

[... additional sections ...]
```

## Security Notes

- Passwords are prompted for and not stored in the configuration file by default (they are used for the session only if entered via command line or prompt without saving)
- The script uses secure password input via `getpass`
- SSH connections are established with proper security settings
- All sensitive information is handled securely

## Troubleshooting

1. **Connection Issues**:
   - Verify network connectivity to jumphost/FortiGate
   - Check credentials
   - Ensure proper permissions
   - Verify verification code if required

2. **Command Execution Issues**:
   - Check FortiGate CLI permissions
   - Verify command availability on your FortiGate version
   - Review log file for detailed error messages

3. **Export Issues**:
   - Ensure write permissions in the target directory
   - Check available disk space
   - Verify file path validity

## Logging

The script creates a detailed log file (`fortigate_health_check.log`) that includes:
- Connection attempts and status
- Command execution results
- Error messages and stack traces
- General execution flow

Check this file for detailed troubleshooting information if issues occur.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 