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

## Usage

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
- `--fortigate <ip>`: FortiGate IP/Hostname
- `--fortigate-user <user>`: FortiGate username
- `--config <file_path>`: Path to a custom configuration file (default: `fortigate_config.ini`)
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

### Examples

1. **First-time run with prompts, then save configuration:**
   ```bash
   python fortigate_health_check.py --save-config
   ```
   (Follow prompts for jumphost (if any) and FortiGate details)

2. **Using a saved configuration and exporting to JSON:**
   ```bash
   python fortigate_health_check.py --export-json report.json
   ```

3. **Direct connection to FortiGate, overriding saved config for this run:**
   ```bash
   python fortigate_health_check.py --fortigate 192.168.1.1 --fortigate-user admin
   ```

4. **Connection through jumphost with text report and debug logging:**
   ```bash
   python fortigate_health_check.py --jumphost 10.0.0.1 --jumphost-user jumpuser --fortigate 192.168.1.1 --fortigate-user admin --debug
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