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
- **Critical Alert Banners**: If the FortiGate is detected to be in Memory Conserve Mode, a prominent banner is displayed at the top of both the console output and the text report for immediate attention.
- **Concurrency**: Uses `concurrent.futures` for running commands (currently limited to serial execution for prompt stability)
- **Detailed Logging**: Comprehensive logging to `fortigate_health_check.log`
- **Argument Parsing**: Flexible command-line arguments using `argparse`
- **Error Handling**: Improved error messages within parsers and connection logic

- **Configuration File (`fortigate_config.ini`)**: Supports an INI file for persistent storage of general script settings (like jumphost details, default FortiGate user, retry parameters) and can *optionally* contain a list of target FortiGate IPs/hostnames.
- **Flexible IP/Hostname Input Methods**:
  - Multiple target devices (IPs or FQDNs) can be processed in a single run.
  - Target IPs/Hostnames are determined with the following precedence:
    1.  **Command-Line**: Directly via the `--fortigate` argument (comma-separated).
    2.  **INI Configuration File**: From the `fortigate` key in `fortigate_config.ini` (if not overridden by CLI).
    3.  **Interactive Prompt (Fallback)**: If no IPs are provided by the above, choose to:
        -   Enter a comma-separated list directly.
        -   Load from a simple text file (`.txt`) with one IP/Hostname per line.
- **Sample IP File Generation**: If opting to load IPs from a text file and it doesn't exist, the script offers to create a sample file (e.g., `your_ips.txt`) with formatting instructions. The script then exits for you to populate this file.
- **Input Validation**: All IP/Hostname inputs (from any method) are validated for correct syntax (IPv4, IPv6, basic FQDN). Invalid entries are logged and skipped.
- **Critical Alert Banners**: If the FortiGate is detected to be in Memory Conserve Mode, a prominent banner is displayed at the top of both the console output and the text report for immediate attention.

## Usage

### Configuration File (`fortigate_config.ini`)

The script uses an INI file (default: `fortigate_config.ini`) for storing common settings. This file can define:
- Jumphost IP/Hostname and username.
- A common FortiGate username to be used for all targets.
- Script behavior like connection retries and delays.
- **Optionally**: A comma-separated list of FortiGate IPs/hostnames for the `fortigate` key under the `[Connection]` section.

**Example `fortigate_config.ini`:**
```ini
[Connection]
jumphost = your.jumphost.ip
jumphost_user = jumpadmin
fortigate = 192.168.1.10, fw.example.com ; This line is one way to list targets
fortigate_user = fg_admin

[Settings]
max_retries = 3
retry_delay = 5
```
- To save your current command-line settings or prompted inputs to this file, use the `--save-config` argument.
- To use a different INI file, use `--config /path/to/your_custom_config.ini`.

### Providing Target FortiGate IPs/Hostnames

The script determines the target FortiGate devices to check using the following order of precedence:

1.  **Command-Line Argument (`--fortigate`)**: This is the highest priority. If used, it overrides any IP list in the INI file.
    ```bash
    python fortigate_health_check.py --fortigate "192.168.1.10,device.example.com,10.0.0.1"
    ```

2.  **INI Configuration File (`fortigate` key)**: If the `--fortigate` argument is *not* used, the script looks for a `fortigate` key in the `[Connection]` section of your active INI file (e.g., `fortigate_config.ini`). The value should be a comma-separated list of IPs/hostnames.
    *(See INI example in the section above)*

3.  **Interactive Prompt (Fallback Method)**: If no IPs/Hostnames are specified via the command line OR in the INI file, the script will then prompt you:
    ```
    How do you want to provide FortiGate IPs/Hostnames?
    1. Enter comma-separated list
    2. Load from a text file
    Enter choice (1 or 2):
    ```
    -   **Choice 1 (Comma-separated list)**: You'll be prompted to type or paste a comma-separated list of IPs/Hostnames directly into the console. These will be validated.
    -   **Choice 2 (Load from a separate text file)**: 
        -   You'll be asked for the path to a simple text file (e.g., `my_devices.txt`).
        -   This `.txt` file should contain one IP address or FQDN per line.
        -   Lines starting with `#` are comments; empty lines are ignored. All entries are validated.
        -   **Automatic Sample File Creation**: If you provide a path to a `.txt` file that *does not exist*, the script will ask:
            `File 'my_devices.txt' not found. Create a sample file here? (yes/no):`
            If you answer `yes`, the script will create `my_devices.txt` with example formatting and instructions, then exit. You can then edit this file with your actual IPs/hostnames and re-run the health check script.

        **Example `my_devices.txt` content:**
        ```txt
        # List of FortiGates for health check
        192.168.1.10
        fw-branch.example.com
        # 10.0.5.30  (This one is currently commented out)
        2001:db8::100
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
*****************************************************************
CRITICAL ALERT: FORTIGATE IS IN MEMORY CONSERVE MODE!
(Detected via: Performance Status reports: Conserve)
*****************************************************************

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
********************************************************************************
CRITICAL ALERT: FORTIGATE IS IN MEMORY CONSERVE MODE!
(Detected via: Performance Status reports: Conserve)
********************************************************************************

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