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
pip install paramiko colorama
```

## Features

- Direct connection to FortiGate or connection through a jumphost
- Support for verification codes when connecting through jumphost
- Comprehensive health checks including:
  - System status
  - Performance metrics
  - HA status
  - Interface status
  - VPN tunnel status
  - Hardware health
  - Memory status
  - License status
  - SSL certificate status
- Export results to JSON or CSV format
- Colored console output for better readability
- Detailed logging

## Usage

### Basic Usage

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

### Command Line Arguments

You can also provide the connection details as command line arguments:

```bash
python fortigate_health_check.py --jumphost <jumphost_ip> --jumphost-user <username> --fortigate <fortigate_ip> --fortigate-user <username>
```

Available arguments:
- `--jumphost`: Jumphost IP/Hostname
- `--jumphost-user`: Jumphost username
- `--fortigate`: FortiGate IP/Hostname
- `--fortigate-user`: FortiGate username
- `--export-json`: Export results to JSON file
- `--export-csv`: Export results to CSV file
- `--max-retries`: Maximum connection retry attempts (default: 3)
- `--retry-delay`: Delay between retry attempts in seconds (default: 5)
- `--max-workers`: Maximum concurrent command executions (default: 5)

### Examples

1. Direct connection to FortiGate:
```bash
python fortigate_health_check.py --fortigate 192.168.1.1 --fortigate-user admin
```

2. Connection through jumphost with export:
```bash
python fortigate_health_check.py --jumphost 10.0.0.1 --jumphost-user jumpuser --fortigate 192.168.1.1 --fortigate-user admin --export-json results.json
```

3. Full configuration with custom retry settings:
```bash
python fortigate_health_check.py --jumphost 10.0.0.1 --jumphost-user jumpuser --fortigate 192.168.1.1 --fortigate-user admin --max-retries 5 --retry-delay 10 --max-workers 8 --export-csv results.csv
```

## Output

The script provides output in three formats:

1. **Console Output**: Colored, formatted display of health check results
2. **Log File**: Detailed logs saved to `fortigate_health_check.log`
3. **Export Files**: JSON or CSV files (if export options are specified)

### Sample Console Output

```
=== FortiGate Health Check Report ===

--- System Status ---
Firmware Version: FortiOS v6.4.5
License Status: Valid
System Time: 2024-03-14 10:30:45

--- Performance Status ---
CPU Usage: 45%
Memory Usage: 60%
Conserve Mode: Normal

[... additional sections ...]
```

## Security Notes

- Passwords are never stored and are only used for the current session
- The script uses secure password input (hidden from console)
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