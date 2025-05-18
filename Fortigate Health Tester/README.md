# FortiGate Health Check Script

This Python script automates health checks for FortiGate firewalls by connecting through an SSH jumphost. It collects and analyzes various system metrics and presents them in a human-readable format.

## Features

- Connects to FortiGate through an SSH jumphost
- Collects comprehensive health metrics including:
  - System status and firmware version
  - Performance metrics (CPU, Memory, Conserve Mode)
  - HA status
  - Interface status
  - VPN/IPsec status
  - Routing table
  - Hardware health
  - Session statistics
  - Log disk status
  - NTP status
- Secure password handling
- Detailed logging
- Human-readable output format

## Requirements

- Python 3.6 or higher
- Required Python packages (install via `pip install -r requirements.txt`):
  - paramiko
  - getpass4

## Installation

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd fortigate-health-check
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the script:
```bash
python fortigate_health_check.py
```

The script will prompt you for:
1. Jumphost details:
   - IP address or hostname
   - Username
   - Password
2. FortiGate details:
   - IP address
   - Username
   - Password

After successful connection, the script will:
1. Configure the FortiGate session
2. Run all health check commands
3. Parse and display the results
4. Log all activities to `fortigate_health_check.log`

## Output

The script provides a detailed health check report including:
- System status and version information
- Performance metrics
- Interface status
- VPN/IPsec status
- And more...

All activities are logged to both the console and `fortigate_health_check.log` file.

## Security Notes

- Passwords are handled securely using Python's `getpass` module
- SSH connections are established with strict host key checking disabled for the FortiGate connection
- All sensitive information is handled in memory only and not stored on disk

## Error Handling

The script includes comprehensive error handling for:
- Connection failures
- Authentication errors
- Command execution errors
- Parsing errors

All errors are logged with appropriate context for troubleshooting.

## Contributing

Feel free to submit issues and enhancement requests! 