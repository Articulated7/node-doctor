# node-doctor
A security and configuration auditing tool for Tor relay operators.



## ⚠️ Project Status

**Early Development** - This tool is currently in active development and not yet ready for production use. 

## What is Node Doctor?

Node Doctor is an open-source tool designed to help Tor relay operators identify common misconfigurations, security issues, and operational problems with their relays. It performs automated checks across several categories:

- **Tor Configuration**: Validates your torrc settings and relay configuration
- **Host Security**: Checks SSH config, firewall rules, and system hardening
- **Information Leakage**: Identifies potential privacy issues in your setup
- **Operational Best Practices**: Ensures you’re following recommended practices

## Goals

- Help relay operators catch configuration mistakes before they become problems
- Improve overall Tor network security by making it easier to run relays correctly
- Provide clear, actionable recommendations for fixing issues
- Be transparent about what the tool checks and what access it requires

## Non-Goals

- This tool does NOT send any data externally
- This tool does NOT modify your configuration (read-only)
- This tool does NOT replace good operational security practices
- This tool is NOT an intrusion detection system

## Privacy & Transparency

**Node Doctor never does anything without your explicit permission:**

- ✅ Reads local Tor config files (basic scan)
- ⚠️ Reads system configs like SSH settings (only with `--system` flag, will prompt for sudo if needed)
- ⚠️ Makes external connections for version/DNS checks (only with `--network` flag, asks first)
- ❌ Never modifies any files
- ❌ Never sends data about your relay anywhere
- ❌ Never runs automatically or in the background

**What external connections might be made** (only with `--network` flag):

- Query Tor Project for current version information
- DNS lookups to check for leaks
- Connectivity tests to verify relay reachability

You can review the source code to verify exactly what happens during each check.

## Installation

*Coming soon - not yet ready for installation*

## Usage

```bash
# Basic checks (no special permissions required, no external connections)
node-doctor scan

# Include system-level checks (will prompt for sudo only if needed)
node-doctor scan --system

# Include network connectivity checks (will connect to external services)
node-doctor scan --network

# Full scan with all checks (will ask for confirmation before elevated access)
node-doctor scan --full
```

**The tool will always:**

- Clearly state what it’s about to do before doing it
- Ask for explicit confirmation before requiring sudo
- Ask for explicit confirmation before making external connections
- Show you exactly what commands/checks will run at elevated privilege
- Allow you to skip any check you’re not comfortable with

## Access Levels

Node Doctor is transparent about what it accesses:

- **Basic checks**: Read-only access to Tor configuration files
- **System checks**: Read-only access to system configs (SSH, firewall) - may require sudo
- **Network checks**: Makes external connections to verify connectivity and versions



## Disclaimer

This tool is provided as-is to help relay operators. It is not officially affiliated with or endorsed by The Tor Project. Always use your own judgment when operating a relay, and consult official Tor Project documentation.

Running this tool does not guarantee your relay is secure or properly configured. It’s one tool among many for maintaining good operational security.

## License

See LICENSE file for details

## Acknowledgments

Built with input from the Tor relay operator community. Thanks to all the operators who’ve shared their knowledge and experience.
