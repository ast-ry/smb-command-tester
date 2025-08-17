# SMB2/3 Protocol Scanner and Functionality Testing Tool

## Overview

A comprehensive Python-based command-line tool for testing SMBv2/v3 protocol functionality and performing automated functionality testing. Built using the `impacket` library, it provides multiple operation modes for enterprise SMB server assessment and security testing.

### Key Features

1. **Automated Functionality Testing**: Comprehensive test suites for SMB2/3 protocol operations
2. **Interactive Command Mode**: Granular testing of specific SMB operations
3. **Advanced Authentication**: Support for NTLM, Kerberos, Pass-the-Hash, and Anonymous authentication
4. **Protocol Analysis**: SMB dialect detection and capability assessment
5. **Security Assessment**: File ownership analysis and security information retrieval

## Installation

This tool requires Python 3.6+ and the `impacket` library:

```bash
pip install impacket
```

## Quick Start

```bash
# Basic functionality scan with NTLM authentication
python smb_protocol_scanner.py scan -s server.example.com -u username -p password sharename

# Anonymous access dialect analysis
python smb_protocol_scanner.py dialect-scan -s server.example.com --auth-method anonymous

# Test multiple authentication methods
python smb_protocol_scanner.py auth-test -s server.example.com -u username -p password
```

## Authentication Methods

The tool supports multiple authentication methods for comprehensive security testing:

### NTLM Authentication (Default)
```bash
# Local NTLM authentication
python smb_protocol_scanner.py scan -s server -u username -p password sharename

# Domain NTLM authentication
python smb_protocol_scanner.py scan -s server -u username -p password -d DOMAIN sharename
```

### Kerberos Authentication
```bash
# Kerberos with password
python smb_protocol_scanner.py scan -s server --auth-method kerberos -u username -p password -d DOMAIN --kdc-host kdc.domain.com sharename

# Kerberos with AES key
python smb_protocol_scanner.py scan -s server --auth-method kerberos -u username -d DOMAIN --aes-key <hex_key> --kdc-host kdc.domain.com sharename
```

### Pass-the-Hash Authentication
```bash
python smb_protocol_scanner.py scan -s server --auth-method pass-the-hash -u username --nt-hash <nt_hash> -d DOMAIN sharename
```

### Anonymous Authentication
```bash
python smb_protocol_scanner.py scan -s server --auth-method anonymous sharename
```

## Command Reference

### Core Analysis Commands

#### `scan` - Comprehensive Functionality Testing
Performs automated testing of SMB2/3 protocol functionality with detailed reporting.

```bash
# Standard functionality scan
python smb_protocol_scanner.py scan -s <server> -u <user> -p <pass> <share>

# Full scan with all information levels
python smb_protocol_scanner.py scan -s <server> -u <user> -p <pass> <share> --full

# Anonymous scan
python smb_protocol_scanner.py scan -s <server> --auth-method anonymous <share>
```

**Output includes:**
- Protocol version and capabilities
- Authentication method used
- Success/failure rates for different SMB operations
- Detailed functionality assessment

#### `dialect-scan` - SMB Protocol Analysis
Analyzes supported SMB dialects and server capabilities.

```bash
# Comprehensive dialect analysis
python smb_protocol_scanner.py dialect-scan -s <server> -u <user> -p <pass>

# Show all known SMB dialects for reference
python smb_protocol_scanner.py dialect-scan -s <server> -u <user> -p <pass> --show-all
```

**Features:**
- SMB version detection (1.0, 2.0, 2.1, 3.0, 3.0.2, 3.1.1)
- Capability assessment (encryption, multi-channel, leases)
- Port-specific testing (445, 139)
- Security recommendations

### Authentication Testing Commands

#### `auth-test` - Multi-Method Authentication Testing
Tests multiple authentication methods against the target server.

```bash
python smb_protocol_scanner.py auth-test -s <server> -u <user> -p <pass>
```

#### `auth-verify` - Specific Authentication Verification
Verifies a specific authentication method works correctly.

```bash
# Verify Kerberos authentication
python smb_protocol_scanner.py auth-verify -s <server> --auth-method kerberos -u <user> -p <pass> -d <domain>

# Verify Pass-the-Hash authentication
python smb_protocol_scanner.py auth-verify -s <server> --auth-method pass-the-hash -u <user> --nt-hash <hash>
```

### File Operations

#### `query-dir` - Directory Listing
```bash
# List root directory of share
python smb_protocol_scanner.py query-dir -s <server> -u <user> -p <pass> <share>

# List specific subdirectory
python smb_protocol_scanner.py query-dir -s <server> -u <user> -p <pass> <share> "path\\to\\dir"
```

#### `read-file` / `write-file` - File I/O Operations
```bash
# Write content to a file
python smb_protocol_scanner.py write-file -s <server> -u <user> -p <pass> <share> "file.txt" "Content to write"

# Read file content
python smb_protocol_scanner.py read-file -s <server> -u <user> -p <pass> <share> "file.txt"

# Write with specific encoding
python smb_protocol_scanner.py write-file -s <server> -u <user> -p <pass> <share> "file.txt" "Content" --encoding utf-8

# Overwrite existing file
python smb_protocol_scanner.py write-file -s <server> -u <user> -p <pass> <share> "file.txt" "New content" --overwrite
```

#### `mkdir` / `delete` - Directory Management
```bash
# Create directory
python smb_protocol_scanner.py mkdir -s <server> -u <user> -p <pass> <share> "new_directory"

# Delete file
python smb_protocol_scanner.py delete -s <server> -u <user> -p <pass> <share> "file.txt"

# Delete directory
python smb_protocol_scanner.py delete -s <server> -u <user> -p <pass> <share> "directory" --is-dir
```

#### `rename` - File/Directory Renaming
```bash
python smb_protocol_scanner.py rename -s <server> -u <user> -p <pass> <share> "old_name.txt" "new_name.txt"

# With overwrite option
python smb_protocol_scanner.py rename -s <server> -u <user> -p <pass> <share> "old_name.txt" "new_name.txt" --overwrite
```

### Advanced Operations

#### `lock-file` / `unlock-file` - File Locking
*Note: File locking provides access verification and alternative guidance due to Impacket limitations.*

```bash
# Exclusive lock attempt
python smb_protocol_scanner.py lock-file -s <server> -u <user> -p <pass> <share> "file.txt" 0 1024

# Shared lock attempt
python smb_protocol_scanner.py lock-file -s <server> -u <user> -p <pass> <share> "file.txt" 0 1024 --shared

# Unlock
python smb_protocol_scanner.py unlock-file -s <server> -u <user> -p <pass> <share> "file.txt" 0 1024
```

#### `query-info` - File Information
```bash
python smb_protocol_scanner.py query-info -s <server> -u <user> -p <pass> <share> "file.txt"
```

#### `file-security` - Security Information
Retrieves file security and ownership information.

```bash
python smb_protocol_scanner.py file-security -s <server> -u <user> -p <pass> <share> "file.txt"
```

#### `query-ea` / `set-ea` - Extended Attributes
```bash
# Set Extended Attribute (value in hex)
python smb_protocol_scanner.py set-ea -s <server> -u <user> -p <pass> <share> "file.txt" "custom.attribute" "deadbeef"

# Query Extended Attributes
python smb_protocol_scanner.py query-ea -s <server> -u <user> -p <pass> <share> "file.txt"
```


## Connection Arguments Reference

All commands support these common connection arguments:

| Argument | Description | Default |
|----------|-------------|---------|
| `-s, --server` | SMB server IP/hostname | Required |
| `-P, --port` | SMB server port | 445 |
| `--auth-method` | Authentication method | ntlm |
| `-u, --user` | Username | "" |
| `-p, --password` | Password | "" |
| `-d, --domain` | Domain name | "" |
| `--lm-hash` | LM hash for pass-the-hash | None |
| `--nt-hash` | NT hash for pass-the-hash | None |
| `--kdc-host` | KDC hostname for Kerberos | None |
| `--aes-key` | AES key for Kerberos | None |

## Example Workflows

### Enterprise SMB Server Assessment
```bash
# 1. Initial dialect and capability analysis
python smb_protocol_scanner.py dialect-scan -s server.corp.com -u admin -p password

# 2. Authentication method testing
python smb_protocol_scanner.py auth-test -s server.corp.com -u admin -p password

# 3. Comprehensive functionality scan
python smb_protocol_scanner.py scan -s server.corp.com -u admin -p password shared_folder --full

# 4. Security information gathering
python smb_protocol_scanner.py file-security -s server.corp.com -u admin -p password shared_folder important_file.doc
```

### Anonymous Access Testing
```bash
# Test for anonymous access vulnerabilities
python smb_protocol_scanner.py dialect-scan -s target.com --auth-method anonymous
python smb_protocol_scanner.py scan -s target.com --auth-method anonymous public_share
```

### Pass-the-Hash Authentication Testing
```bash
# Test with hash-based credentials
python smb_protocol_scanner.py auth-verify -s server.com --auth-method pass-the-hash -u username --nt-hash <nt_hash>
```

## Output Interpretation

### Scan Results
- **SUCCESS**: Feature works correctly
- **NOT_SUPPORTED**: Feature not supported by server/client
- **FAIL**: Feature failed (potential security issue)
- **SKIPPED**: Test skipped due to prerequisites

### Protocol Analysis
- **SMB Version**: Detected protocol version (2.0, 2.1, 3.0, 3.0.2, 3.1.1)
- **Capabilities**: Supported features (encryption, multi-channel, leases)
- **Security Level**: Overall security assessment

### Authentication Results
- **Authentication Method**: Used authentication type
- **Protocol Version**: SMB version for the connection
- **Success Rate**: Percentage of successful operations

## Security Considerations

1. **Credential Protection**: Never use production credentials in testing
2. **Network Isolation**: Run tests in isolated network environments
3. **Logging**: Be aware that SMB activities may be logged by target servers
4. **Permission Impact**: Some tests create/delete files and directories
5. **Compliance**: Ensure testing authorization before scanning production systems

## Troubleshooting

### Common Issues

**Connection Refused**
- Check firewall settings (ports 445, 139)
- Verify SMB service is running
- Confirm network connectivity

**Authentication Failures**
- Verify credentials and domain settings
- Check authentication method compatibility
- Test with anonymous access first

**Permission Denied**
- Ensure user has appropriate share permissions
- Verify write access for scan operations
- Check file/directory ownership

## Technical Details

### Supported SMB Features
- **Protocol Versions**: SMB 2.0, 2.1, 3.0, 3.0.2, 3.1.1
- **Authentication**: NTLM, Kerberos, Pass-the-Hash, Anonymous
- **Operations**: File I/O, Directory management, Locking, Extended Attributes
- **Advanced**: IOCTL requests, Change notifications, Protocol negotiation

### Implementation Notes
- Built on Impacket library for cross-platform compatibility
- Handles SMB dialect negotiation automatically
- Provides fallback mechanisms for unsupported features
- Includes comprehensive error handling and reporting

### Performance Considerations
- Scan operations may take several minutes on large shares
- Network latency affects operation timing
- Use `--full` scan option cautiously on production systems

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

This tool is provided for legitimate security testing and system administration purposes. Users are responsible for ensuring appropriate authorization before testing any systems.