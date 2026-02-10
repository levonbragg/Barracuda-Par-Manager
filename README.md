# Barracuda PAR Manager

A command-line tool for parsing and extracting files from Barracuda backup archives (.par and .pca formats).

## Features

### Archive Management
- 📦 Parse unencrypted Barracuda PAR backup files (.par)
- 🔐 Decrypt and parse encrypted PCA backup files (.pca) using OpenSSL-compatible AES-256-CBC
- 📋 List archive contents with detailed file information
- 🌳 Display directory structure as a tree
- 📤 Extract individual files or entire archives
- 🔍 Compare two backup archives
- 🔒 Secure password prompting with hidden input

### Firewall Rule Analysis
- 🔥 Parse and display firewall rules with selective output options
- 🌐 Extract and display network objects (IPs, subnets, DNS names)
- 🔌 Extract and display service objects (TCP/UDP ports, protocols)
- 👥 Extract and display user objects (users, VPN users, groups)
- 🌍 Extract and display URL filtering objects (allow/block lists)
- 🔄 Compare firewall rules between backups
- 📊 Automatic format detection (Policy Profiles vs Legacy Application Rule Set)
- 📝 Support for both compact and diff-optimized output formats

## Installation

### Prerequisites

- Go 1.25 or later

### Build from Source

```bash
git clone https://github.com/levonbragg/Barracuda-Par-Manager.git
cd Barracuda-Par-Manager
go mod tidy
go build -o par_parser .
```

## Usage

### Basic Commands

```bash
# List all entries in an archive
./par_parser list backup.par

# Show file sizes
./par_parser list -s backup.par

# Display as tree structure
./par_parser tree backup.par

# Extract all files
./par_parser extract -o ./output backup.par

# Extract specific files (flat mode)
./par_parser extract -o ./output -F -f "*.conf" backup.par

# View file content
./par_parser cat backup.par path/to/file.conf

# Compare two backups
./par_parser diff old.par new.par
```

### Working with Encrypted Files (.pca)

```bash
# Interactive password prompt (recommended)
./par_parser list backup.pca
# You'll be prompted to enter the password securely

# Using password flag (for automation)
./par_parser list -P mypassword backup.pca
# Warning: This exposes the password in command history

# Extract from encrypted archive
./par_parser extract -o ./output backup.pca
```

### Firewall Rules

#### Basic Firewall Commands

```bash
# Show all firewall rules (networks, services, users, URLs, and rules)
./par_parser fwrules backup.par

# Show detailed firewall rules
./par_parser fwdetail backup.par

# Show in diff-optimized format
./par_parser fwrules -d backup.par

# Compare firewall rules between backups
./par_parser fwdiff old.par new.par
```

#### Selective Output with Flags

Show only specific sections by combining flags:

```bash
# Show only network objects
./par_parser fwrules -n backup.par

# Show only service objects
./par_parser fwrules -S backup.par

# Show only user objects
./par_parser fwrules -U backup.par

# Show only URL filtering objects
./par_parser fwrules -L backup.par

# Show only rules (no objects)
./par_parser fwrules -r backup.par

# Combine flags to show multiple sections
./par_parser fwrules -n -S -U backup.par
./par_parser fwrules -n -S -U -L backup.par
```

#### Dedicated Object Commands

For convenience, use dedicated commands for specific object types:

```bash
# Show only network objects
./par_parser fwnetworks backup.par

# Show only service objects
./par_parser fwservices backup.par

# Show only user objects
./par_parser fwusers backup.par

# Show only URL filtering objects
./par_parser fwurls backup.par

# Show only firewall rules (no objects)
./par_parser fwruleonly backup.par
```

#### Format Detection

The tool automatically detects the firewall format and adjusts output accordingly:

- **Policy Profiles Format** (new): Shows only URL Match Objects
- **Application Rule Set** (legacy): Shows both URL Policy Objects and Match Objects

Format type is displayed in the output header for all firewall commands.

## Creating Encrypted Archives

You can create encrypted .pca files using OpenSSL:

```bash
# Interactive password prompt
openssl enc -aes-256-cbc -salt -in backup.par -out backup.pca -md md5

# From stdin (for scripting)
echo "mypassword" | openssl enc -aes-256-cbc -salt -in backup.par -out backup.pca -pass stdin -md md5
```

**Note:** The `-md md5` flag is required for compatibility with the parser's key derivation.

## Command Reference

### Archive Commands

- `list` - List all entries in the archive
- `tree` - Show entries in tree structure
- `dirs` - List only directories
- `files` - List only files
- `cat` - Print file content to stdout
- `extract` - Extract files from archive
- `diff` - Compare two archives

### Firewall Commands

- `fwrules` - Show firewall rules in compact format (all objects + rules)
- `fwdetail` - Show firewall rules in detailed format
- `fwdiff` - Compare firewall rules between two backups
- `fwnetworks` - Show only network objects from firewall rules
- `fwservices` - Show only service objects from firewall rules
- `fwusers` - Show only user objects from firewall rules
- `fwurls` - Show only URL filtering objects from firewall rules
- `fwruleonly` - Show only firewall rules (no objects)

### General Options

- `-f, --filter <pattern>` - Filter entries by pattern
- `-o, --output <dir>` - Output directory for extraction
- `-s, --size` - Show file sizes in listing
- `-c, --content` - Show content differences in diff
- `-u, --unchanged` - Show unchanged files in diff
- `-e, --ext <extension>` - Filter files by extension
- `-F, --flat` - Extract files without directory structure
- `-P, --password <password>` - Password for encrypted .pca files

### Firewall Options

These options work with the `fwrules` command to show selective output:

- `-n, --networks` - Show only network objects
- `-S, --services` - Show only service objects
- `-U, --users` - Show only user objects
- `-L, --urls` - Show only URL filtering objects
- `-r, --rules` - Show only rules (no objects)
- `-d, --diffable` - Output in diff-optimized format
- `-p, --path <path>` - Path to fwrule file within archive

**Note:** Combine multiple flags to show specific sections (e.g., `-n -S -U` shows networks, services, and users)

## File Format Details

### .par Files (Unencrypted)

Barracuda PAR (Phionar Archive) format is a binary format that stores:
- File metadata (permissions, ownership, timestamps)
- Directory structure
- File contents
- Configuration files
- Firewall rules with comprehensive object definitions:
  - Network objects (IP addresses, subnets, DNS names)
  - Service objects (TCP/UDP ports, protocols, ICMP)
  - User objects (users, VPN users, groups)
  - URL filtering objects (policy objects and match conditions)

### .pca Files (Encrypted)

OpenSSL-compatible encrypted format:
- **Algorithm**: AES-256-CBC
- **Format**: `Salted__` (8 bytes) + salt (8 bytes) + encrypted data
- **Key Derivation**: EVP_BytesToKey with MD5 (for OpenSSL compatibility)
- **Padding**: PKCS7

### Firewall Object Types

The parser extracts and displays four types of firewall objects:

#### Network Objects
- IP addresses and subnets (e.g., `192.168.1.0/24`)
- DNS-based objects that resolve to IP addresses
- Network sets and groups
- References to other network objects

#### Service Objects
- TCP ports (e.g., `TCP/80`, `TCP/443`)
- UDP ports (e.g., `UDP/53`, `UDP/123`)
- ICMP protocol entries
- Port ranges and service groups
- References to other service objects

#### User Objects
- Regular users (`user:username`)
- VPN users (`vpn:username`)
- VPN groups (`vpngroup:groupname`)
- Groups (`group:groupname`)
- Wildcard patterns (`user:*`, `vpn:*`)

#### URL Filtering Objects
- **Policy Objects**: URL category policies with allow/block lists
- **Match Objects**: URL category conditions for matching traffic
- Domain names with actions (`[ALLOW]` or `[BLOCK]`)

**Format-Specific Behavior:**
- **Policy Profiles Format** (evalPolicyGlobal=1): Only Match Objects are displayed
- **Application Rule Set** (Legacy): Both Policy Objects and Match Objects are displayed

## Security

### Best Practices

1. **Use Interactive Prompts**: Prefer password prompts over `-P` flag to avoid exposing passwords in command history
2. **Strong Passwords**: Use passwords with at least 8 characters
3. **Secure Storage**: Store .pca files with appropriate file system permissions
4. **Clear History**: If you used the `-P` flag, clear your shell history

### Security Features

- Secure password input with hidden echo (using `golang.org/x/term`)
- Memory cleanup: Keys, IVs, and passwords are zeroed after use
- Warning messages when using insecure password methods
- No password leakage in error messages
- PKCS7 padding validation to detect incorrect passwords

## Documentation

- [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md) - Comprehensive usage examples

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) file for details

## Acknowledgments

- Built for parsing Barracuda Networks backup files
- OpenSSL-compatible encryption for broad compatibility
- Developed with security and usability in mind

## Support

For issues, questions, or contributions, please open an issue on GitHub.
