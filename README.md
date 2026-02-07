# Barracuda PAR Manager

A command-line tool for parsing and extracting files from Barracuda backup archives (.par and .pca formats).

## Features

- 📦 Parse unencrypted Barracuda PAR backup files (.par)
- 🔐 Decrypt and parse encrypted PCA backup files (.pca) using OpenSSL-compatible AES-256-CBC
- 📋 List archive contents with detailed file information
- 🌳 Display directory structure as a tree
- 📤 Extract individual files or entire archives
- 🔍 Compare two backup archives
- 🔥 Parse and compare firewall rules from Barracuda backups
- 🔒 Secure password prompting with hidden input

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

```bash
# Show firewall rules in compact format
./par_parser fwrules backup.par

# Show detailed firewall rules
./par_parser fwdetail backup.par

# Compare firewall rules between backups
./par_parser fwdiff old.par new.par
```

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

### Commands

- `list` - List all entries in the archive
- `tree` - Show entries in tree structure
- `dirs` - List only directories
- `files` - List only files
- `cat` - Print file content to stdout
- `extract` - Extract files from archive
- `diff` - Compare two archives
- `fwrules` - Show firewall rules in compact format
- `fwdetail` - Show firewall rules in detailed format
- `fwdiff` - Compare firewall rules between two backups

### Options

- `-f, --filter <pattern>` - Filter entries by pattern
- `-o, --output <dir>` - Output directory for extraction
- `-s, --size` - Show file sizes in listing
- `-c, --content` - Show content differences in diff
- `-u, --unchanged` - Show unchanged files in diff
- `-e, --ext <extension>` - Filter files by extension
- `-d, --diffable` - Output in diff-optimized format (fwrules)
- `-p, --path <path>` - Path to fwrule file within archive
- `-F, --flat` - Extract files without directory structure
- `-P, --password <password>` - Password for encrypted .pca files

## File Format Details

### .par Files (Unencrypted)

Barracuda PAR (Phionar Archive) format is a binary format that stores:
- File metadata (permissions, ownership, timestamps)
- Directory structure
- File contents
- Configuration files
- Firewall rules

### .pca Files (Encrypted)

OpenSSL-compatible encrypted format:
- **Algorithm**: AES-256-CBC
- **Format**: `Salted__` (8 bytes) + salt (8 bytes) + encrypted data
- **Key Derivation**: EVP_BytesToKey with MD5 (for OpenSSL compatibility)
- **Padding**: PKCS7

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
