# PAR Parser - Usage Examples

## Working with Unencrypted .par Files

### List all entries
```bash
./par_parser.exe list backup.par
```

### Show file sizes
```bash
./par_parser.exe list -s backup.par
```

### View as tree structure
```bash
./par_parser.exe tree backup.par
```

### Extract all files
```bash
./par_parser.exe extract -o ./output backup.par
```

### Extract specific files (flat mode)
```bash
./par_parser.exe extract -o ./output -F -f "*.conf" backup.par
```

### View file content
```bash
./par_parser.exe cat backup.par box.conf
```

### Compare two backups
```bash
./par_parser.exe diff old.par new.par
```

## Working with Encrypted .pca Files

### Method 1: Interactive Password Prompt (Recommended)
```bash
./par_parser.exe list backup.pca
# Prompts: "Enter password for encrypted archive: "
# Type password (hidden) and press Enter
```

**Benefits:**
- Password is hidden while typing
- No password in command history
- Most secure method

### Method 2: Using -P Flag (For Automation)
```bash
./par_parser.exe list -P mypassword backup.pca
```

**Warning:** Password visible in:
- Command history
- Process list (while running)
- Shell scripts

**Use only when:**
- Running in automation scripts
- Appropriate security controls in place
- Non-interactive environment

### List encrypted archive
```bash
./par_parser.exe list backup.pca
# Enter password when prompted
```

### Extract from encrypted archive
```bash
./par_parser.exe extract -o ./output backup.pca
# Enter password when prompted
```

### View file from encrypted archive
```bash
./par_parser.exe cat backup.pca box.conf
# Enter password when prompted
```

### Compare encrypted archives
```bash
./par_parser.exe diff old.pca new.pca
# Enter password when prompted (same password used for both)
```

### View firewall rules
```bash
./par_parser.exe fwrules backup.pca
# Enter password when prompted
```

## Creating Encrypted .pca Files

### Using OpenSSL (Linux/macOS/Windows with OpenSSL)
```bash
# From password prompt (secure)
openssl enc -aes-256-cbc -salt -in backup.par -out backup.pca -md md5

# From stdin (for scripting)
echo "mypassword" | openssl enc -aes-256-cbc -salt -in backup.par -out backup.pca -pass stdin -md md5
```

**Note:** The `-md md5` flag is required for compatibility with the parser's key derivation.

## Advanced Usage

### Filter by pattern
```bash
./par_parser.exe list -f "boxadm" backup.par
```

### List only directories
```bash
./par_parser.exe dirs backup.par
```

### List only files with extension
```bash
./par_parser.exe files -e .conf backup.par
```

### Compare with content diff
```bash
./par_parser.exe diff -c old.par new.par
```

### Show unchanged files in diff
```bash
./par_parser.exe diff -u old.par new.par
```

### Firewall rules in diffable format
```bash
./par_parser.exe fwrules -d backup.par
```

### Compare firewall rules between backups
```bash
./par_parser.exe fwdiff old.par new.par
```

## Troubleshooting

### "invalid password: decryption failed"
- Wrong password entered
- File may be corrupted
- File may not be properly encrypted

### "file is not encrypted"
- Trying to decrypt a .par file
- File doesn't have "Salted__" header
- Auto-detection should handle this

### "password input requires an interactive terminal"
- Running in non-interactive environment
- Use `-P` flag for automation

### "file data is corrupted"
- File is damaged
- File is truncated
- Not a valid OpenSSL encrypted file

## Security Best Practices

1. **Use Interactive Prompts:** Prefer password prompts over `-P` flag
2. **Secure Backups:** Store .pca files with appropriate permissions
3. **Strong Passwords:** Use passwords with at least 8 characters
4. **Avoid Plaintext:** Don't store passwords in scripts or config files
5. **Clean History:** Clear command history if you used `-P` flag
   ```bash
   history -c  # Bash
   ```

## File Format Details

### .par Files
- Unencrypted Barracuda backup format
- Binary format with metadata headers
- Can be read directly

### .pca Files
- OpenSSL-compatible AES-256-CBC encryption
- Format: `Salted__` (8 bytes) + salt (8 bytes) + encrypted data
- Key derivation: EVP_BytesToKey with MD5 (for OpenSSL compatibility)
- PKCS7 padding

## Getting Help

```bash
./par_parser.exe help
```

Or run without arguments:
```bash
./par_parser.exe
```
