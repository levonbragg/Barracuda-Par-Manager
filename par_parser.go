package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// PAR file format (Barracuda "phionar" backup format)
//
// Archive Header (first entry only):
//   - Bytes 0-3:   Total archive size (uint32 LE)
//   - Bytes 4-7:   First file content size (uint32 LE)
//   - Bytes 8-11:  Type flag (0=file, 1=directory) (uint32 LE)
//   - Bytes 12-15: Unix file mode (uint32 LE)
//   - Bytes 16-19: Reserved/UID (uint32 LE)
//   - Bytes 20-23: Reserved/GID (uint32 LE)
//   - Bytes 24-27: Filename length including null (uint32 LE)
//   - Bytes 28+:   Filename (null-terminated)
//   - After filename: File content (size from bytes 4-7)
//
// Subsequent Entries:
//   - Bytes 0-3:   Content size (uint32 LE)
//   - Bytes 4-7:   Type flag (0=file, 1=directory) (uint32 LE)
//   - Bytes 8-11:  Unix file mode (uint32 LE)
//   - Bytes 12-15: Reserved/UID (uint32 LE)
//   - Bytes 16-19: Reserved/GID (uint32 LE)
//   - Bytes 20-23: Filename length including null (uint32 LE)
//   - Bytes 24+:   Filename (null-terminated)
//   - After filename: File content

type PAREntry struct {
	ContentSize uint32
	TypeFlag    uint32 // 0=file, 1=directory
	Mode        uint32
	UID         uint32
	GID         uint32
	FilenameLen uint32
	Filename    string
	Content     []byte
	Offset      int64 // Offset in archive where this entry starts
}

type PARArchive struct {
	Filename    string
	ArchiveSize uint32
	Entries     []PAREntry
	EntryMap    map[string]*PAREntry // Quick lookup by filename
}

func (e *PAREntry) IsDirectory() bool {
	return e.TypeFlag == 1 || (e.Mode&0xF000) == 0x4000
}

func (e *PAREntry) ModeString() string {
	mode := e.Mode
	typeChar := '-'
	if (mode & 0xF000) == 0x4000 {
		typeChar = 'd'
	} else if (mode & 0xF000) == 0xA000 {
		typeChar = 'l'
	}

	perms := ""
	for i := 8; i >= 0; i-- {
		if mode&(1<<i) != 0 {
			switch i % 3 {
			case 2:
				perms += "r"
			case 1:
				perms += "w"
			case 0:
				perms += "x"
			}
		} else {
			perms += "-"
		}
	}
	return string(typeChar) + perms
}

func (e *PAREntry) ContentHash() string {
	if len(e.Content) == 0 {
		return ""
	}
	hash := sha256.Sum256(e.Content)
	return fmt.Sprintf("%x", hash[:8]) // First 8 bytes for brevity
}

// Custom errors for decryption
var (
	ErrInvalidPassword = errors.New("invalid password: decryption failed")
	ErrNotEncrypted    = errors.New("file is not encrypted")
	ErrCorruptedData   = errors.New("file data is corrupted")
)

// evpBytesToKey implements OpenSSL's EVP_BytesToKey key derivation function.
//
// WARNING: This function uses MD5 for compatibility with OpenSSL's legacy
// encryption format. MD5 is cryptographically broken and should not be used
// for new applications. This implementation exists solely for decrypting
// existing .pca files created by Barracuda backup systems using OpenSSL.
//
// The algorithm iteratively hashes (password + salt) until enough bytes are
// generated for both the key and IV.
func evpBytesToKey(password, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	var m []byte
	var prevHash []byte

	totalLen := keyLen + ivLen
	for len(m) < totalLen {
		h := md5.New()
		h.Write(prevHash)
		h.Write(password)
		h.Write(salt)
		prevHash = h.Sum(nil)
		m = append(m, prevHash...)
	}

	key = m[:keyLen]
	iv = m[keyLen : keyLen+ivLen]
	return key, iv
}

// removePKCS7Padding removes and validates PKCS7 padding from decrypted data
func removePKCS7Padding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, ErrCorruptedData
	}

	// Get padding length from last byte
	paddingLen := int(data[length-1])

	// Validate padding length
	if paddingLen == 0 || paddingLen > aes.BlockSize || paddingLen > length {
		return nil, ErrInvalidPassword // Invalid padding usually means wrong password
	}

	// Verify all padding bytes are correct
	for i := length - paddingLen; i < length; i++ {
		if data[i] != byte(paddingLen) {
			return nil, ErrInvalidPassword
		}
	}

	return data[:length-paddingLen], nil
}

// decryptPCA decrypts OpenSSL-encrypted data with detailed error handling.
// Returns ErrInvalidPassword if password is wrong.
// Returns ErrCorruptedData if file is damaged.
func decryptPCA(encryptedData []byte, password string) ([]byte, error) {
	// Check minimum size (must have "Salted__" + salt + at least one block)
	if len(encryptedData) < 16+aes.BlockSize {
		return nil, ErrCorruptedData
	}

	// Check for OpenSSL "Salted__" magic header
	if string(encryptedData[:8]) != "Salted__" {
		return nil, ErrNotEncrypted
	}

	// Extract salt (8 bytes after "Salted__")
	salt := encryptedData[8:16]
	ciphertext := encryptedData[16:]

	// Derive key and IV using EVP_BytesToKey
	key, iv := evpBytesToKey([]byte(password), salt, 32, aes.BlockSize)

	// Zero out key and IV after use
	defer func() {
		for i := range key {
			key[i] = 0
		}
		for i := range iv {
			iv[i] = 0
		}
	}()

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Decrypt using CBC mode
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrCorruptedData
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	// Remove PKCS7 padding
	return removePKCS7Padding(decrypted)
}

// detectFileType uses magic header (primary) and extension (fallback) to determine file type
func detectFileType(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	// Check for OpenSSL encrypted format magic header
	if len(data) >= 8 && string(data[:8]) == "Salted__" {
		return "pca", nil
	}

	// Fallback to extension
	if strings.HasSuffix(strings.ToLower(filename), ".pca") {
		return "pca", nil
	}

	return "par", nil
}

// promptForPassword prompts the user to enter a password securely (with hidden input)
func promptForPassword() ([]byte, error) {
	// Check if stdin is a terminal
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("password input requires an interactive terminal")
	}

	fmt.Fprint(os.Stderr, "Enter password for encrypted archive: ")
	password, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr) // Print newline after password entry

	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}

	if len(password) < 8 {
		fmt.Fprintln(os.Stderr, "Warning: password is shorter than 8 characters")
	}

	return password, nil
}

// parsePARData parses PAR archive data from a byte slice
func parsePARData(data []byte, filename string) (*PARArchive, error) {
	archive := &PARArchive{
		Filename: filename,
		EntryMap: make(map[string]*PAREntry),
	}

	offset := 0
	isFirst := true

	for offset < len(data) {
		entry := PAREntry{Offset: int64(offset)}

		// First entry has archive size instead of content size at position 0
		if isFirst {
			archive.ArchiveSize = binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			isFirst = false
		}

		// Make sure we have enough bytes for the header
		if offset+24 > len(data) {
			break
		}

		// Read entry header
		entry.ContentSize = binary.LittleEndian.Uint32(data[offset : offset+4])
		entry.TypeFlag = binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		entry.Mode = binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		entry.UID = binary.LittleEndian.Uint32(data[offset+12 : offset+16])
		entry.GID = binary.LittleEndian.Uint32(data[offset+16 : offset+20])
		entry.FilenameLen = binary.LittleEndian.Uint32(data[offset+20 : offset+24])
		offset += 24

		// Sanity check
		if entry.FilenameLen > 4096 || entry.FilenameLen == 0 {
			return nil, fmt.Errorf("invalid filename length %d at offset %d", entry.FilenameLen, offset-24)
		}

		// Read filename
		if offset+int(entry.FilenameLen) > len(data) {
			break
		}
		entry.Filename = string(data[offset : offset+int(entry.FilenameLen)-1]) // -1 to exclude null
		offset += int(entry.FilenameLen)

		// Read content
		if offset+int(entry.ContentSize) > len(data) {
			return nil, fmt.Errorf("content would exceed file bounds: offset=%d, size=%d, fileLen=%d",
				offset, entry.ContentSize, len(data))
		}
		entry.Content = data[offset : offset+int(entry.ContentSize)]
		offset += int(entry.ContentSize)

		archive.Entries = append(archive.Entries, entry)
		archive.EntryMap[entry.Filename] = &archive.Entries[len(archive.Entries)-1]
	}

	return archive, nil
}

// ParsePARFile parses an unencrypted PAR file (backward compatible)
func ParsePARFile(filename string) (*PARArchive, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return parsePARData(data, filename)
}

// LoadArchive auto-detects file type and handles encryption.
// This is the preferred entry point for loading archives.
func LoadArchive(filename string, password ...string) (*PARArchive, error) {
	// Detect file type
	fileType, err := detectFileType(filename)
	if err != nil {
		return nil, err
	}

	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// If encrypted, decrypt it
	if fileType == "pca" {
		var pwd string
		if len(password) > 0 && password[0] != "" {
			pwd = password[0]
		} else {
			// Prompt for password
			pwdBytes, err := promptForPassword()
			if err != nil {
				return nil, fmt.Errorf("password required: %v", err)
			}
			pwd = string(pwdBytes)
			// Zero out password bytes
			for i := range pwdBytes {
				pwdBytes[i] = 0
			}
		}

		// Decrypt
		decrypted, err := decryptPCA(data, pwd)
		if err != nil {
			return nil, err
		}

		// Zero out password
		pwdBytes := []byte(pwd)
		for i := range pwdBytes {
			pwdBytes[i] = 0
		}

		data = decrypted
	}

	return parsePARData(data, filename)
}

// List prints all entries in the archive
func (a *PARArchive) List(filter string, showSize bool) {
	fmt.Printf("Archive: %s (%d bytes, %d entries)\n\n", a.Filename, a.ArchiveSize, len(a.Entries))

	if showSize {
		fmt.Printf("%-10s %10s  %s\n", "MODE", "SIZE", "FILENAME")
		fmt.Println("---------- ----------  ----------------------------------------")
	} else {
		fmt.Printf("%-10s  %s\n", "MODE", "FILENAME")
		fmt.Println("----------  ----------------------------------------")
	}

	for _, e := range a.Entries {
		if filter != "" && !strings.Contains(e.Filename, filter) {
			continue
		}
		if showSize {
			fmt.Printf("%-10s %10d  %s\n", e.ModeString(), e.ContentSize, e.Filename)
		} else {
			fmt.Printf("%-10s  %s\n", e.ModeString(), e.Filename)
		}
	}
}

// Tree prints entries in a tree structure
func (a *PARArchive) Tree(root string) {
	fmt.Printf("Archive: %s\n", a.Filename)

	// Build directory structure
	type node struct {
		name     string
		isDir    bool
		size     uint32
		children map[string]*node
	}

	rootNode := &node{name: ".", isDir: true, children: make(map[string]*node)}

	for _, e := range a.Entries {
		if root != "" && !strings.HasPrefix(e.Filename, root) {
			continue
		}

		parts := strings.Split(e.Filename, "/")
		current := rootNode

		for i, part := range parts {
			if part == "" {
				continue
			}

			if current.children[part] == nil {
				isDir := i < len(parts)-1 || e.IsDirectory()
				current.children[part] = &node{
					name:     part,
					isDir:    isDir,
					children: make(map[string]*node),
				}
			}

			if i == len(parts)-1 {
				current.children[part].size = e.ContentSize
				current.children[part].isDir = e.IsDirectory()
			}

			current = current.children[part]
		}
	}

	// Print tree
	var printTree func(n *node, prefix string, isLast bool)
	printTree = func(n *node, prefix string, isLast bool) {
		connector := "├── "
		if isLast {
			connector = "└── "
		}

		if n.name != "." {
			sizeStr := ""
			if !n.isDir && n.size > 0 {
				sizeStr = fmt.Sprintf(" (%d bytes)", n.size)
			}
			dirMarker := ""
			if n.isDir {
				dirMarker = "/"
			}
			fmt.Printf("%s%s%s%s%s\n", prefix, connector, n.name, dirMarker, sizeStr)
		}

		// Sort children
		names := make([]string, 0, len(n.children))
		for name := range n.children {
			names = append(names, name)
		}
		sort.Strings(names)

		newPrefix := prefix
		if n.name != "." {
			if isLast {
				newPrefix += "    "
			} else {
				newPrefix += "│   "
			}
		}

		for i, name := range names {
			printTree(n.children[name], newPrefix, i == len(names)-1)
		}
	}

	printTree(rootNode, "", true)
}

// ListDirs prints only directories
func (a *PARArchive) ListDirs() {
	fmt.Printf("Directories in %s:\n\n", a.Filename)
	for _, e := range a.Entries {
		if e.IsDirectory() {
			fmt.Printf("  %s/\n", e.Filename)
		}
	}
}

// ListFiles prints only files (optionally filtered by extension)
func (a *PARArchive) ListFiles(ext string) {
	fmt.Printf("Files in %s", a.Filename)
	if ext != "" {
		fmt.Printf(" (filtered: *%s)", ext)
	}
	fmt.Println(":\n")

	for _, e := range a.Entries {
		if !e.IsDirectory() {
			if ext == "" || strings.HasSuffix(e.Filename, ext) {
				fmt.Printf("  %-10s %8d  %s\n", e.ModeString(), e.ContentSize, e.Filename)
			}
		}
	}
}

// Extract extracts files from the archive
func (a *PARArchive) Extract(outputDir string, pattern string, flat bool) error {
	if outputDir == "" {
		outputDir = "."
	}

	extracted := 0
	extractedFiles := make(map[string]bool) // Track files in flat mode to detect conflicts

	for _, e := range a.Entries {
		// Filter by pattern if specified
		if pattern != "" {
			matched, err := filepath.Match(pattern, filepath.Base(e.Filename))
			if err != nil {
				return fmt.Errorf("invalid pattern: %v", err)
			}
			// Also check if pattern matches any part of the path
			pathMatched := strings.Contains(e.Filename, pattern)
			if !matched && !pathMatched {
				continue
			}
		}

		// Skip directories in flat mode
		if flat && e.IsDirectory() {
			continue
		}

		var outPath string
		if flat {
			// Extract just the filename without path
			outPath = filepath.Join(outputDir, filepath.Base(e.Filename))

			// Check for filename conflicts
			baseName := filepath.Base(e.Filename)
			if extractedFiles[baseName] {
				fmt.Printf("  Warning:      Skipping duplicate filename %s (from %s)\n", baseName, e.Filename)
				continue
			}
			extractedFiles[baseName] = true
		} else {
			// Preserve full directory structure
			outPath = filepath.Join(outputDir, e.Filename)
		}

		if e.IsDirectory() {
			if err := os.MkdirAll(outPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %v", outPath, err)
			}
			fmt.Printf("  Created dir:  %s/\n", e.Filename)
		} else {
			// Ensure parent directory exists (only needed in non-flat mode)
			if !flat {
				parentDir := filepath.Dir(outPath)
				if err := os.MkdirAll(parentDir, 0755); err != nil {
					return fmt.Errorf("failed to create parent directory %s: %v", parentDir, err)
				}
			} else {
				// In flat mode, just ensure output directory exists
				if err := os.MkdirAll(outputDir, 0755); err != nil {
					return fmt.Errorf("failed to create output directory %s: %v", outputDir, err)
				}
			}

			// Write file
			if err := os.WriteFile(outPath, e.Content, os.FileMode(e.Mode&0777)); err != nil {
				return fmt.Errorf("failed to write file %s: %v", outPath, err)
			}

			if flat {
				fmt.Printf("  Extracted:    %s (%d bytes) from %s\n", filepath.Base(e.Filename), len(e.Content), e.Filename)
			} else {
				fmt.Printf("  Extracted:    %s (%d bytes)\n", e.Filename, len(e.Content))
			}
		}
		extracted++
	}

	if flat {
		fmt.Printf("\nExtracted %d files to %s (flat mode)\n", extracted, outputDir)
	} else {
		fmt.Printf("\nExtracted %d entries to %s\n", extracted, outputDir)
	}
	return nil
}

// ExtractFile extracts a single file and returns its content (or prints to stdout)
func (a *PARArchive) ExtractFile(filename string, toStdout bool) error {
	entry, ok := a.EntryMap[filename]
	if !ok {
		return fmt.Errorf("file not found: %s", filename)
	}

	if entry.IsDirectory() {
		return fmt.Errorf("%s is a directory", filename)
	}

	if toStdout {
		fmt.Print(string(entry.Content))
		return nil
	}

	outPath := filepath.Base(filename)
	if err := os.WriteFile(outPath, entry.Content, os.FileMode(entry.Mode&0777)); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	fmt.Printf("Extracted %s to %s (%d bytes)\n", filename, outPath, len(entry.Content))
	return nil
}

// DiffResult represents a difference between two archives
type DiffResult struct {
	OnlyInFirst  []string            // Files only in first archive
	OnlyInSecond []string            // Files only in second archive
	Modified     []string            // Files that exist in both but differ
	Unchanged    []string            // Files that are identical
	ModifiedDiff map[string][]string // Detailed diff for text files
}

// shouldIgnorePath checks if a path should be ignored in diff operations
func shouldIgnorePath(path string) bool {
	// Ignore anything in zrepo directory and its metadata files
	if strings.HasPrefix(path, "zrepo/") || path == "zrepo" ||
		strings.HasPrefix(path, "zrepo.") {
		return true
	}

	// Ignore anything in servers/CSC/services/policyserver* and its metadata
	if strings.HasPrefix(path, "servers/CSC/services/policyserver") {
		return true
	}

	return false
}

// Diff compares two archives and returns the differences
func Diff(archive1, archive2 *PARArchive, showContent bool) *DiffResult {
	result := &DiffResult{
		ModifiedDiff: make(map[string][]string),
	}

	// Check files in archive1
	for filename, entry1 := range archive1.EntryMap {
		// Skip ignored paths
		if shouldIgnorePath(filename) {
			continue
		}

		entry2, exists := archive2.EntryMap[filename]
		if !exists {
			result.OnlyInFirst = append(result.OnlyInFirst, filename)
		} else if entry1.ContentHash() != entry2.ContentHash() {
			result.Modified = append(result.Modified, filename)
			if showContent && !entry1.IsDirectory() {
				result.ModifiedDiff[filename] = generateDiff(entry1, entry2)
			}
		} else {
			result.Unchanged = append(result.Unchanged, filename)
		}
	}

	// Check files only in archive2
	for filename := range archive2.EntryMap {
		// Skip ignored paths
		if shouldIgnorePath(filename) {
			continue
		}

		if _, exists := archive1.EntryMap[filename]; !exists {
			result.OnlyInSecond = append(result.OnlyInSecond, filename)
		}
	}

	// Sort all slices for consistent output
	sort.Strings(result.OnlyInFirst)
	sort.Strings(result.OnlyInSecond)
	sort.Strings(result.Modified)
	sort.Strings(result.Unchanged)

	return result
}

// generateDiff creates a simple line-by-line diff for text files
func generateDiff(entry1, entry2 *PAREntry) []string {
	lines1 := strings.Split(string(entry1.Content), "\n")
	lines2 := strings.Split(string(entry2.Content), "\n")

	var diff []string

	// Simple diff - show lines that are different
	maxLines := len(lines1)
	if len(lines2) > maxLines {
		maxLines = len(lines2)
	}

	for i := 0; i < maxLines; i++ {
		var line1, line2 string
		if i < len(lines1) {
			line1 = lines1[i]
		}
		if i < len(lines2) {
			line2 = lines2[i]
		}

		if line1 != line2 {
			if i < len(lines1) && (i >= len(lines2) || line1 != line2) {
				diff = append(diff, fmt.Sprintf("-%d: %s", i+1, line1))
			}
			if i < len(lines2) && (i >= len(lines1) || line1 != line2) {
				diff = append(diff, fmt.Sprintf("+%d: %s", i+1, line2))
			}
		}
	}

	return diff
}

// PrintDiff prints the diff result in a readable format
func (d *DiffResult) Print(showUnchanged bool, showContent bool) {
	fmt.Println("=" + strings.Repeat("=", 70))
	fmt.Println("DIFF SUMMARY")
	fmt.Println("=" + strings.Repeat("=", 70))

	if len(d.OnlyInFirst) > 0 {
		fmt.Printf("\n[REMOVED] Files only in FIRST archive (%d):\n", len(d.OnlyInFirst))
		for _, f := range d.OnlyInFirst {
			fmt.Printf("  - %s\n", f)
		}
	}

	if len(d.OnlyInSecond) > 0 {
		fmt.Printf("\n[ADDED] Files only in SECOND archive (%d):\n", len(d.OnlyInSecond))
		for _, f := range d.OnlyInSecond {
			fmt.Printf("  + %s\n", f)
		}
	}

	if len(d.Modified) > 0 {
		fmt.Printf("\n[MODIFIED] Files that differ (%d):\n", len(d.Modified))
		for _, f := range d.Modified {
			fmt.Printf("  ~ %s\n", f)
			if showContent {
				if lines, ok := d.ModifiedDiff[f]; ok && len(lines) > 0 {
					for _, line := range lines {
						if len(line) > 100 {
							line = line[:100] + "..."
						}
						fmt.Printf("      %s\n", line)
					}
				}
			}
		}
	}

	if showUnchanged && len(d.Unchanged) > 0 {
		fmt.Printf("\n[UNCHANGED] Identical files (%d):\n", len(d.Unchanged))
		for _, f := range d.Unchanged {
			fmt.Printf("  = %s\n", f)
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 71))
	fmt.Printf("Summary: %d removed, %d added, %d modified, %d unchanged\n",
		len(d.OnlyInFirst), len(d.OnlyInSecond), len(d.Modified), len(d.Unchanged))
}

func printUsage() {
	fmt.Println(`Barracuda PAR Backup Parser
===========================
Supports both unencrypted (.par) and encrypted (.pca) archives.

Usage: par_parser <command> [options] <file.par|file.pca> [file2.par]

Commands:
  list      List all entries in the archive
  tree      Show entries in tree structure
  dirs      List only directories
  files     List only files
  cat       Print file content to stdout
  extract   Extract files from archive
  diff      Compare two archives

  Firewall Rules:
  fwrules    Show firewall rules in compact format
  fwdetail   Show firewall rules in detailed format
  fwdiff     Compare firewall rules between two backups
  fwnetworks Show only network objects from firewall rules
  fwservices Show only service objects from firewall rules
  fwusers    Show only user objects from firewall rules
  fwurls     Show only URL filtering objects from firewall rules
  fwruleonly Show only firewall rules (no objects)

Options:
  -f, --filter <pattern>   Filter entries by pattern
  -o, --output <dir>       Output directory for extraction
  -s, --size               Show file sizes in listing
  -c, --content            Show content differences in diff
  -u, --unchanged          Show unchanged files in diff
  -e, --ext <extension>    Filter files by extension
  -d, --diffable           Output in diff-optimized format (fwrules)
  -p, --path <path>        Path to fwrule file within archive
  -F, --flat               Extract files without directory structure
  -P, --password <password> Password for encrypted .pca files
                           (prompted securely if not provided)

  Firewall Rule Options (fwrules command only):
  -n, --networks           Show only network objects
  -S, --services           Show only service objects
  -U, --users              Show only user objects
  -L, --urls               Show only URL filtering objects
  -r, --rules              Show only rules (no objects)
                           (combine flags to show multiple sections)

Examples:
  par_parser list backup.par
  par_parser list backup.pca
  par_parser list -P mypassword backup.pca
  par_parser list -s backup.par
  par_parser list -f boxadm backup.par
  par_parser tree backup.par
  par_parser dirs backup.par
  par_parser files -e .conf backup.par
  par_parser cat backup.par box.conf
  par_parser extract -o ./output backup.par
  par_parser extract -o ./output encrypted.pca
  par_parser extract -o ./output -F backup.par
  par_parser extract -o ./output -F -f "*.fwrule" backup.par
  par_parser diff old.par new.par
  par_parser diff old.pca new.pca

  Firewall Rules:
  par_parser fwrules backup.par
  par_parser fwrules -d backup.par
  par_parser fwrules -n backup.par              (show only network objects)
  par_parser fwrules -S backup.par              (show only service objects)
  par_parser fwrules -U backup.par              (show only user objects)
  par_parser fwrules -L backup.par              (show only URL filtering objects)
  par_parser fwrules -r backup.par              (show only rules)
  par_parser fwrules -n -S -U -L backup.par     (show networks, services, users, and URLs)
  par_parser fwnetworks backup.par              (dedicated command for networks)
  par_parser fwservices backup.par              (dedicated command for services)
  par_parser fwusers backup.par                 (dedicated command for users)
  par_parser fwurls backup.par                  (dedicated command for URLs)
  par_parser fwruleonly backup.par              (dedicated command for rules only)
  par_parser fwdetail backup.par
  par_parser fwdiff old.par new.par

Security Notes:
  - Passwords are prompted securely (hidden from terminal)
  - .pca files use OpenSSL-compatible AES-256-CBC encryption
  - Avoid using -P flag (passwords visible in command history)`)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	// Parse flags
	var filter, output, ext, fwPath, password string
	var showSize, showContent, showUnchanged, diffable, flat bool
	var showNetworks, showServices, showUsers, showURLs, showRules bool
	args := os.Args[2:]
	var positionalArgs []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f", "--filter":
			if i+1 < len(args) {
				filter = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				output = args[i+1]
				i++
			}
		case "-e", "--ext":
			if i+1 < len(args) {
				ext = args[i+1]
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				i++
			}
		case "-p", "--path":
			if i+1 < len(args) {
				fwPath = args[i+1]
				i++
			}
		case "-P", "--password":
			if i+1 < len(args) {
				password = args[i+1]
				fmt.Fprintln(os.Stderr, "Warning: Using -P flag exposes password in command history. Consider omitting for secure prompt.")
				i++
			}
		case "-s", "--size":
			showSize = true
		case "-c", "--content":
			showContent = true
		case "-u", "--unchanged":
			showUnchanged = true
		case "-d", "--diffable":
			diffable = true
		case "-F", "--flat":
			flat = true
		case "-n", "--networks":
			showNetworks = true
		case "-S", "--services":
			showServices = true
		case "-U", "--users":
			showUsers = true
		case "-L", "--urls":
			showURLs = true
		case "-r", "--rules":
			showRules = true
		default:
			positionalArgs = append(positionalArgs, args[i])
		}
	}

	if len(positionalArgs) < 1 && command != "help" {
		fmt.Println("Error: No archive file specified")
		printUsage()
		os.Exit(1)
	}

	switch command {
	case "help", "-h", "--help":
		printUsage()

	case "list":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		archive.List(filter, showSize)

	case "tree":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		archive.Tree(filter)

	case "dirs":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		archive.ListDirs()

	case "files":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		archive.ListFiles(ext)

	case "cat":
		if len(positionalArgs) < 2 {
			fmt.Println("Error: Specify file to cat")
			os.Exit(1)
		}
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if err := archive.ExtractFile(positionalArgs[1], true); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "extract":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Extracting %s...\n\n", positionalArgs[0])
		if err := archive.Extract(output, filter, flat); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "diff":
		if len(positionalArgs) < 2 {
			fmt.Println("Error: diff requires two archive files")
			os.Exit(1)
		}
		archive1, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error parsing %s: %v\n", positionalArgs[0], err)
			os.Exit(1)
		}
		archive2, err := LoadArchive(positionalArgs[1], password)
		if err != nil {
			fmt.Printf("Error parsing %s: %v\n", positionalArgs[1], err)
			os.Exit(1)
		}

		fmt.Printf("Comparing:\n  [1] %s (%d entries)\n  [2] %s (%d entries)\n\n",
			archive1.Filename, len(archive1.Entries),
			archive2.Filename, len(archive2.Entries))

		result := Diff(archive1, archive2, showContent)
		result.Print(showUnchanged, showContent)

	case "fwrules":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fwContent := findFWRuleContent(archive, fwPath)
		if fwContent == "" {
			fmt.Println("Error: No firewall rule file found")
			os.Exit(1)
		}
		ruleset := ParseFWRuleFile(fwContent)

		// Determine what to show based on flags
		opts := OutputOptions{}
		if !showNetworks && !showServices && !showUsers && !showURLs && !showRules {
			// No flags specified, show all (default behavior)
			opts = AllSections()
		} else {
			// Show only requested sections
			opts.ShowNetworks = showNetworks
			opts.ShowServices = showServices
			opts.ShowUsers = showUsers
			opts.ShowURLs = showURLs
			opts.ShowRules = showRules
		}

		if diffable {
			fmt.Print(ruleset.FormatDiffableSelective(opts))
		} else {
			fmt.Print(ruleset.FormatCompactSelective(opts))
		}

	case "fwnetworks":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fwContent := findFWRuleContent(archive, fwPath)
		if fwContent == "" {
			fmt.Println("Error: No firewall rule file found")
			os.Exit(1)
		}
		ruleset := ParseFWRuleFile(fwContent)
		opts := OutputOptions{ShowNetworks: true}
		if diffable {
			fmt.Print(ruleset.FormatDiffableSelective(opts))
		} else {
			fmt.Print(ruleset.FormatCompactSelective(opts))
		}

	case "fwservices":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fwContent := findFWRuleContent(archive, fwPath)
		if fwContent == "" {
			fmt.Println("Error: No firewall rule file found")
			os.Exit(1)
		}
		ruleset := ParseFWRuleFile(fwContent)
		opts := OutputOptions{ShowServices: true}
		if diffable {
			fmt.Print(ruleset.FormatDiffableSelective(opts))
		} else {
			fmt.Print(ruleset.FormatCompactSelective(opts))
		}

	case "fwusers":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fwContent := findFWRuleContent(archive, fwPath)
		if fwContent == "" {
			fmt.Println("Error: No firewall rule file found")
			os.Exit(1)
		}
		ruleset := ParseFWRuleFile(fwContent)
		opts := OutputOptions{ShowUsers: true}
		if diffable {
			fmt.Print(ruleset.FormatDiffableSelective(opts))
		} else {
			fmt.Print(ruleset.FormatCompactSelective(opts))
		}

	case "fwurls":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fwContent := findFWRuleContent(archive, fwPath)
		if fwContent == "" {
			fmt.Println("Error: No firewall rule file found")
			os.Exit(1)
		}
		ruleset := ParseFWRuleFile(fwContent)
		opts := OutputOptions{ShowURLs: true}
		if diffable {
			fmt.Print(ruleset.FormatDiffableSelective(opts))
		} else {
			fmt.Print(ruleset.FormatCompactSelective(opts))
		}

	case "fwruleonly":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fwContent := findFWRuleContent(archive, fwPath)
		if fwContent == "" {
			fmt.Println("Error: No firewall rule file found")
			os.Exit(1)
		}
		ruleset := ParseFWRuleFile(fwContent)
		opts := OutputOptions{ShowRules: true}
		if diffable {
			fmt.Print(ruleset.FormatDiffableSelective(opts))
		} else {
			fmt.Print(ruleset.FormatCompactSelective(opts))
		}

	case "fwdetail":
		archive, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fwContent := findFWRuleContent(archive, fwPath)
		if fwContent == "" {
			fmt.Println("Error: No firewall rule file found")
			os.Exit(1)
		}
		ruleset := ParseFWRuleFile(fwContent)
		fmt.Print(ruleset.FormatDetailed())

	case "fwdiff":
		if len(positionalArgs) < 2 {
			fmt.Println("Error: fwdiff requires two archive files")
			os.Exit(1)
		}
		archive1, err := LoadArchive(positionalArgs[0], password)
		if err != nil {
			fmt.Printf("Error parsing %s: %v\n", positionalArgs[0], err)
			os.Exit(1)
		}
		archive2, err := LoadArchive(positionalArgs[1], password)
		if err != nil {
			fmt.Printf("Error parsing %s: %v\n", positionalArgs[1], err)
			os.Exit(1)
		}

		fwContent1 := findFWRuleContent(archive1, fwPath)
		fwContent2 := findFWRuleContent(archive2, fwPath)

		if fwContent1 == "" || fwContent2 == "" {
			fmt.Println("Error: Could not find firewall rules in one or both archives")
			os.Exit(1)
		}

		ruleset1 := ParseFWRuleFile(fwContent1)
		ruleset2 := ParseFWRuleFile(fwContent2)

		fmt.Print(DiffRuleSets(ruleset1, ruleset2))

	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

// findFWRuleContent finds and returns the firewall rule file content
func findFWRuleContent(archive *PARArchive, specificPath string) string {
	// If specific path given, use it
	if specificPath != "" {
		if entry, ok := archive.EntryMap[specificPath]; ok {
			return string(entry.Content)
		}
		return ""
	}

	// Search for common fwrule file locations
	searchPaths := []string{
		"servers/CSC/services/NGFW/active.fwrule",
		"boxsrv/boxfw.lfwrule7",
	}

	for _, path := range searchPaths {
		if entry, ok := archive.EntryMap[path]; ok {
			return string(entry.Content)
		}
	}

	// Search for any .fwrule file
	for name, entry := range archive.EntryMap {
		if strings.HasSuffix(name, ".fwrule") || strings.HasSuffix(name, ".lfwrule7") {
			return string(entry.Content)
		}
	}

	return ""
}
