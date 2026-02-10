package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Barracuda Firewall Rule Parser
// Converts verbose .fwrule format to human-readable compact format

// FWRule represents a firewall rule
type FWRule struct {
	Name        string
	Comment     string
	Source      []string // List of source addresses/refs
	Destination []string // List of destination addresses/refs
	Service     []string // List of services/ports
	Action      string   // PASS, BLOCK, CASCADE, REDIRECT
	ActionDetail string  // NAT type, redirect target, cascade target
	Deactivated bool
	Bidirectional bool
	Dynamic     bool
	MAC         string   // MAC address if specified
}

// FWNetObject represents a network object definition
type FWNetObject struct {
	Name    string
	Type    string // dns, set, entry
	Comment string
	Members []string
}

// FWServiceObject represents a service object definition
type FWServiceObject struct {
	Name    string
	Comment string
	Ports   []string // "TCP/80", "UDP/53", etc.
}

// FWUserObject represents a user object definition
type FWUserObject struct {
	Name    string
	Comment string
	Users   []string // Regular users, VPN users, groups, etc.
}

// FWURLObject represents a URL filtering object definition
type FWURLObject struct {
	Name    string
	Type    string   // "policy" or "condition"
	Comment string
	URLs    []string // URL entries with actions (e.g., "domain.com [ALLOW]")
}

// FWRuleSet represents the entire ruleset
type FWRuleSet struct {
	Name              string
	Comment           string
	EvalPolicyGlobal  bool // true = Policy Profiles Format, false = Legacy Application Rule Set
	Rules             []FWRule
	NetObjects        map[string]*FWNetObject
	ServiceObjects    map[string]*FWServiceObject
	UserObjects       map[string]*FWUserObject
	URLObjects        map[string]*FWURLObject
	SubSets           map[string]*FWRuleSet
}

// FormatType returns a human-readable format type string
func (rs *FWRuleSet) FormatType() string {
	if rs.EvalPolicyGlobal {
		return "Policy Profiles Format"
	}
	return "Application Rule Set (Legacy)"
}

// IsPolicyProfilesFormat returns true if using the new Policy Profiles Format
func (rs *FWRuleSet) IsPolicyProfilesFormat() bool {
	return rs.EvalPolicyGlobal
}

// IsLegacyFormat returns true if using the legacy Application Rule Set format
func (rs *FWRuleSet) IsLegacyFormat() bool {
	return !rs.EvalPolicyGlobal
}

// Token types for the parser
type TokenType int

const (
	TOK_IDENTIFIER TokenType = iota
	TOK_LBRACE
	TOK_RBRACE
	TOK_EQUALS
	TOK_VALUE
	TOK_EOF
)

type Token struct {
	Type  TokenType
	Value string
}

// Lexer for the fwrule format
type FWRuleLexer struct {
	input  string
	pos    int
	tokens []Token
}

func NewFWRuleLexer(input string) *FWRuleLexer {
	return &FWRuleLexer{input: input, pos: 0}
}

func (l *FWRuleLexer) skipWhitespace() {
	for l.pos < len(l.input) && (l.input[l.pos] == ' ' || l.input[l.pos] == '\t' || l.input[l.pos] == '\n' || l.input[l.pos] == '\r') {
		l.pos++
	}
}

func (l *FWRuleLexer) readIdentifier() string {
	start := l.pos
	for l.pos < len(l.input) && (isAlphaNum(l.input[l.pos]) || l.input[l.pos] == '_' || l.input[l.pos] == '-' || l.input[l.pos] == '.') {
		l.pos++
	}
	return l.input[start:l.pos]
}

func (l *FWRuleLexer) readValue() string {
	// Value is everything between { and }
	start := l.pos
	depth := 1
	for l.pos < len(l.input) && depth > 0 {
		if l.input[l.pos] == '{' {
			depth++
		} else if l.input[l.pos] == '}' {
			depth--
		}
		if depth > 0 {
			l.pos++
		}
	}
	return strings.TrimSpace(l.input[start:l.pos])
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func (l *FWRuleLexer) NextToken() Token {
	l.skipWhitespace()

	if l.pos >= len(l.input) {
		return Token{TOK_EOF, ""}
	}

	switch l.input[l.pos] {
	case '{':
		l.pos++
		return Token{TOK_LBRACE, "{"}
	case '}':
		l.pos++
		return Token{TOK_RBRACE, "}"}
	case '=':
		l.pos++
		return Token{TOK_EQUALS, "="}
	default:
		if isAlphaNum(l.input[l.pos]) || l.input[l.pos] == '_' {
			return Token{TOK_IDENTIFIER, l.readIdentifier()}
		}
		l.pos++
		return l.NextToken()
	}
}

// Parser for fwrule format
type FWRuleParser struct {
	lexer   *FWRuleLexer
	current Token
	content string
}

func NewFWRuleParser(content string) *FWRuleParser {
	p := &FWRuleParser{
		lexer:   NewFWRuleLexer(content),
		content: content,
	}
	p.advance()
	return p
}

func (p *FWRuleParser) advance() {
	p.current = p.lexer.NextToken()
}

func (p *FWRuleParser) expect(t TokenType) string {
	if p.current.Type != t {
		return ""
	}
	val := p.current.Value
	p.advance()
	return val
}

// ParseValue reads a value between braces
func (p *FWRuleParser) parseValue() string {
	if p.current.Type != TOK_LBRACE {
		return ""
	}
	p.advance() // skip {

	// Find the matching closing brace
	start := p.lexer.pos - 1
	depth := 1
	for p.lexer.pos < len(p.content) && depth > 0 {
		if p.content[p.lexer.pos] == '{' {
			depth++
		} else if p.content[p.lexer.pos] == '}' {
			depth--
		}
		p.lexer.pos++
	}

	value := strings.TrimSpace(p.content[start : p.lexer.pos-1])
	p.advance()
	return value
}

// ParseFWRuleFile parses the entire fwrule file content
func ParseFWRuleFile(content string) *FWRuleSet {
	ruleset := &FWRuleSet{
		NetObjects:     make(map[string]*FWNetObject),
		ServiceObjects: make(map[string]*FWServiceObject),
		UserObjects:    make(map[string]*FWUserObject),
		URLObjects:     make(map[string]*FWURLObject),
		SubSets:        make(map[string]*FWRuleSet),
	}

	// Use regex-based parsing for reliability
	ruleset.Name = extractValue(content, "name")
	ruleset.Comment = extractValue(content, "comment")

	// Check if this is Policy Profiles Format (new) or Application Rule Set (legacy)
	evalPolicyGlobal := extractValue(content, "evalPolicyGlobal")
	ruleset.EvalPolicyGlobal = (evalPolicyGlobal == "1")

	// Extract network objects
	parseNetObjects(content, ruleset)

	// Extract service objects
	parseServiceObjects(content, ruleset)

	// Extract user objects
	parseUserObjects(content, ruleset)

	// Extract URL filtering objects
	parseURLObjects(content, ruleset)

	// Extract rules
	parseRules(content, ruleset)

	return ruleset
}

func extractValue(content, key string) string {
	pattern := regexp.MustCompile(key + `=\{([^}]*)\}`)
	match := pattern.FindStringSubmatch(content)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

func extractBlock(content, startMarker string) []string {
	var blocks []string
	pattern := regexp.MustCompile(`(?s)` + startMarker + `\{`)
	indices := pattern.FindAllStringIndex(content, -1)

	for _, idx := range indices {
		start := idx[0]
		depth := 0
		end := start

		for i := idx[1] - 1; i < len(content); i++ {
			if content[i] == '{' {
				depth++
			} else if content[i] == '}' {
				depth--
				if depth == 0 {
					end = i + 1
					break
				}
			}
		}

		if end > start {
			blocks = append(blocks, content[start:end])
		}
	}
	return blocks
}

func parseNetObjects(content string, ruleset *FWRuleSet) {
	// Find netobj section
	netObjPattern := regexp.MustCompile(`(?s)netobj=\{(.*?)\n\t[a-z]+obj=`)
	match := netObjPattern.FindStringSubmatch(content)
	if len(match) < 2 {
		// Try alternate pattern
		netObjPattern = regexp.MustCompile(`(?s)netobj=\{(.*?)\n\truleobj=`)
		match = netObjPattern.FindStringSubmatch(content)
	}

	if len(match) > 1 {
		netSection := match[1]

		// Parse NetSet objects
		netSets := extractBlock(netSection, "NetSet")
		for _, ns := range netSets {
			obj := parseNetSet(ns)
			if obj.Name != "" {
				ruleset.NetObjects[obj.Name] = obj
			}
		}
	}
}

func parseNetSet(content string) *FWNetObject {
	obj := &FWNetObject{Type: "set"}
	obj.Name = extractValue(content, "name")
	obj.Comment = extractValue(content, "comment")

	// Check for DNS type
	netType := extractValue(content, "netType")
	if netType == "5" {
		obj.Type = "dns"
	}

	// Extract members
	// Look for NetEntry and NetRef
	entryPattern := regexp.MustCompile(`addr=\{([^}]+)\}`)
	entries := entryPattern.FindAllStringSubmatch(content, -1)
	for _, e := range entries {
		if len(e) > 1 && e[1] != "" {
			obj.Members = append(obj.Members, e[1])
		}
	}

	refPattern := regexp.MustCompile(`ref=\{([^}]+)\}`)
	refs := refPattern.FindAllStringSubmatch(content, -1)
	for _, r := range refs {
		if len(r) > 1 && r[1] != "" {
			obj.Members = append(obj.Members, "@"+r[1])
		}
	}

	return obj
}

func parseServiceObjects(content string, ruleset *FWRuleSet) {
	// Find srvobj section first
	srvObjPattern := regexp.MustCompile(`(?s)srvobj=\{(.*?)\n\t[a-z]+obj=`)
	match := srvObjPattern.FindStringSubmatch(content)

	var svcSection string
	if len(match) > 1 {
		svcSection = match[1]
	} else {
		// Fallback - look for srvobj section with different ending
		srvObjPattern2 := regexp.MustCompile(`(?s)srvobj=\{(.*?)\n\truleobj=`)
		match2 := srvObjPattern2.FindStringSubmatch(content)
		if len(match2) > 1 {
			svcSection = match2[1]
		} else {
			svcSection = content
		}
	}

	// Find service sets within the section
	svcSets := extractBlock(svcSection, "ServiceSet")
	for _, ss := range svcSets {
		obj := parseServiceSet(ss)
		if obj.Name != "" && !strings.Contains(obj.Name, ":srv") {
			ruleset.ServiceObjects[obj.Name] = obj
		}
	}
}

func parseServiceSet(content string) *FWServiceObject {
	obj := &FWServiceObject{}
	obj.Name = extractValue(content, "name")
	obj.Comment = extractValue(content, "comment")

	// Extract TCP entries - the format is: portLimit={ 25} or portLimit={ 5060 5065}
	tcpBlocks := extractBlock(content, "ServiceEntryTCP")
	for _, block := range tcpBlocks {
		portPattern := regexp.MustCompile(`portLimit=\{\s*([^}]*)\}`)
		if m := portPattern.FindStringSubmatch(block); len(m) > 1 {
			ports := strings.Fields(strings.TrimSpace(m[1]))
			for _, p := range ports {
				if p != "" {
					obj.Ports = append(obj.Ports, "TCP/"+p)
				}
			}
		}
	}

	// Extract UDP entries
	udpBlocks := extractBlock(content, "ServiceEntryUDP")
	for _, block := range udpBlocks {
		portPattern := regexp.MustCompile(`portLimit=\{\s*([^}]*)\}`)
		if m := portPattern.FindStringSubmatch(block); len(m) > 1 {
			ports := strings.Fields(strings.TrimSpace(m[1]))
			for _, p := range ports {
				if p != "" {
					obj.Ports = append(obj.Ports, "UDP/"+p)
				}
			}
		}
	}

	// Extract ICMP
	if strings.Contains(content, "ServiceEntryICMP") {
		obj.Ports = append(obj.Ports, "ICMP")
	}

	// Extract service references within the list section
	listPattern := regexp.MustCompile(`(?s)list=\{(.*?)\n\t\t\}`)
	if listMatch := listPattern.FindStringSubmatch(content); len(listMatch) > 1 {
		refPattern := regexp.MustCompile(`ref=\{([^}]+)\}`)
		refs := refPattern.FindAllStringSubmatch(listMatch[1], -1)
		for _, r := range refs {
			if len(r) > 1 && r[1] != "" {
				obj.Ports = append(obj.Ports, "@"+r[1])
			}
		}
	}

	return obj
}

func parseUserObjects(content string, ruleset *FWRuleSet) {
	// Find userobj section
	userObjPattern := regexp.MustCompile(`(?s)userobj=\{(.*?)\n\t[a-z]+obj=`)
	match := userObjPattern.FindStringSubmatch(content)
	if len(match) < 2 {
		// Try alternate pattern for end of file
		userObjPattern = regexp.MustCompile(`(?s)userobj=\{(.*?)\n\truleobj=`)
		match = userObjPattern.FindStringSubmatch(content)
	}

	if len(match) > 1 {
		userSection := match[1]

		// Parse UserSet objects
		userSets := extractBlock(userSection, "UserSet")
		for _, us := range userSets {
			obj := parseUserSet(us)
			if obj.Name != "" {
				ruleset.UserObjects[obj.Name] = obj
			}
		}
	}
}

func parseUserSet(content string) *FWUserObject {
	obj := &FWUserObject{}
	obj.Name = extractValue(content, "name")
	obj.Comment = extractValue(content, "comment")

	// Track unique users to avoid duplicates
	seen := make(map[string]bool)

	// Extract regular users
	userPattern := regexp.MustCompile(`user=\{([^}]+)\}`)
	users := userPattern.FindAllStringSubmatch(content, -1)
	for _, u := range users {
		if len(u) > 1 && u[1] != "" {
			user := strings.TrimSpace(u[1])
			if user != "?*" && !seen[user] {
				obj.Users = append(obj.Users, "user:"+user)
				seen[user] = true
			} else if user == "?*" && !seen["user:*"] {
				obj.Users = append(obj.Users, "user:*")
				seen["user:*"] = true
			}
		}
	}

	// Extract VPN users
	vpnUserPattern := regexp.MustCompile(`VPNuser=\{([^}]+)\}`)
	vpnUsers := vpnUserPattern.FindAllStringSubmatch(content, -1)
	for _, u := range vpnUsers {
		if len(u) > 1 && u[1] != "" {
			user := strings.TrimSpace(u[1])
			key := "vpn:" + user
			if user != "?*" && !seen[key] {
				obj.Users = append(obj.Users, "vpn:"+user)
				seen[key] = true
			} else if user == "?*" && !seen["vpn:*"] {
				obj.Users = append(obj.Users, "vpn:*")
				seen["vpn:*"] = true
			}
		}
	}

	// Extract VPN groups
	vpnGroupPattern := regexp.MustCompile(`VPNgroup=\{([^}]+)\}`)
	vpnGroups := vpnGroupPattern.FindAllStringSubmatch(content, -1)
	for _, g := range vpnGroups {
		if len(g) > 1 && g[1] != "" {
			group := strings.TrimSpace(g[1])
			key := "vpngroup:" + group
			if group != "" && !seen[key] {
				obj.Users = append(obj.Users, "vpngroup:"+group)
				seen[key] = true
			}
		}
	}

	// Extract groups
	groupsPattern := regexp.MustCompile(`groups=\{([^}]+)\}`)
	groups := groupsPattern.FindAllStringSubmatch(content, -1)
	for _, g := range groups {
		if len(g) > 1 && g[1] != "" {
			group := strings.TrimSpace(g[1])
			key := "group:" + group
			if group != "" && !seen[key] {
				obj.Users = append(obj.Users, "group:"+group)
				seen[key] = true
			}
		}
	}

	return obj
}

func parseURLObjects(content string, ruleset *FWRuleSet) {
	// Parse URL category policies
	urlPolicyPattern := regexp.MustCompile(`(?s)urlcatpolicyobj=\{(.*?)\n\t[a-z]+obj=`)
	match := urlPolicyPattern.FindStringSubmatch(content)
	if len(match) < 2 {
		// Try alternate pattern
		urlPolicyPattern = regexp.MustCompile(`(?s)urlcatpolicyobj=\{(.*?)\n\truleobj=`)
		match = urlPolicyPattern.FindStringSubmatch(content)
	}

	if len(match) > 1 {
		urlPolicySection := match[1]
		urlPolicies := extractBlock(urlPolicySection, "UrlCatPolicy")
		for _, up := range urlPolicies {
			obj := parseURLPolicy(up)
			if obj.Name != "" {
				ruleset.URLObjects[obj.Name] = obj
			}
		}
	}

	// Parse URL category conditions
	urlCondPattern := regexp.MustCompile(`(?s)urlcatcondobj=\{(.*?)\n\t[a-z]+obj=`)
	match = urlCondPattern.FindStringSubmatch(content)
	if len(match) < 2 {
		// Try alternate pattern
		urlCondPattern = regexp.MustCompile(`(?s)urlcatcondobj=\{(.*?)\n\truleobj=`)
		match = urlCondPattern.FindStringSubmatch(content)
	}

	if len(match) > 1 {
		urlCondSection := match[1]
		urlConds := extractBlock(urlCondSection, "UrlCatCond")
		for _, uc := range urlConds {
			obj := parseURLCond(uc)
			if obj.Name != "" {
				// Avoid duplicates by checking if name already exists
				if _, exists := ruleset.URLObjects[obj.Name]; !exists {
					ruleset.URLObjects[obj.Name] = obj
				}
			}
		}
	}
}

func parseURLPolicy(content string) *FWURLObject {
	obj := &FWURLObject{Type: "Policy Objects"}
	obj.Name = extractValue(content, "name")
	obj.Comment = extractValue(content, "comment")

	// Extract custom list
	customListPattern := regexp.MustCompile(`customlist=\{([^}]*)\}`)
	if match := customListPattern.FindStringSubmatch(content); len(match) > 1 {
		customList := match[1]
		// Parse entries: domain.com|1 (1=allow, 2=block)
		entries := strings.Split(customList, ",")
		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.Split(entry, "|")
			if len(parts) >= 2 {
				domain := parts[0]
				action := parts[1]
				actionStr := ""
				switch action {
				case "1":
					actionStr = "[ALLOW]"
				case "2":
					actionStr = "[BLOCK]"
				default:
					actionStr = "[" + action + "]"
				}
				obj.URLs = append(obj.URLs, domain+" "+actionStr)
			}
		}
	}

	return obj
}

func parseURLCond(content string) *FWURLObject {
	obj := &FWURLObject{Type: "Match Objects"}
	obj.Name = extractValue(content, "name")
	obj.Comment = extractValue(content, "comment")

	// Extract custom list
	customListPattern := regexp.MustCompile(`customlist=\{([^}]*)\}`)
	if match := customListPattern.FindStringSubmatch(content); len(match) > 1 {
		customList := match[1]
		// Parse entries: domain.com|1 (1=allow, 2=block)
		entries := strings.Split(customList, ",")
		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.Split(entry, "|")
			if len(parts) >= 2 {
				domain := parts[0]
				action := parts[1]
				actionStr := ""
				switch action {
				case "1":
					actionStr = "[ALLOW]"
				case "2":
					actionStr = "[BLOCK]"
				default:
					actionStr = "[" + action + "]"
				}
				obj.URLs = append(obj.URLs, domain+" "+actionStr)
			}
		}
	}

	return obj
}

func parseRules(content string, ruleset *FWRuleSet) {
	ruleBlocks := extractBlock(content, "\t\tRule")

	for _, rb := range ruleBlocks {
		rule := parseRule(rb)
		if rule.Name != "" {
			ruleset.Rules = append(ruleset.Rules, rule)
		}
	}
}

func parseRule(content string) FWRule {
	rule := FWRule{}
	rule.Name = extractValue(content, "name")
	rule.Comment = extractValue(content, "comment")
	rule.Deactivated = extractValue(content, "deactivated") == "1"
	rule.Dynamic = extractValue(content, "dynamic") == "1"

	// Parse source
	rule.Source = parseNetworkField(content, "srcExplicit", "src")

	// Parse destination
	rule.Destination = parseNetworkField(content, "dstExplicit", "dst")

	// Parse service
	rule.Service = parseServiceField(content)

	// Parse action
	rule.Action, rule.ActionDetail = parseAction(content)

	// Check for MAC
	macPattern := regexp.MustCompile(`mac=\{([^}]+)\}`)
	if m := macPattern.FindStringSubmatch(content); len(m) > 1 {
		rule.MAC = m[1]
	}

	// Check bidirectional
	rule.Bidirectional = extractValue(content, "bothWays") == "1"

	return rule
}

func parseNetworkField(content, explicitField, refField string) []string {
	var results []string

	// Check for explicit definition first (srcExplicit, dstExplicit)
	explicitPattern := regexp.MustCompile(`(?s)` + explicitField + `=\{(.*?)\n\t\t\t\}`)
	if match := explicitPattern.FindStringSubmatch(content); len(match) > 1 {
		section := match[1]
		results = append(results, extractNetworkItems(section)...)
	}

	// Also check for non-explicit field (src, dst) if we haven't found anything
	if len(results) == 0 {
		// Find the start of the field and extract the whole block
		fieldStart := regexp.MustCompile(`\t` + refField + `=\{`).FindStringIndex(content)
		if fieldStart != nil {
			// Extract from field start and find matching closing brace
			section := extractBalancedBlock(content[fieldStart[0]:])
			results = append(results, extractNetworkItems(section)...)
		}
	}

	return results
}

// extractBalancedBlock extracts content from a {...} block handling nested braces
func extractBalancedBlock(content string) string {
	start := strings.Index(content, "{")
	if start == -1 {
		return ""
	}

	depth := 0
	for i := start; i < len(content); i++ {
		if content[i] == '{' {
			depth++
		} else if content[i] == '}' {
			depth--
			if depth == 0 {
				return content[start+1 : i]
			}
		}
	}
	return content[start+1:]
}

func extractNetworkItems(section string) []string {
	var results []string
	seen := make(map[string]bool)

	// Extract addresses (but not 0.0.0.0 which is often a placeholder for dynamic entries)
	addrPattern := regexp.MustCompile(`addr=\{([^}]+)\}`)
	addrs := addrPattern.FindAllStringSubmatch(section, -1)
	for _, a := range addrs {
		if len(a) > 1 && a[1] != "" {
			addr := strings.TrimSpace(a[1])
			// Skip placeholder addresses that are part of NetPrefix dynamic entries
			if addr != "0.0.0.0" || !strings.Contains(section, "NetPrefixInst") {
				if !seen[addr] {
					results = append(results, addr)
					seen[addr] = true
				}
			}
		}
	}

	// Extract NetPrefixRef references (prefixref=)
	prefixRefPattern := regexp.MustCompile(`prefixref=\{([^}]+)\}`)
	prefixRefs := prefixRefPattern.FindAllStringSubmatch(section, -1)
	for _, r := range prefixRefs {
		if len(r) > 1 && r[1] != "" {
			refName := "@" + strings.TrimSpace(r[1])
			if !seen[refName] {
				results = append(results, refName)
				seen[refName] = true
			}
		}
	}

	// Extract ref= from NetRef blocks - use (?s) for multiline and .*? to cross nested braces
	netRefPattern := regexp.MustCompile(`(?s)NetRef\{.*?ref=\{([^}]+)\}`)
	netRefs := netRefPattern.FindAllStringSubmatch(section, -1)
	for _, r := range netRefs {
		if len(r) > 1 && r[1] != "" {
			refName := strings.TrimSpace(r[1])
			// Skip internal/system references and path-like references
			if refName == "Matching" || refName == "" || strings.Contains(refName, "/") {
				continue
			}
			// Skip if the reference contains newlines or tabs (malformed)
			if strings.Contains(refName, "\n") || strings.Contains(refName, "\t") {
				continue
			}
			refKey := "@" + refName
			if !seen[refKey] {
				results = append(results, refKey)
				seen[refKey] = true
			}
		}
	}

	// Also look for standalone ref= that might be inside NetEntry blocks
	entryRefPattern := regexp.MustCompile(`(?s)NetEntry\{.*?ref=\{([^}]+)\}`)
	entryRefs := entryRefPattern.FindAllStringSubmatch(section, -1)
	for _, r := range entryRefs {
		if len(r) > 1 && r[1] != "" {
			refName := strings.TrimSpace(r[1])
			if refName == "Matching" || refName == "" || strings.Contains(refName, "/") {
				continue
			}
			if strings.Contains(refName, "\n") || strings.Contains(refName, "\t") {
				continue
			}
			refKey := "@" + refName
			if !seen[refKey] {
				results = append(results, refKey)
				seen[refKey] = true
			}
		}
	}

	return results
}

func parseServiceField(content string) []string {
	var results []string

	// Check for explicit service
	if strings.Contains(content, "srvExplicit=") {
		// Extract inline service definitions
		tcpPattern := regexp.MustCompile(`ServiceEntryTCP\{[^}]*portLimit=\{\s*([^}]+)\}`)
		for _, m := range tcpPattern.FindAllStringSubmatch(content, -1) {
			if len(m) > 1 {
				ports := strings.Fields(m[1])
				for _, p := range ports {
					results = append(results, "TCP/"+p)
				}
			}
		}

		udpPattern := regexp.MustCompile(`ServiceEntryUDP\{[^}]*portLimit=\{\s*([^}]+)\}`)
		for _, m := range udpPattern.FindAllStringSubmatch(content, -1) {
			if len(m) > 1 {
				ports := strings.Fields(m[1])
				for _, p := range ports {
					results = append(results, "UDP/"+p)
				}
			}
		}
	}

	// Check for service reference
	srvRefPattern := regexp.MustCompile(`srv=\{[^}]*ServiceRef\{[^}]*ref=\{([^}]+)\}`)
	if match := srvRefPattern.FindStringSubmatch(content); len(match) > 1 {
		results = append(results, "@"+match[1])
	}

	if len(results) == 0 {
		results = append(results, "Any")
	}

	return results
}

func parseAction(content string) (string, string) {
	// ActionBlock
	if strings.Contains(content, "ActionBlock{") {
		return "BLOCK", ""
	}

	// ActionPass
	if strings.Contains(content, "ActionPass{") {
		// Check for NAT type
		connPattern := regexp.MustCompile(`conn=\{[^}]*ref=\{([^}]+)\}`)
		if match := connPattern.FindStringSubmatch(content); len(match) > 1 {
			return "PASS", match[1]
		}
		return "PASS", ""
	}

	// ActionCascade
	if strings.Contains(content, "ActionCascade{") {
		subsetPattern := regexp.MustCompile(`subsetName=\{([^}]+)\}`)
		if match := subsetPattern.FindStringSubmatch(content); len(match) > 1 {
			return "CASCADE", match[1]
		}
		return "CASCADE", ""
	}

	// ActionLocalRedirect
	if strings.Contains(content, "ActionLocalRedirect{") {
		addrPattern := regexp.MustCompile(`ActionLocalRedirect\{[^}]*addr=\{([^}]+)\}`)
		if match := addrPattern.FindStringSubmatch(content); len(match) > 1 {
			return "REDIRECT", match[1]
		}
		return "REDIRECT", ""
	}

	// ActionGroup
	if strings.Contains(content, "ActionGroup{") {
		return "GROUP", ""
	}

	return "UNKNOWN", ""
}

// OutputOptions controls what sections to include in output
type OutputOptions struct {
	ShowNetworks bool
	ShowServices bool
	ShowUsers    bool
	ShowURLs     bool
	ShowRules    bool
}

// AllSections returns options to show all sections
func AllSections() OutputOptions {
	return OutputOptions{ShowNetworks: true, ShowServices: true, ShowUsers: true, ShowURLs: true, ShowRules: true}
}

// FormatCompact returns a compact human-readable representation
func (rs *FWRuleSet) FormatCompact() string {
	return rs.FormatCompactSelective(AllSections())
}

// FormatCompactSelective returns a compact representation with selective sections
func (rs *FWRuleSet) FormatCompactSelective(opts OutputOptions) string {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 79) + "\n")
	sb.WriteString(fmt.Sprintf("FIREWALL RULESET: %s\n", rs.Name))
	if rs.Comment != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", rs.Comment))
	}
	sb.WriteString(fmt.Sprintf("Format: %s\n", rs.FormatType()))
	sb.WriteString("=" + strings.Repeat("=", 79) + "\n\n")

	// Network Objects summary
	if opts.ShowNetworks && len(rs.NetObjects) > 0 {
		sb.WriteString("NETWORK OBJECTS:\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")

		names := make([]string, 0, len(rs.NetObjects))
		for name := range rs.NetObjects {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			obj := rs.NetObjects[name]
			typeStr := ""
			if obj.Type == "dns" {
				typeStr = " [DNS]"
			}
			members := strings.Join(obj.Members, ", ")
			if len(members) > 50 {
				members = members[:47] + "..."
			}
			sb.WriteString(fmt.Sprintf("  %-30s%s = %s\n", name, typeStr, members))
		}
		sb.WriteString("\n")
	}

	// Service Objects summary
	if opts.ShowServices && len(rs.ServiceObjects) > 0 {
		sb.WriteString("SERVICE OBJECTS:\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")

		names := make([]string, 0, len(rs.ServiceObjects))
		for name := range rs.ServiceObjects {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			obj := rs.ServiceObjects[name]
			ports := strings.Join(obj.Ports, ", ")
			sb.WriteString(fmt.Sprintf("  %-25s = %s\n", name, ports))
		}
		sb.WriteString("\n")
	}

	// User Objects summary
	if opts.ShowUsers && len(rs.UserObjects) > 0 {
		sb.WriteString("USER OBJECTS:\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")

		names := make([]string, 0, len(rs.UserObjects))
		for name := range rs.UserObjects {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			obj := rs.UserObjects[name]
			users := strings.Join(obj.Users, ", ")
			if len(users) > 50 {
				users = users[:47] + "..."
			}
			sb.WriteString(fmt.Sprintf("  %-30s = %s\n", name, users))
		}
		sb.WriteString("\n")
	}

	// URL Filtering Objects summary
	if opts.ShowURLs && len(rs.URLObjects) > 0 {
		sb.WriteString("URL FILTERING OBJECTS:\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")

		names := make([]string, 0, len(rs.URLObjects))
		for name, obj := range rs.URLObjects {
			// If Policy Profiles Format (new), skip Policy Objects and only show Match Objects
			if rs.IsPolicyProfilesFormat() && obj.Type == "Policy Objects" {
				continue
			}
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			obj := rs.URLObjects[name]
			typeStr := fmt.Sprintf("[%s]", strings.ToUpper(obj.Type))
			sb.WriteString(fmt.Sprintf("  %-25s %-12s (%d URLs)\n", name, typeStr, len(obj.URLs)))
			if obj.Comment != "" {
				sb.WriteString(fmt.Sprintf("    # %s\n", obj.Comment))
			}
		}
		sb.WriteString("\n")
	}

	// Rules
	if opts.ShowRules {
		sb.WriteString("FIREWALL RULES:\n")
		sb.WriteString(strings.Repeat("-", 80) + "\n")
		sb.WriteString(fmt.Sprintf("%-4s %-25s %-8s %-20s %-20s\n", "#", "NAME", "ACTION", "SOURCE", "DESTINATION"))
		sb.WriteString(strings.Repeat("-", 80) + "\n")

		for i, rule := range rs.Rules {
			status := ""
			if rule.Deactivated {
				status = "[OFF] "
			}

			action := rule.Action
			if rule.ActionDetail != "" {
				action = fmt.Sprintf("%s→%s", rule.Action, truncate(rule.ActionDetail, 10))
			}

			src := formatNetList(rule.Source)
			dst := formatNetList(rule.Destination)

			sb.WriteString(fmt.Sprintf("%-4d %s%-25s %-8s %-20s %-20s\n",
				i+1, status, truncate(rule.Name, 25), action, truncate(src, 20), truncate(dst, 20)))

			// Service line if not "Any"
			svcStr := formatSvcList(rule.Service)
			if svcStr != "Any" && svcStr != "@Any" {
				sb.WriteString(fmt.Sprintf("     Service: %s\n", svcStr))
			}

			// Comment if present
			if rule.Comment != "" {
				sb.WriteString(fmt.Sprintf("     # %s\n", rule.Comment))
			}

			// MAC if present
			if rule.MAC != "" {
				sb.WriteString(fmt.Sprintf("     MAC: %s\n", rule.MAC))
			}
		}

		sb.WriteString(strings.Repeat("-", 80) + "\n")
		sb.WriteString(fmt.Sprintf("Total: %d rules\n", len(rs.Rules)))
	}

	return sb.String()
}

// FormatDetailed returns a more detailed but still readable representation
func (rs *FWRuleSet) FormatDetailed() string {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 79) + "\n")
	sb.WriteString(fmt.Sprintf("FIREWALL RULESET: %s\n", rs.Name))
	if rs.Comment != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", rs.Comment))
	}
	sb.WriteString(fmt.Sprintf("Total Rules: %d\n", len(rs.Rules)))
	sb.WriteString("=" + strings.Repeat("=", 79) + "\n\n")

	for i, rule := range rs.Rules {
		status := "ACTIVE"
		if rule.Deactivated {
			status = "DISABLED"
		}

		sb.WriteString(fmt.Sprintf("Rule #%d: %s [%s]\n", i+1, rule.Name, status))
		sb.WriteString(strings.Repeat("-", 50) + "\n")

		if rule.Comment != "" {
			sb.WriteString(fmt.Sprintf("  Comment:     %s\n", rule.Comment))
		}

		sb.WriteString(fmt.Sprintf("  Source:      %s\n", strings.Join(rule.Source, ", ")))
		sb.WriteString(fmt.Sprintf("  Destination: %s\n", strings.Join(rule.Destination, ", ")))
		sb.WriteString(fmt.Sprintf("  Service:     %s\n", strings.Join(rule.Service, ", ")))

		actionStr := rule.Action
		if rule.ActionDetail != "" {
			actionStr = fmt.Sprintf("%s (%s)", rule.Action, rule.ActionDetail)
		}
		sb.WriteString(fmt.Sprintf("  Action:      %s\n", actionStr))

		if rule.MAC != "" {
			sb.WriteString(fmt.Sprintf("  MAC Filter:  %s\n", rule.MAC))
		}
		if rule.Dynamic {
			sb.WriteString("  Dynamic:     Yes\n")
		}
		if rule.Bidirectional {
			sb.WriteString("  Bidir:       Yes\n")
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatDiffable returns a format optimized for diff comparison
func (rs *FWRuleSet) FormatDiffable() string {
	return rs.FormatDiffableSelective(AllSections())
}

// FormatDiffableSelective returns a diff-friendly format with selective sections
func (rs *FWRuleSet) FormatDiffableSelective(opts OutputOptions) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Ruleset: %s\n", rs.Name))
	sb.WriteString(fmt.Sprintf("# Comment: %s\n", rs.Comment))
	sb.WriteString(fmt.Sprintf("# Format: %s\n\n", rs.FormatType()))

	// Network objects (sorted for stable diff)
	if opts.ShowNetworks && len(rs.NetObjects) > 0 {
		sb.WriteString("## Network Objects\n")
		names := make([]string, 0, len(rs.NetObjects))
		for name := range rs.NetObjects {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			obj := rs.NetObjects[name]
			sort.Strings(obj.Members)
			sb.WriteString(fmt.Sprintf("NET %s = %s\n", name, strings.Join(obj.Members, " | ")))
		}
		sb.WriteString("\n")
	}

	// Service objects (sorted)
	if opts.ShowServices && len(rs.ServiceObjects) > 0 {
		sb.WriteString("## Service Objects\n")
		names := make([]string, 0, len(rs.ServiceObjects))
		for name := range rs.ServiceObjects {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			obj := rs.ServiceObjects[name]
			sort.Strings(obj.Ports)
			sb.WriteString(fmt.Sprintf("SVC %s = %s\n", name, strings.Join(obj.Ports, " | ")))
		}
		sb.WriteString("\n")
	}

	// User objects (sorted)
	if opts.ShowUsers && len(rs.UserObjects) > 0 {
		sb.WriteString("## User Objects\n")
		names := make([]string, 0, len(rs.UserObjects))
		for name := range rs.UserObjects {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			obj := rs.UserObjects[name]
			sort.Strings(obj.Users)
			sb.WriteString(fmt.Sprintf("USR %s = %s\n", name, strings.Join(obj.Users, " | ")))
		}
		sb.WriteString("\n")
	}

	// URL filtering objects (sorted)
	if opts.ShowURLs && len(rs.URLObjects) > 0 {
		sb.WriteString("## URL Filtering Objects\n")
		names := make([]string, 0, len(rs.URLObjects))
		for name, obj := range rs.URLObjects {
			// If Policy Profiles Format (new), skip Policy Objects and only show Match Objects
			if rs.IsPolicyProfilesFormat() && obj.Type == "Policy Objects" {
				continue
			}
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			obj := rs.URLObjects[name]
			sort.Strings(obj.URLs)
			sb.WriteString(fmt.Sprintf("URL %s [%s] = %s\n", name, obj.Type, strings.Join(obj.URLs, " | ")))
		}
		sb.WriteString("\n")
	}

	// Rules
	if opts.ShowRules {
		sb.WriteString("## Rules\n")
		for i, rule := range rs.Rules {
			status := ""
			if rule.Deactivated {
				status = " [DISABLED]"
			}

			sort.Strings(rule.Source)
			sort.Strings(rule.Destination)
			sort.Strings(rule.Service)

			actionStr := rule.Action
			if rule.ActionDetail != "" {
				actionStr = fmt.Sprintf("%s(%s)", rule.Action, rule.ActionDetail)
			}

			sb.WriteString(fmt.Sprintf("RULE %03d: %s%s\n", i+1, rule.Name, status))
			sb.WriteString(fmt.Sprintf("  SRC: %s\n", strings.Join(rule.Source, " | ")))
			sb.WriteString(fmt.Sprintf("  DST: %s\n", strings.Join(rule.Destination, " | ")))
			sb.WriteString(fmt.Sprintf("  SVC: %s\n", strings.Join(rule.Service, " | ")))
			sb.WriteString(fmt.Sprintf("  ACT: %s\n", actionStr))
			if rule.Comment != "" {
				sb.WriteString(fmt.Sprintf("  CMT: %s\n", rule.Comment))
			}
			if rule.MAC != "" {
				sb.WriteString(fmt.Sprintf("  MAC: %s\n", rule.MAC))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func formatNetList(items []string) string {
	if len(items) == 0 {
		return "Any"
	}
	return strings.Join(items, ", ")
}

func formatSvcList(items []string) string {
	if len(items) == 0 {
		return "Any"
	}
	return strings.Join(items, ", ")
}

// DiffRuleSets compares two rulesets and returns differences
func DiffRuleSets(rs1, rs2 *FWRuleSet) string {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 79) + "\n")
	sb.WriteString("FIREWALL RULESET DIFF\n")
	sb.WriteString(fmt.Sprintf("  Old: %s (%d rules)\n", rs1.Name, len(rs1.Rules)))
	sb.WriteString(fmt.Sprintf("  New: %s (%d rules)\n", rs2.Name, len(rs2.Rules)))
	sb.WriteString("=" + strings.Repeat("=", 79) + "\n\n")

	// Build rule maps by name
	rules1 := make(map[string]FWRule)
	rules2 := make(map[string]FWRule)

	for _, r := range rs1.Rules {
		rules1[r.Name] = r
	}
	for _, r := range rs2.Rules {
		rules2[r.Name] = r
	}

	// Find removed rules
	var removed []string
	for name := range rules1 {
		if _, exists := rules2[name]; !exists {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)

	// Find added rules
	var added []string
	for name := range rules2 {
		if _, exists := rules1[name]; !exists {
			added = append(added, name)
		}
	}
	sort.Strings(added)

	// Find modified rules
	var modified []string
	for name, r1 := range rules1 {
		if r2, exists := rules2[name]; exists {
			if !rulesEqual(r1, r2) {
				modified = append(modified, name)
			}
		}
	}
	sort.Strings(modified)

	if len(removed) > 0 {
		sb.WriteString("[REMOVED RULES]\n")
		for _, name := range removed {
			r := rules1[name]
			sb.WriteString(fmt.Sprintf("  - %s: %s → %s : %s\n", name,
				formatNetList(r.Source), formatNetList(r.Destination), r.Action))
		}
		sb.WriteString("\n")
	}

	if len(added) > 0 {
		sb.WriteString("[ADDED RULES]\n")
		for _, name := range added {
			r := rules2[name]
			sb.WriteString(fmt.Sprintf("  + %s: %s → %s : %s\n", name,
				formatNetList(r.Source), formatNetList(r.Destination), r.Action))
		}
		sb.WriteString("\n")
	}

	if len(modified) > 0 {
		sb.WriteString("[MODIFIED RULES]\n")
		for _, name := range modified {
			r1 := rules1[name]
			r2 := rules2[name]
			sb.WriteString(fmt.Sprintf("  ~ %s:\n", name))

			if !stringSliceEqual(r1.Source, r2.Source) {
				sb.WriteString(fmt.Sprintf("    Source: %s → %s\n",
					formatNetList(r1.Source), formatNetList(r2.Source)))
			}
			if !stringSliceEqual(r1.Destination, r2.Destination) {
				sb.WriteString(fmt.Sprintf("    Dest:   %s → %s\n",
					formatNetList(r1.Destination), formatNetList(r2.Destination)))
			}
			if !stringSliceEqual(r1.Service, r2.Service) {
				sb.WriteString(fmt.Sprintf("    Svc:    %s → %s\n",
					formatSvcList(r1.Service), formatSvcList(r2.Service)))
			}
			if r1.Action != r2.Action || r1.ActionDetail != r2.ActionDetail {
				sb.WriteString(fmt.Sprintf("    Action: %s(%s) → %s(%s)\n",
					r1.Action, r1.ActionDetail, r2.Action, r2.ActionDetail))
			}
			if r1.Deactivated != r2.Deactivated {
				sb.WriteString(fmt.Sprintf("    Status: %v → %v\n",
					statusStr(r1.Deactivated), statusStr(r2.Deactivated)))
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString(strings.Repeat("-", 80) + "\n")
	sb.WriteString(fmt.Sprintf("Summary: %d removed, %d added, %d modified, %d unchanged\n",
		len(removed), len(added), len(modified),
		len(rs1.Rules)-len(removed)-len(modified)))

	return sb.String()
}

func rulesEqual(r1, r2 FWRule) bool {
	return r1.Action == r2.Action &&
		r1.ActionDetail == r2.ActionDetail &&
		r1.Deactivated == r2.Deactivated &&
		stringSliceEqual(r1.Source, r2.Source) &&
		stringSliceEqual(r1.Destination, r2.Destination) &&
		stringSliceEqual(r1.Service, r2.Service)
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func statusStr(deactivated bool) string {
	if deactivated {
		return "DISABLED"
	}
	return "ACTIVE"
}
