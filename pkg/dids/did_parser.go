package dids

import (
	"fmt"
	"regexp"
	"strings"
)

// ParsedDid represents a parsed DID according to the DID specification
type ParsedDid struct {
	Did      string `json:"did"`
	Method   string `json:"method"`
	Id       string `json:"id"`
	Path     string `json:"path,omitempty"`
	Query    string `json:"query,omitempty"`
	Fragment string `json:"fragment,omitempty"`
}

// DID regular expression based on the DID specification
// did = "did:" method-name ":" method-specific-id
// method-specific-id can contain one or more colon-separated idstrings.
// This regex allows any characters except '/', '?', '#' in the method-specific-id part,
// which includes ':' for sub-segments (e.g., did:example:sub:id).
var didRegex = regexp.MustCompile(`^did:([a-z0-9]+):([^/?#]+)(?:/([^?#]*))?(?:\?([^#]*))?(?:#(.*))?$`)

// ParseDid parses a DID string and returns a ParsedDid or an error
func ParseDid(did string) (*ParsedDid, error) {
	parsed := TryParseDid(did)
	if parsed == nil {
		return nil, fmt.Errorf("error parsing DID '%s': invalid format", did)
	}
	return parsed, nil
}

// TryParseDid attempts to parse a DID string and returns a ParsedDid or nil if parsing fails
func TryParseDid(did string) *ParsedDid {
	if did == "" {
		return nil
	}

	// Trim whitespace
	did = strings.TrimSpace(did)

	// Match against DID regex
	matches := didRegex.FindStringSubmatch(did)
	if matches == nil || len(matches) < 3 {
		return nil
	}

	parsed := &ParsedDid{
		Did:    did,
		Method: matches[1],
		Id:     matches[2],
	}

	// Optional path component
	if len(matches) > 3 && matches[3] != "" {
		parsed.Path = matches[3]
	}

	// Optional query component
	if len(matches) > 4 && matches[4] != "" {
		parsed.Query = matches[4]
	}

	// Optional fragment component
	if len(matches) > 5 && matches[5] != "" {
		parsed.Fragment = matches[5]
	}

	return parsed
}

// IsValidDid checks if a string is a valid DID
func IsValidDid(did string) bool {
	return TryParseDid(did) != nil
}

// BuildDid constructs a DID from its components
func BuildDid(method, id string) string {
	return fmt.Sprintf("did:%s:%s", method, id)
}

// BuildDidWithPath constructs a DID with a path component
func BuildDidWithPath(method, id, path string) string {
	return fmt.Sprintf("did:%s:%s/%s", method, id, path)
}

// BuildDidUrl constructs a full DID URL with all components
func BuildDidUrl(method, id, path, query, fragment string) string {
	didUrl := BuildDid(method, id)

	if path != "" {
		didUrl += "/" + path
	}

	if query != "" {
		didUrl += "?" + query
	}

	if fragment != "" {
		didUrl += "#" + fragment
	}

	return didUrl
}

// GetDidFromDidUrl extracts the DID portion from a DID URL
func GetDidFromDidUrl(didUrl string) string {
	parsed := TryParseDid(didUrl)
	if parsed == nil {
		return ""
	}

	return BuildDid(parsed.Method, parsed.Id)
}

// HasPath checks if the parsed DID has a path component
func (p *ParsedDid) HasPath() bool {
	return p.Path != ""
}

// HasQuery checks if the parsed DID has a query component
func (p *ParsedDid) HasQuery() bool {
	return p.Query != ""
}

// HasFragment checks if the parsed DID has a fragment component
func (p *ParsedDid) HasFragment() bool {
	return p.Fragment != ""
}

// ToDidUrl returns the full DID URL including all components
func (p *ParsedDid) ToDidUrl() string {
	return BuildDidUrl(p.Method, p.Id, p.Path, p.Query, p.Fragment)
}

// ToBaseDid returns just the base DID without path, query, or fragment
func (p *ParsedDid) ToBaseDid() string {
	return BuildDid(p.Method, p.Id)
}

// WithFragment creates a new ParsedDid with the specified fragment
func (p *ParsedDid) WithFragment(fragment string) *ParsedDid {
	return &ParsedDid{
		Did:      p.Did,
		Method:   p.Method,
		Id:       p.Id,
		Path:     p.Path,
		Query:    p.Query,
		Fragment: fragment,
	}
}

// WithPath creates a new ParsedDid with the specified path
func (p *ParsedDid) WithPath(path string) *ParsedDid {
	return &ParsedDid{
		Did:      p.Did,
		Method:   p.Method,
		Id:       p.Id,
		Path:     path,
		Query:    p.Query,
		Fragment: p.Fragment,
	}
}

// WithQuery creates a new ParsedDid with the specified query
func (p *ParsedDid) WithQuery(query string) *ParsedDid {
	return &ParsedDid{
		Did:      p.Did,
		Method:   p.Method,
		Id:       p.Id,
		Path:     p.Path,
		Query:    query,
		Fragment: p.Fragment,
	}
}

// Clone creates a deep copy of the ParsedDid
func (p *ParsedDid) Clone() *ParsedDid {
	return &ParsedDid{
		Did:      p.Did,
		Method:   p.Method,
		Id:       p.Id,
		Path:     p.Path,
		Query:    p.Query,
		Fragment: p.Fragment,
	}
}

// String returns the string representation of the parsed DID
func (p *ParsedDid) String() string {
	return p.ToDidUrl()
}

// Equals compares two ParsedDid instances for equality
func (p *ParsedDid) Equals(other *ParsedDid) bool {
	if other == nil {
		return false
	}

	return p.Did == other.Did &&
		p.Method == other.Method &&
		p.Id == other.Id &&
		p.Path == other.Path &&
		p.Query == other.Query &&
		p.Fragment == other.Fragment
}

// Validation helpers

// ValidateDid validates a DID string according to the specification
func ValidateDid(did string) error {
	parsed := TryParseDid(did)
	if parsed == nil {
		return fmt.Errorf("invalid DID format: %s", did)
	}

	// Additional validation rules
	if parsed.Method == "" {
		return fmt.Errorf("DID method cannot be empty")
	}

	if parsed.Id == "" {
		return fmt.Errorf("DID method-specific-id cannot be empty")
	}

	// Method name must be lowercase and contain only specific characters
	methodRegex := regexp.MustCompile(`^[a-z0-9]+$`)
	if !methodRegex.MatchString(parsed.Method) {
		return fmt.Errorf("invalid DID method name: %s", parsed.Method)
	}

	return nil
}

// IsValidDidMethod checks if a method name is valid
func IsValidDidMethod(method string) bool {
	if method == "" {
		return false
	}

	methodRegex := regexp.MustCompile(`^[a-z0-9]+$`)
	return methodRegex.MatchString(method)
}

// Common DID method constants
const (
	MethodKey   = "key"
	MethodWeb   = "web"
	MethodJwk   = "jwk"
	MethodPeer  = "peer"
	MethodSov   = "sov"
	MethodIndy  = "indy"
	MethodCheqd = "cheqd"
)

// IsKnownMethod checks if a method is one of the commonly known methods
func IsKnownMethod(method string) bool {
	knownMethods := []string{
		MethodKey,
		MethodWeb,
		MethodJwk,
		MethodPeer,
		MethodSov,
		MethodIndy,
		MethodCheqd,
	}

	for _, known := range knownMethods {
		if method == known {
			return true
		}
	}

	return false
}
