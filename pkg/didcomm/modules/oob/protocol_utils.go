package oob

import (
	"fmt"
	"strings"
)

// ParsedProtocolUri represents a parsed DIDComm protocol URI
type ParsedProtocolUri struct {
	BaseUri      string // e.g., "https://didcomm.org"
	ProtocolName string // e.g., "didexchange"
	MajorVersion string // e.g., "1"
	MinorVersion string // e.g., "1"
	FullUri      string // e.g., "https://didcomm.org/didexchange/1.1"
}

// ParseProtocolUri parses a protocol URI into its components
func ParseProtocolUri(uri string) (*ParsedProtocolUri, error) {
	if uri == "" {
		return nil, fmt.Errorf("empty protocol URI")
	}

	// Handle .x wildcards by replacing with .0
	uri = strings.ReplaceAll(uri, ".x", ".0")

	// Split by forward slashes
	parts := strings.Split(uri, "/")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid protocol URI format: %s", uri)
	}

	// Extract base URI (e.g., https://didcomm.org)
	baseUri := strings.Join(parts[:3], "/")

	// Extract protocol name (e.g., didexchange)
	protocolName := parts[3]

	// Extract version if present
	majorVersion := ""
	minorVersion := ""
	if len(parts) > 4 {
		versionParts := strings.Split(parts[4], ".")
		if len(versionParts) > 0 {
			majorVersion = versionParts[0]
		}
		if len(versionParts) > 1 {
			minorVersion = versionParts[1]
		}
	}

	return &ParsedProtocolUri{
		BaseUri:      baseUri,
		ProtocolName: protocolName,
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		FullUri:      uri,
	}, nil
}

// SupportsProtocolVersion checks if a supported version can handle a requested version
// Ignores minor version differences (e.g., 1.1 supports 1.0)
func SupportsProtocolVersion(supported, requested *ParsedProtocolUri) bool {
	if supported == nil || requested == nil {
		return false
	}

	// Must have same base URI and protocol name
	if supported.BaseUri != requested.BaseUri {
		return false
	}
	if supported.ProtocolName != requested.ProtocolName {
		return false
	}

	// Must have same major version
	if supported.MajorVersion != requested.MajorVersion {
		return false
	}

	// Minor version differences are OK
	return true
}

// GetSupportedHandshakeProtocols returns supported protocols ordered by preference
func GetSupportedHandshakeProtocols(requested []HandshakeProtocol) []HandshakeProtocol {
	if len(requested) == 0 {
		// Return all supported protocols in default order
		return []HandshakeProtocol{
			HandshakeProtocolDidExchange,
			HandshakeProtocolConnections,
		}
	}

	// Filter and order by requested preference
	var result []HandshakeProtocol
	supportedMap := map[string]HandshakeProtocol{
		string(HandshakeProtocolDidExchange): HandshakeProtocolDidExchange,
		string(HandshakeProtocolConnections): HandshakeProtocolConnections,
	}

	for _, req := range requested {
		// Parse requested protocol
		reqParsed, err := ParseProtocolUri(string(req))
		if err != nil {
			continue
		}

		// Check if we support this protocol
		for supportedUri, supportedProtocol := range supportedMap {
			supParsed, err := ParseProtocolUri(supportedUri)
			if err != nil {
				continue
			}

			if SupportsProtocolVersion(supParsed, reqParsed) {
				result = append(result, supportedProtocol)
				// Remove from map to avoid duplicates
				delete(supportedMap, supportedUri)
				break
			}
		}
	}

	return result
}
