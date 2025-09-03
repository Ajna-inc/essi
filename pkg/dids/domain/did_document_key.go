package domain

// DidDocumentKey represents a key associated with a DID document
type DidDocumentKey struct {
	// KmsKeyId is the key management system identifier for the key
	KmsKeyId string `json:"kmsKeyId"`
	// DidDocumentRelativeKeyId is the key reference within the DID document (e.g., "#key-1")
	DidDocumentRelativeKeyId string `json:"didDocumentRelativeKeyId"`
}