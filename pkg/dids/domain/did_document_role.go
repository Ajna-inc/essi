package domain

// DidDocumentRole represents the role of a DID document in the system
type DidDocumentRole string

const (
	// DidDocumentRoleCreated indicates a DID that was created by this agent
	DidDocumentRoleCreated DidDocumentRole = "created"
	// DidDocumentRoleReceived indicates a DID that was received from another agent
	DidDocumentRoleReceived DidDocumentRole = "received"
)