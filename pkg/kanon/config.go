package kanon

// Config holds settings for the Kanon module (EVM-based anoncreds registry).
type Config struct {
	Enabled         bool
	Network         string
	RpcUrl          string
	PrivateKey      string
	ContractAddress string
	ChainID         int64
	// UseMemory forces an in-memory ledger for testing without network access
	UseMemory bool
}
