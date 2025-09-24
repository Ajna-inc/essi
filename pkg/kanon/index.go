// Package kanon provides a plugin for Credo-Go following the Credo-TS pattern
// It includes support for DIDs and AnonCreds on Ethereum-based ledgers
package kanon

// This file serves as the main entry point for the Kanon plugin
// In Go, we don't have export * like TypeScript, but all public 
// types and functions (starting with capital letters) are automatically exported

// The main exports from this package are:
// - KanonModule: The main module following Credo-TS plugin pattern
// - KanonModuleConfig: Configuration for the module
// - NetworkConfig: Network configuration
// - EthereumLedgerService: Service for interacting with the ledger
//
// From sub-packages:
// - dids.KanonDidRegistrar: DID registrar for Kanon
// - dids.KanonDidResolver: DID resolver for Kanon  
// - anoncreds.KanonAnonCredsRegistry: AnonCreds registry for Kanon