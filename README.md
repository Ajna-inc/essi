# ESSI Agent

ESSI (Enterprise Self-Sovereign Identity) is a Go-based implementation of a decentralized identity agent that supports verifiable credentials, proof presentations, and DID (Decentralized Identifier) operations using AnonCreds and DIDComm protocols.

## Features

- **Verifiable Credentials**: Issue, hold, and verify AnonCreds-based credentials
- **Proof Presentations**: Create and verify zero-knowledge proofs
- **DID Operations**: Create and resolve peer DIDs and DID key methods
- **Out-of-Band (OOB) Invitations**: Generate and process connection invitations
- **DIDComm Messaging**: Secure peer-to-peer communication
- **Blockchain Integration**: Kanon network integration for credential definitions and schemas
- **Storage**: Aries Askar for secure credential and key storage

## Architecture

ESSI Agent is built with a modular architecture:

- **Core Agent**: Central agent framework with dependency injection
- **Storage Module**: Aries Askar for secure storage
- **DIDs Module**: Support for peer DIDs and DID key methods  
- **DIDComm Module**: Message handling and transport
- **AnonCreds Module**: Anonymous credentials and presentations
- **Kanon Module**: Blockchain registry for schemas and credential definitions

## Quick Start

### Prerequisites

- Go 1.19 or later
- CGO enabled (`CGO_ENABLED=1`)
- Native dependencies handled by Makefile (prepare-askar integrated)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Ajna-inc/essi
cd essi
```

2. Setup development environment (tools + dependencies):
```bash
make dev-setup
```

3. Build the project:
```bash
make kanon-test
```

## Usage

### 1. Creating Out-of-Band Invitations

Create an invitation that other agents can use to connect:

```bash
# Basic invitation
make run-create-oob

# Custom configuration
make run-create-oob ARGS='-host 0.0.0.0 -port 3001 -label "My Agent"'

# Multi-use invitation
make run-create-oob
```

**Parameters:**
- `-host`: Inbound host (default: 127.0.0.1)
- `-port`: Inbound port (default: 3001)  
- `-label`: Agent label (default: "Essi-Go")
- `-db`: Database path (default: "./create-oob-askar.db")

### 2. Running Integration Tests

Test various agent capabilities:

```bash
# Full flow (connection + credential + proof)
make run ARGS='-action e2eFullFlow'
```

**Parameters:**
- `-action`: Action to perform (e2eIssue, e2eFullFlow, testConnections, testDIDs, testSchema, testCredDef)
- `-host`: Agent host (default: 127.0.0.1)
- `-port`: Agent port (default: 9002)
- `-cache`: Use fixed IDs for caching tests

### 3. Agent Configuration

The agent can be configured through code or environment:

```go
config := &AgentConfig{
    Label:    "My Agent",
    Host:     "127.0.0.1", 
    Port:     9002,
    DBPath:   "./my-agent.db",
    StoreID:  "my-agent-store",
    StoreKey: "secure-key-123",
    KanonConfig: kanonpkg.KanonModuleConfigOptions{
        Networks: []kanonpkg.NetworkConfig{{
            Network:         "testnet",
            RpcUrl:          "http://127.0.0.1:8545/",
            PrivateKey:      "0x...",
            ChainId:         31337,
            ContractAddress: "0x...",
        }},
    },
}

agent, err := SetupAgent(config, metrics)
```

## Key Components

### Agent Modules

- **AskarModule**: Secure storage for keys and credentials
- **KanonModule**: Blockchain integration for public registries
- **DidsModule**: DID creation and resolution
- **AnonCredsModule**: Anonymous credentials functionality
- **DidCommModule**: Secure messaging between agents
- **CredentialsModule**: Credential issuance and verification protocols
- **ProofsModule**: Proof presentation protocols

### Supported Protocols

- **DID Exchange 1.1**
- **Connections 1.0**
- **Issue Credential 2.0**
- **Present Proof 2.0**
- **Out-of-Band 1.1**
- **Trust Ping 1.0**

### Credential Formats

- **AnonCreds**: Anonymous credentials with zero-knowledge proofs

## API Examples

### Creating a Connection

```go
// Process an out-of-band invitation
connOps := NewConnectionOperations(agent, metrics)
connection, err := connOps.ProcessOOBInvitation(invitationURL)

// Wait for connection to complete
err = connOps.WaitForConnectionComplete(connection.ID, 30*time.Second)
```

### Issuing a Credential

```go
// Create credential service
credService := NewCredentialService(agent, anonApi, metrics)

// Issue credential to connection
attributes := map[string]string{
    "name":  "Alice Smith",
    "age":   "30", 
    "title": "Developer",
}

err := credService.OfferCredentialToConnection(
    connectionID, 
    credentialDefinitionID, 
    attributes,
)
```

### Requesting a Proof

```go
// Create proof operations
proofOps := NewProofOperations(agent, anonApi, metrics)

// Execute proof flow
err := proofOps.ExecuteProofFlow(connectionID)
```

## Storage

ESSI Agent uses Aries Askar for secure storage:

- **Keys**: Private keys are stored encrypted
- **Credentials**: Credentials are stored with metadata
- **DIDs**: DID documents and associated keys
- **Records**: Connection records and protocol state

Database files are SQLite by default but Askar supports PostgreSQL for production.

## Network Configuration

For local development, ESSI works with:

- **Local Blockchain**: Hardhat/Anvil at http://127.0.0.1:8545
- **Contract Address**: 0x5FbDB2315678afecb367f032d93F642f64180aa3 (local)
- **Chain ID**: 31337 (Hardhat default)

For production, configure appropriate network endpoints and contract addresses.

## Development

### Building

```bash
# Build all commands
make build

# Run tests
make test

# Run with debug logging
RUST_LOG=debug make run ARGS='-action e2eIssue'
```

### Dependencies

- **Go modules**: Standard Go dependency management
- **Native libraries**: Aries Askar, AnonCreds-RS via CGO bindings
- **Build tools**: CGO-compatible C compiler

## Troubleshooting

### Common Issues

1. **CGO_ENABLED=1 required**: ESSI requires CGO for native dependencies
2. **Port conflicts**: Ensure ports 9002, 3001 are available
3. **Database locks**: Stop existing agents before running new instances  
4. **Network connectivity**: Verify blockchain RPC endpoint is accessible

### Debug Mode

Enable detailed logging:
```bash
RUST_LOG=debug make run ARGS='-action e2eIssue'
```

## Contributing

1. Follow Go conventions and existing code patterns
2. Add tests for new functionality
3. Update documentation for API changes
4. Ensure CGO compatibility

## License

Apache License 2.0. See the LICENSE file for details.

