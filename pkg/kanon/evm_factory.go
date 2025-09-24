package kanon

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	goabi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/ajna-inc/essi/pkg/kanon/ledger"
)

// evmLedger implements ledger.KanonLedger using go-ethereum JSON-RPC calls.
// It encodes minimal read operations needed for holder flows.
type evmLedger struct {
	rpcURL   string
	contract common.Address
	client   *ethclient.Client
	chainID  *big.Int
	privKey  *ecdsa.PrivateKey
}

func newEvmLedger(cfg Config) ledger.KanonLedger {
	if cfg.RpcUrl == "" || cfg.ContractAddress == "" {
		return nil
	}
	c, err := ethclient.Dial(cfg.RpcUrl)
	if err != nil {
		return nil
	}
	var key *ecdsa.PrivateKey
	if cfg.PrivateKey != "" {
		k, kerr := crypto.HexToECDSA(strings.TrimPrefix(cfg.PrivateKey, "0x"))
		if kerr == nil {
			key = k
		}
	}
	return &evmLedger{rpcURL: cfg.RpcUrl, contract: common.HexToAddress(cfg.ContractAddress), client: c, chainID: big.NewInt(cfg.ChainID), privKey: key}
}

// Note: We do not have a generated ABI binding in this repo; instead we use
// low-level CallContract helpers via bind.CallOpts and crafted calldata.
// To keep this simple and dependency-light, we assume canonical function
// selectors and decode results naively where possible.

func (e *evmLedger) GetSchema(schemaId string) (string, error) {
	// Function signature: getSchema(string) returns (string, address[])
	// We only need the first return param (string JSON).
	// In production, generate ABI via abigen or embed ABI JSON.
	type resp struct {
		JSON string
	}
	// Use a light approach: call via a bound contract with ABI json string.
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "schemaId", "type": "string" } ], "name": "getSchema", "outputs": [ { "internalType": "string", "name": "", "type": "string" }, { "internalType": "address[]", "name": "", "type": "address[]" } ], "stateMutability": "view", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	var outVals []interface{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	callOpts := &bind.CallOpts{Context: ctx}
	if err := contract.Call(callOpts, &outVals, "getSchema", schemaId); err != nil {
		return "", err
	}
	if len(outVals) < 2 {
		return "", fmt.Errorf("getSchema: unexpected return count")
	}
	jsonStr, ok := outVals[0].(string)
	if !ok {
		return "", fmt.Errorf("getSchema: json not string")
	}
	// Validate it's JSON
	var js map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &js); err != nil {
		return "", fmt.Errorf("invalid schema json from contract: %w", err)
	}
	return jsonStr, nil
}

func (e *evmLedger) GetCredentialDefinition(credDefId string) (string, string, string, error) {
	// Function signature: getCredentialDefinition(string) returns (string id, string version, string json)
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "credDefId", "type": "string" } ], "name": "getCredentialDefinition", "outputs": [ { "internalType": "string", "name": "", "type": "string" }, { "internalType": "string", "name": "", "type": "string" }, { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	var outVals []interface{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	callOpts := &bind.CallOpts{Context: ctx}
	if err := contract.Call(callOpts, &outVals, "getCredentialDefinition", credDefId); err != nil {
		return "", "", "", err
	}
	if len(outVals) < 3 {
		return "", "", "", fmt.Errorf("getCredentialDefinition: unexpected return count")
	}
	id, _ := outVals[0].(string)
	version, _ := outVals[1].(string)
	payload, _ := outVals[2].(string)
	// Validate JSON
	var js map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &js); err != nil {
		return "", "", "", fmt.Errorf("invalid cred def json from contract: %w", err)
	}
	return id, version, payload, nil
}

// DID operations
func (e *evmLedger) GetDID(did string) (string, string, error) {
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "_did", "type": "string" } ], "name": "getDID", "outputs": [ { "internalType": "string", "name": "", "type": "string" }, { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	var outVals []interface{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	callOpts := &bind.CallOpts{Context: ctx}
	if err := contract.Call(callOpts, &outVals, "getDID", did); err != nil {
		return "", "", err
	}
	if len(outVals) < 2 {
		return "", "", fmt.Errorf("getDID: unexpected return count")
	}
	doc, _ := outVals[0].(string)
	meta, _ := outVals[1].(string)
	return doc, meta, nil
}

func (e *evmLedger) RegisterDID(did string, didDocJson string, metadata string) error {
	if e.privKey == nil || e.chainID == nil {
		return fmt.Errorf("evm ledger: missing signer or chainId")
	}
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "_did", "type": "string" }, { "internalType": "string", "name": "_context", "type": "string" }, { "internalType": "string", "name": "_metadata", "type": "string" } ], "name": "registerDID", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	auth, err := bind.NewKeyedTransactorWithChainID(e.privKey, e.chainID)
	if err != nil {
		return err
	}
	_, err = contract.Transact(auth, "registerDID", did, didDocJson, metadata)
	return err
}

func (e *evmLedger) UpdateDID(did string, didDocJson string, metadata string) error {
	if e.privKey == nil || e.chainID == nil {
		return fmt.Errorf("evm ledger: missing signer or chainId")
	}
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "_did", "type": "string" }, { "internalType": "string", "name": "_context", "type": "string" }, { "internalType": "string", "name": "_metadata", "type": "string" } ], "name": "updateDID", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	auth, err := bind.NewKeyedTransactorWithChainID(e.privKey, e.chainID)
	if err != nil {
		return err
	}
	_, err = contract.Transact(auth, "updateDID", did, didDocJson, metadata)
	return err
}

// AnonCreds-related resources (write + read)
func (e *evmLedger) RegisterSchema(schemaId string, detailsJson string, issuerId string) error {
	if e.privKey == nil || e.chainID == nil {
		return fmt.Errorf("evm ledger: missing signer or chainId")
	}
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "_schemaId", "type": "string" }, { "internalType": "string", "name": "_details", "type": "string" }, { "internalType": "string", "name": "_issuerId", "type": "string" } ], "name": "registerSchema", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	auth, err := bind.NewKeyedTransactorWithChainID(e.privKey, e.chainID)
	if err != nil {
		return err
	}
	_, err = contract.Transact(auth, "registerSchema", schemaId, detailsJson, issuerId)
	return err
}

func (e *evmLedger) AddApprovedIssuer(schemaId string, issuerAddress string) error {
	if e.privKey == nil || e.chainID == nil {
		return fmt.Errorf("evm ledger: missing signer or chainId")
	}
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "_schemaId", "type": "string" }, { "internalType": "address", "name": "_issuer", "type": "address" } ], "name": "addApprovedIssuer", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	auth, err := bind.NewKeyedTransactorWithChainID(e.privKey, e.chainID)
	if err != nil {
		return err
	}
	_, err = contract.Transact(auth, "addApprovedIssuer", schemaId, common.HexToAddress(issuerAddress))
	return err
}

func (e *evmLedger) RegisterCredentialDefinition(credDefId string, schemaId string, issuer string, detailsJson string) error {
	if e.privKey == nil || e.chainID == nil {
		return fmt.Errorf("evm ledger: missing signer or chainId")
	}
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "_credDefId", "type": "string" }, { "internalType": "string", "name": "_schemaId", "type": "string" }, { "internalType": "string", "name": "_issuerId", "type": "string" }, { "internalType": "string", "name": "_detailsJson", "type": "string" } ], "name": "registerCredentialDefinition", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	auth, err := bind.NewKeyedTransactorWithChainID(e.privKey, e.chainID)
	if err != nil {
		return err
	}
	_, err = contract.Transact(auth, "registerCredentialDefinition", credDefId, schemaId, issuer, detailsJson)
	return err
}

func (e *evmLedger) RegisterRevocationRegistry(revRegDefId string, definitionJson string) error {
	// Not supported by current contract
	return fmt.Errorf("not supported by contract: RegisterRevocationRegistry")
}

func (e *evmLedger) GetRevocationRegistry(revRegDefId string) (string, error) {
	// Not supported by current contract
	return "", fmt.Errorf("not supported by contract: GetRevocationRegistry")
}

func (e *evmLedger) StoreStatusList(statusListId string, statusPurpose string, encodedList string, issuerId string, length int) error {
	if e.privKey == nil || e.chainID == nil {
		return fmt.Errorf("evm ledger: missing signer or chainId")
	}
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "_statusListId", "type": "string" }, { "internalType": "string", "name": "_statusPurpose", "type": "string" }, { "internalType": "string", "name": "_encodedList", "type": "string" }, { "internalType": "string", "name": "_issuerId", "type": "string" }, { "internalType": "uint256", "name": "_length", "type": "uint256" } ], "name": "storeStatusList", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	auth, err := bind.NewKeyedTransactorWithChainID(e.privKey, e.chainID)
	if err != nil {
		return err
	}
	_, err = contract.Transact(auth, "storeStatusList", statusListId, statusPurpose, encodedList, issuerId, big.NewInt(int64(length)))
	return err
}

func (e *evmLedger) GetStatusList(statusListId string) (statusPurpose string, encodedList string, issuerId string, length int, timestamp int64, err error) {
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "_statusListId", "type": "string" } ], "name": "getStatusList", "outputs": [ { "internalType": "string", "name": "statusPurpose", "type": "string" }, { "internalType": "string", "name": "encodedList", "type": "string" }, { "internalType": "string", "name": "issuerId", "type": "string" }, { "internalType": "uint256", "name": "length", "type": "uint256" }, { "internalType": "uint256", "name": "timestamp", "type": "uint256" } ], "stateMutability": "view", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	var outVals []interface{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	callOpts := &bind.CallOpts{Context: ctx}
	if callErr := contract.Call(callOpts, &outVals, "getStatusList", statusListId); callErr != nil {
		err = callErr
		return
	}
	if len(outVals) < 5 {
		err = fmt.Errorf("getStatusList: unexpected return count")
		return
	}
	sp, _ := outVals[0].(string)
	enc, _ := outVals[1].(string)
	iss, _ := outVals[2].(string)
	ln, _ := outVals[3].(*big.Int)
	ts, _ := outVals[4].(*big.Int)
	return sp, enc, iss, int(ln.Int64()), ts.Int64(), nil
}

func (e *evmLedger) UpdateStatusList(statusListId string, encodedList string) error {
	if e.privKey == nil || e.chainID == nil {
		return fmt.Errorf("evm ledger: missing signer or chainId")
	}
	abiJSON := `[ { "inputs": [ { "internalType": "string", "name": "_statusListId", "type": "string" }, { "internalType": "string", "name": "_encodedList", "type": "string" } ], "name": "updateStatusList", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]`
	contract := bind.NewBoundContract(e.contract, mustParseABI(abiJSON), e.client, e.client, e.client)
	auth, err := bind.NewKeyedTransactorWithChainID(e.privKey, e.chainID)
	if err != nil {
		return err
	}
	_, err = contract.Transact(auth, "updateStatusList", statusListId, encodedList)
	return err
}

// --- helpers ---
func mustParseABI(jsonABI string) goabi.ABI {
	parsed, err := goabi.JSON(strings.NewReader(jsonABI))
	if err != nil {
		panic(err)
	}
	return parsed
}
