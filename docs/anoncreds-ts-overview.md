# Credo-TS AnonCreds Architecture and Flow (Overview)

This document summarizes how anoncreds is implemented in Credo-TS, focusing on credential issuance (offer → request → issue) and the components involved. It highlights JSON shapes expected by anoncreds-rs and maps each part to our current Go code so we can align interop.

## High-level Flow

1) Issuer creates offer
- Format service: `packages/anoncreds/src/formats/AnonCredsCredentialFormatService.ts`
  - `createOffer()` → `createAnonCredsOffer()`
  - Delegates to Issuer service to build anoncreds offer payload
- Issuer service: `packages/anoncreds/src/anoncreds-rs/AnonCredsRsIssuerService.ts`
  - `createCredentialOffer()`
    - Looks up stored CredDef + KeyCorrectnessProof (KCP) via repositories
    - Calls `CredentialOffer.create({ credentialDefinitionId, keyCorrectnessProof, schemaId })`
    - Returns anoncreds-rs JSON for `CredentialOffer`

2) Holder accepts offer → creates request
- Format service: `acceptOffer()`
  - Parses offer attachment JSON
  - Fetches `credentialDefinition` via registry (`fetchCredentialDefinition` utils)
  - Delegates to Holder service `createCredentialRequest()` with offer + cred def
- Holder service: `packages/anoncreds/src/anoncreds-rs/AnonCredsRsHolderService.ts`
  - `createCredentialRequest()`
    - Ensures link secret
    - Calls anoncreds-rs `CredentialRequest.create({ credentialOffer, credentialDefinition, linkSecret })`
    - Returns `credentialRequest` and `credentialRequestMetadata`

3) Issuer accepts request → issues credential
- Format service: `acceptRequest()`
  - Loads issuer-side `credentialDefinition` and revocation data (if any)
  - Delegates to Issuer service `createCredential()`
- Issuer service: `createCredential()`
  - Calls anoncreds-rs `Credential.create({ offer, request, cred_def, cred_def_priv, values, revocationConfig? })`
  - Returns issued credential JSON (legacy anoncreds), then stored as W3C internally

## Registry Resolution (Schema/CredDef/Revocation)

- `AnonCredsRegistryService` (router): `packages/anoncreds/src/services/registry/AnonCredsRegistryService.ts`
  - Picks registry by `supportedIdentifier` regex
  - Concrete registries (Indy VDR, Cheqd, Kanon in our app) implement read/write ops
- Utilities to fetch:
  - `fetchSchema`, `fetchCredentialDefinition`, `fetchRevocationRegistryDefinition`, `fetchRevocationStatusList` (under `packages/anoncreds/src/utils`)

## JSON Shapes Required by anoncreds-rs

CredentialOffer (indispensable parts):
```
{
  "schema_id": "<string>",
  "cred_def_id": "<string>",
  "key_correctness_proof": {
    "c": { "value": "<bigint>" },
    "xz_cap": { "value": "<bigint>" },
    "xr_cap": [
      ["name", { "value": "<bigint>" }],
      ["role", { "value": "<bigint>" }],
      ["master_secret", { "value": "<bigint>" }]
    ]
  },
  "nonce": { "value": "<bigint>" }
}
```

CredentialDefinition (public part used by holder):
```
{
  "issuerId": "<did>",
  "schemaId": "<schema-id>",
  "type": "CL",
  "tag": "<tag>",
  "value": {
    "primary": {
      "n": { "value": "<bigint>" },
      "s": { "value": "<bigint>" },
      "z": { "value": "<bigint>" },
      "rctxt": { "value": "<bigint>" },
      "r": {
        "name": { "value": "<bigint>" },
        "role": { "value": "<bigint>" },
        "master_secret": { "value": "<bigint>" }
      }
    }
  }
}
```

Note: in some older tests nonce appears as a string at the model layer, but the NodeJS anoncreds-rs parser expects BigNumber wrappers at the raw JSON boundary. KCP fields always require wrappers.

## Credo-TS Components (Key Files)

- Format orchestration:
  - `packages/anoncreds/src/formats/AnonCredsCredentialFormatService.ts`
    - Creates/accepts offers and requests, calls holder/issuer services, fetches registry data
- Issuer service (anoncreds-rs):
  - `packages/anoncreds/src/anoncreds-rs/AnonCredsRsIssuerService.ts`
- Holder service (anoncreds-rs):
  - `packages/anoncreds/src/anoncreds-rs/AnonCredsRsHolderService.ts`
- Registry router:
  - `packages/anoncreds/src/services/registry/AnonCredsRegistryService.ts`
- Registry implementations (example):
  - `packages/indy-vdr/src/anoncreds/IndyVdrAnonCredsRegistry.ts`
  - `packages/cheqd/src/anoncreds/services/CheqdAnonCredsRegistry.ts`
- Utils (fetch/identifiers/transforms):
  - `packages/anoncreds/src/utils/*`

## Mapping to Our Go Implementation

- Offer building (issuer):
  - TS: `CredentialOffer.create` via `AnonCredsRsIssuerService.createCredentialOffer`
  - Go: FFI helper `rs.CreateOfferFromParts(schemaId, credDefJson, kcpJson)` returns raw anoncreds offer JSON; service normalizes KCP and nonce

- Holder request:
  - TS: Holder service `createCredentialRequest` expects `credentialOffer` JSON and `credentialDefinition` with wrapped BigNumbers
  - Go: `pkg/didcomm/modules/credentials/services/CredentialService.ProcessOffer` resolves cred def via pluggable registry resolver and embeds it for FFI holder

- Registry resolution:
  - TS: `AnonCredsRegistryService` picks registry by identifier; registries fetch cred def/schema
  - Go: `pkg/anoncreds/registry.Service` routes to registered implementations (memory, kanon/EVM), `resolve.RegistryResolver` adapts to JSON expected by FFI, with BigNumber wrappers

- Issuance:
  - TS: `AnonCredsRsIssuerService.createCredential`
  - Go: `rs.Issuer.CreateCredential(offer, request, values)` using stored secrets; issued credential embedded with `cred_def_json` for holder processing

## Interop Requirements (TS ↔ Go)

- Offers:
  - Ensure `key_correctness_proof.c`, `xz_cap`, `xr_cap[*][1]` are `{ value: string }`
  - Ensure `nonce` is `{ value: string }`

- CredentialDefinition returned to holder:
  - `value.primary` must contain BigNumber wrappers (`n,s,z,rctxt`), and `r` entries wrapped as `{ value }`

- Registries:
  - TS registry that serves EVM/Kanon must return the full `value.primary` object (not `primary.value`) with wrappers intact
  - Go resolver already wraps/normalizes

## Next Steps

1) TS Kanon registry: ensure `getCredentialDefinition()` returns `value.primary` with wrapper objects (no flattening to `primary.value`).
2) TS Holder acceptance: optionally normalize offer just before parsing for safety (wrap nonce/KCP if strings slip through).
3) Go: keep offer normalization (KCP + nonce) and registry resolver wrapping in place.
4) Re-run end-to-end: verify Node holder parses offer; then proceeds to request and issue.




