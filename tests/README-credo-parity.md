Essi-Go DIDComm/Core Test Plan

Goal
- Define Essi-Go tests using Essi’s own APIs and patterns (no Credo‑TS constructs or helpers in test code).
- Cover agent, transport, connections, OOB, mediation/pickup, dispatcher, and envelope services implemented in this repo.
- Out of scope: anoncreds, hedera, openid, tenants, drizzle-specific storage.

How to use this list
- Each section describes what to verify and how to implement the tests using Essi types only.
- Prefer in‑memory subject transport for unit/e2e; use HTTP inbound only for receiver‑specific behavior.
- Run patterns
  - Unit/library: `go test ./pkg/...`
  - Integration (subject transport + NewTestAgent): `go test -tags=integration ./tests/...`

Directory layout and package naming (Go tests)
- Place tests in a dedicated `tests` subfolder per package to avoid polluting the main package and to enforce external‑package testing.
- Use external test packages: `package <pkg>_test` in the test files, and import the package under test.
- Keep top‑level integration suites in `tests/integration`.
- Example
  - Production: `pkg/didcomm/transport/*.go`
  - Tests: `pkg/didcomm/transport/tests/*.go` with `package transport_test`
  - Import: `github.com/ajna-inc/essi/pkg/didcomm/transport`
  - Run: `go test ./...` (will include sub‑packages under `tests/`)

Migration note
- Move existing in‑package tests to subfolders:
  - `pkg/didcomm/transport/subject_transport_test.go` → `pkg/didcomm/transport/tests/subject_transport_test.go`
  - `pkg/core/agent/agent_e2e_test.go` → `pkg/core/agent/tests/agent_e2e_test.go`

Agent & Transports
- What to verify
  - Two agents initialize and connect via Out‑of‑Band (OOB) handshake.
  - Message flow across the connection succeeds.
  - Agent lifecycle toggles `IsInitialized()` across shutdown and re‑init.
- How
  - Initialize agents with `agent.NewAgent` + `Initialize` (modules: Askar, DIDs, DidComm).
  - Use HTTP inbound (via `InboundHost/InboundPort`) or in‑memory subject transport by registering `transport.NewSubjectOutboundTransport()` on the sender and `transport.RegisterSubjectEndpoint()` handlers that call `MessageReceiver.ReceiveEncrypted` on the receiver.
  - Create OOB invitation via DI‑resolved OutOfBandApi and process it on the other agent using `Agent.ProcessOOBInvitation`.
  - Await connection completion using `GetConnections()` polling or `connection.stateChanged` events.
  - Send a DIDComm message using `MessageSender` and assert `message.received` on the receiver event bus.
  - File: tests/integration/subject_e2e_test.go (integration tag)

Test Utilities
- Location: tests/testutil
- Components
  - NewTestAgent(t, TestAgentOptions): spins up an Agent with in‑memory Askar + DIDs + DidComm; optionally registers subject outbound transport. Cleans up via t.Cleanup.
  - SetupSubjectTransports(aDM, aEndpoint, bDM, bEndpoint): registers subject endpoints that forward encrypted payloads to each agent’s MessageReceiver.ReceiveEncrypted; use with SubjectOutboundTransport for socket‑free e2e.
  - WaitForEvent/WaitForMessageType/WaitForConnComplete: event waiters built on the in‑memory Bus.
  - TestLogger: minimal logger implementing core logger.Logger for tests.
  - SenderSpy: captures OutboundMessageContext for asserting Dispatcher→Sender integration.
- Usage
  - In tests, import `github.com/ajna-inc/essi/tests/testutil` and call helpers to compose scenarios quickly.

Basic Messages & Problem Reports
- What to verify
  - Receiving a Basic Message (`https://didcomm.org/basicmessage/1.0/message`) is parsed without error.
  - Receiving a Problem Report (`https://didcomm.org/notification/1.0/problem-report`) is parsed and does not crash; can optionally assert a log or event.
- How
  - Construct `messages.BaseMessage` with the respective `@type` and minimal body, send via `MessageSender`, ensure `Dispatcher` routes to `basic/handlers` without returning an outbound.
  - File: pkg/didcomm/modules/basic/tests/basic_handlers_test.go (package basic_test).

Dispatcher
- What to verify
  - Registering a handler for a specific `@type` routes inbound messages to that handler.
  - Unknown message types return an error and do not send outbound.
  - If a handler returns an `OutboundMessageContext`, the dispatcher uses the configured `MessageSender` (async) or returns it via `DispatchSync` for inline return‑route.
- How
  - Create a `Dispatcher` and register a handler for a custom type; assert the handler receives `InboundMessageContext` and returns a minimal response message.
  - Use `DispatchSync` to verify returned `OutboundMessageContext` and `Dispatch` to verify integration with a mocked `MessageSender`.
  - File: pkg/didcomm/transport/tests/dispatcher_test.go (package transport_test).

Connections – Handshake and Ping
- What to verify
  - OOB invitation (multi‑use) can be used to create multiple distinct completed connections to different requesters.
  - Trust‑ping request/response works across an established connection and can be correlated via thread id.
- How
  - Use `OutOfBandApi.CreateInvitation` with `multiUseInvitation=true`, process on two separate agents, assert inviter has two completed `ConnectionRecord`s.
  - Build a trust‑ping `messages.BaseMessage` of type `https://didcomm.org/trust-ping/1.0/ping` and send via `MessageSender`; assert receiver emits `message.received` and, if implemented, a `ping_response` is sent.
  - File: pkg/didcomm/modules/connections/services/tests/connection_service_test.go (package services_test).

DID Rotation (RFC0794)
- What to verify
  - `DidRotateService.CreateRotate` updates our DID on the `ConnectionRecord` and returns a rotate message.
  - `ProcessRotate` updates their DID on the `ConnectionRecord` and returns an ack.
  - `CreateHangup` and `ProcessHangup` set state to `abandoned`.
- How
  - Create a connection record, call the service methods and assert record fields/state mutations; assert ack threading to rotate.
  - File: pkg/didcomm/modules/connections/services/tests/did_rotate_service_test.go (package services_test).

Out‑of‑Band (OOB)
- What to verify
  - OOB invitation creation populates expected fields (handshake protocols, inline service, recipient keys, label/goal metadata).
  - Receiving invitation via object and via URL creates appropriate records and leads to completed connection(s).
  - Validation guards are enforced (e.g., handshake and/or requests required; invalid combinations rejected).
  - Optional: legacy connectionless invitation handling if implemented (`~service` decorator and URL encoding).
- How
  - Via `OutOfBandApi` create invitation with and without handshake and verify inline `did-communication` service with `did:key` recipient keys.
  - Convert to URL using `OutOfBandApi.InvitationToUrl`, process using `Agent.ProcessOOBInvitation`, and assert record state transitions.
  - Verify error cases by calling create/receive with invalid combinations.
  - File: pkg/didcomm/modules/connections/services/tests/connection_service_test.go (package services_test).

OOB Handshake Reuse
- What to verify
  - `oob/1.1/handshake-reuse` inbound with an existing ready connection produces a `handshake-reuse-accepted` outbound context.
  - Non‑reusable invitations transition to `done` on sender/receiver sides as implemented in handlers.
  - Event `oob.handshakeReused` (or `oob.OutOfBandEventHandshakeReused`) is emitted with correlation id and connection id.
- How
  - Create OOB record (non‑reusable), complete a connection, then inject a `HandshakeReuseMessage` via `MessageReceiver.ReceiveEncrypted` (or dispatch directly with a crafted `InboundMessageContext`). Assert outbound acceptance and state updates in the OOB repository; assert event emission.
  - File: pkg/didcomm/modules/oob/tests/handshake_reuse_test.go (package oob_test).

Mediation & Pickup (Provision + Runtime)
- What to verify
  - Coordinate Mediation request→grant, default mediator selection, start pickup v1, and reception of messages via batch.
  - Keylist update (add/remove) messages are handled when OOB invitations are created/removed and carry the correct recipient key.
- How
  - Use `routingmessages.MediationRequest`, `MediationGrant`, and keylist update handlers in pkg/didcomm/modules/routing.
  - Start `Agent.startPickupV1` for the recipient and assert batch response processing.
  - Files: tests/integration/mediator_provision_e2e_test.go, tests/integration/oob_mediation_e2e_test.go.

Message Pickup v2
- What to verify
  - `messagepickup/2.0/delivery` handler decrypts each attachment, dispatches the inner plaintext messages, and collects ids to ack (even if ack is sent asynchronously elsewhere).
  - `status-request`/`delivery-request` messages can be created/sent (optional if not yet in use).
- How
  - Build a `V2Delivery` with one or more attachments holding encrypted messages addressed to the agent; POST to receiver or dispatch context directly and assert that registered handlers for inner messages are invoked (e.g., by subscribing to `message.received`).
  - File: pkg/didcomm/modules/messagepickup/v2/tests/delivery_handler_test.go (package v2_test).

Handshake Protocol Variants
- What to verify
  - Both `connections/1.0` and `didexchange/1.1` handshakes are supported end‑to‑end.
- How
  - Create invitations or craft request/response messages for each protocol and assert `ConnectionRecord` reaches `complete`.
  - File: pkg/didcomm/modules/connections/services/tests/connection_service_test.go.

Message Receiver (Inbound HTTP)
- What to verify
  - Handle content types: `application/didcomm-envelope-enc`, `application/didcomm-encrypted+json`, `application/didcomm+json`, `application/json`.
  - Auto‑detect encrypted vs plaintext when no Content‑Type.
  - If decrypt fails due to no matching recipient key, ACK silently (HTTP 200).
  - If `~transport.return_route` is set and we can authcrypt, inline pack and return cipher body.
  - Emit `message.received` with correlation id and associated connection id.
- How
  - Start `MessageReceiver` HTTP server; POST payloads with varying content types; assert status codes and bodies.
  - Simulate inbound with senderKey to trigger inline response; verify content type and JWE fields.
  - File: pkg/didcomm/transport/tests/message_receiver_test.go (package transport_test).

Receiver Lifecycle & Health
- What to verify
  - `StartHTTPServer`/`StopHTTPServer` toggle `IsRunning()` and bind to configured host/port.
  - `/health` responds with JSON and reports running state; `/test` echoes headers.
- How
  - Start on an ephemeral port, GET `/health` and `/test`, stop server, assert states and response shape.
  - File: pkg/didcomm/transport/tests/message_receiver_lifecycle_test.go (package transport_test).

Message Sender (Outbound)
- What to verify
  - Prefer authcrypt when `MyKeyId` exists; else anoncrypt.
  - Add `~transport.return_route` for handshake (except `/complete`) and when no inbound endpoint exists.
  - Service resolution order: connection endpoint → DID resolve → ReceivedDidRepository → OOB inline service; error if none.
  - Routing via RFC0094 forward wrappers (outermost→innermost per routingKeys).
  - Queue transport detection and session reuse when present.
- How
  - Inspect chosen package type via envelope and senderKey presence; verify `~transport.return_route` decorator where required.
  - Force each resolution branch by stubbing resolver/repository; assert endpoint/keys used.
  - Assert nested forward message wrapping equals routingKeys length.
  - File: pkg/didcomm/transport/tests/message_sender_test.go (package transport_test).

HTTP Outbound Transport
- What to verify
  - `HttpOutboundTransport.CanSend` recognizes `http(s)://` endpoints.
  - `Send` posts with DIDComm content type; returns status/body/ctype; surfaces non‑2xx as error.
- How
  - Spin up an `httptest` server that asserts headers and returns 200 (and another returning 400) and assert results.
  - File: pkg/didcomm/transport/tests/http_outbound_transport_test.go (package transport_test).

Envelope Service (Pack/Unpack)
- What to verify
  - Pack plaintext, anoncrypt, and authcrypt when sender key set; protected header reflects `alg` and `enc`.
  - Unpack validates protected header and recovers plaintext; supports `kid` formats: did:key (with/without fragment), base58, base64url.
  - Error cases: unsupported `enc/alg`, wallet unavailable, no recipient match, malformed protected header.
- How
  - Table‑driven tests over `kid` formats and error cases.
  - File: pkg/didcomm/services/tests/envelope_service_test.go (package services_test).

JWS Service
- What to verify
  - `CreateJws` signs payloads with Ed25519 keys from wallet; protected header encoding and signature verify.
  - `VerifyJws` validates signature for both `kid` and embedded `jwk` cases.
  - `CreateSignedAttachment` sets `kid` to invitation key and embeds JWK.
- How
  - Create an Ed25519 key in wallet; sign/verify round‑trip; ensure attachment contains base64 payload and JWS with expected fields.
  - File: pkg/didcomm/services/tests/jws_service_test.go (package services_test).

DID Resolution & Key Normalization
- What to verify
  - did:key → base58 normalization extracts raw 32‑byte Ed25519 key (strip multicodec ed01).
  - DidResolverService resolves did:peer/did:key documents and exposes DIDComm services; prioritize `did-communication`/`IndyAgent` types.
  - ReceivedDidRepository fallback provides services when resolver not available.
- How
  - Validate normalization on did:key examples and multibase inputs.
  - Mock resolver responses for did:peer and assert service extraction.
  - Files: pkg/dids/tests/did_resolver_test.go, pkg/didcomm/transport/tests/key_utils_test.go.

Forward (RFC0094)
- What to verify
  - Forward handler parses a `routing/1.0/forward` message without error.
  - Optional: if/when forward‑unwrapping is implemented, the inner message is dispatched.
- How
  - Craft a minimal forward message and dispatch; assert no error; extend once unwrapping is available.
  - File: pkg/didcomm/modules/routing/tests/forward_handler_test.go (package routing_test).

Message Pickup v1
- What to verify
  - Recipient initiates pickup v1 with `~transport.return_route=all`; mediator responds inline with batch containing `messages~attach`.
  - Inbound receiver unwraps and dispatches each attached message.
- How
  - Start `Agent.startPickupV1` and assert batch pickup requests are sent and batch responses are processed (events or state changes).
  - File: tests/integration/pickup_v1_e2e_test.go.

Subject Transport (In‑Memory)
- What to verify
  - Registration and dispatch to subject endpoints works.
  - Missing handler returns error.
  - `CanSend` true for `wss://subject/*` and `ws://subject/*`, false otherwise; normalization preserves path.
- How
  - Use `RegisterSubjectEndpoint`/`UnregisterSubjectEndpoint` with `SubjectOutboundTransport.Send`.
  - File: pkg/didcomm/transport/tests/subject_transport_test.go.

Queue Repository
- What to verify
  - `Add`, `GetAll`, `GetByConnection`, and `Clear` behave as expected; `SetGlobalQueueRepository` switches implementation.
- How
  - Use the in‑memory repo to push sample messages, assert retrieval and clearing; swap repo and assert usage.
  - File: pkg/didcomm/transport/tests/queue_repo_test.go (package transport_test).

Out of Scope (for now)
- Anoncreds flows (issue/proof, revocation)
- OpenID4VC
- Hedera
- Tenants
- Drizzle storage and migrations

Proposed Go Test Files (summary) — subfolder external tests
- pkg/core/agent/tests/agent_e2e_test.go
- pkg/didcomm/transport/tests/dispatcher_test.go
- pkg/didcomm/transport/tests/message_receiver_test.go
- pkg/didcomm/transport/tests/message_sender_test.go
- pkg/didcomm/services/tests/envelope_service_test.go
- pkg/didcomm/modules/connections/services/tests/connection_service_test.go
- pkg/didcomm/modules/messagepickup/v1/tests/pickup_test.go
- pkg/dids/tests/did_resolver_test.go
- pkg/didcomm/transport/tests/key_utils_test.go
- tests/integration/mediator_provision_e2e_test.go
- tests/integration/oob_mediation_e2e_test.go
- tests/integration/pickup_v1_e2e_test.go

Key Behaviors (high‑value checks)
- Keep TheirRecipientKey in did:key format for encryption; normalize only for internal matching.
- Prefer did‑communication/IndyAgent service types in DIDDocs for compatibility.
- Silent 200 on decrypt path when message isn’t for us (no recipient match).
- Prefer authcrypt when MyKeyId exists in wallet.
- Add `~transport.return_route` for handshake (except complete) and when no inbound endpoint.

Notes
- Use the in‑memory subject transport for most tests to avoid network flakiness.
- Limit assertions to observable behaviors (events/records), not internal logs.
