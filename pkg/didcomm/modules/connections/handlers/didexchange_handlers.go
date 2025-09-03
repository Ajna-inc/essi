package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	services "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
	peer "github.com/ajna-inc/essi/pkg/dids/methods/peer"
	didrepo "github.com/ajna-inc/essi/pkg/dids/repository"
)

// DID Exchange 1.1 handlers
func DidExchangeRequestHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	logger.GetDefaultLogger().Info("🤝 (dispatcher) processing didexchange/1.1/request")

	protocol := getDidExchangeProtocol(ctx)
	if protocol == nil {
		return nil, fmt.Errorf("did exchange protocol not configured")
	}

	var req services.DidExchangeRequestMessage
	if err := json.Unmarshal(ctx.Raw, &req); err != nil {
		return nil, fmt.Errorf("failed to parse didexchange request: %w", err)
	}

	rec, err := protocol.ProcessRequest(ctx.AgentContext, &req, nil)
	if err != nil {
		return nil, err
	}
	if cs := getConnectionService(ctx); cs != nil && rec != nil {
		_ = cs.SaveConnection(rec)
	}

	walletService := getWalletService(ctx)
	if walletService == nil {
		return nil, fmt.Errorf("wallet service not configured")
	}

	// Optional: extract DID only
	var raw map[string]interface{}
	_ = json.Unmarshal(ctx.Raw, &raw)
	if raw != nil {
		if didVal, ok := raw["did"].(string); ok && didVal != "" {
			rec.TheirDid = didVal
		}
		// Minimal did_doc~attach parsing for endpoint/key
		if att, ok := raw["did_doc~attach"].(map[string]interface{}); ok {
			if data, ok := att["data"].(map[string]interface{}); ok {
				if b64, ok := data["base64"].(string); ok && b64 != "" {
					var decoded []byte
					if d, err := base64.RawURLEncoding.DecodeString(b64); err == nil {
						decoded = d
					} else if d, err := base64.StdEncoding.DecodeString(b64); err == nil {
						decoded = d
					}
					if len(decoded) > 0 {
						var doc map[string]interface{}
						if err := json.Unmarshal(decoded, &doc); err == nil {
							if svcs, ok := doc["service"].([]interface{}); ok {
								for _, it := range svcs {
									svc, ok := it.(map[string]interface{})
									if !ok {
										continue
									}
									if t, ok := svc["type"].(string); ok {
										if t != "did-communication" && t != "DIDCommMessaging" && t != "IndyAgent" {
											continue
										}
									}
									if rec.TheirEndpoint == "" {
										if ep, ok := svc["serviceEndpoint"].(string); ok && ep != "" {
											rec.TheirEndpoint = ep
										}
										if epObj, ok := svc["serviceEndpoint"].(map[string]interface{}); ok {
											if uri, ok := epObj["uri"].(string); ok && uri != "" {
												rec.TheirEndpoint = uri
											}
										}
									}
									if rec.TheirRecipientKey == "" {
										if rks, ok := svc["recipientKeys"].([]interface{}); ok && len(rks) > 0 {
											if kid, ok := rks[0].(string); ok {
												if strings.HasPrefix(kid, "did:key:") {
													if b58 := transport.DidKeyToBase58(kid); b58 != "" {
														rec.TheirRecipientKey = b58
													}
												} else if strings.HasPrefix(kid, "#") {
													if auth, ok := doc["authentication"].([]interface{}); ok {
														for _, a := range auth {
															if ao, ok := a.(map[string]interface{}); ok {
																if id, _ := ao["id"].(string); id == kid {
																	if pk, ok := ao["publicKeyBase58"].(string); ok && pk != "" {
																		rec.TheirRecipientKey = pk
																		break
																	}
																	if mb, ok := ao["publicKeyMultibase"].(string); ok && mb != "" {
																		if v := transport.MultibaseToBase58(mb); v != "" {
																			rec.TheirRecipientKey = v
																			break
																		}
																	}
																}
															}
														}
													}
												} else if !strings.Contains(kid, ":") {
													rec.TheirRecipientKey = kid
												}
											}
										}
									}
									if rec.TheirEndpoint != "" && rec.TheirRecipientKey != "" {
										break
									}
								}
								// Persist parsed DIDDoc if repo available (best effort)
								if ctx != nil && ctx.TypedDI != nil && rec != nil && rec.TheirDid != "" {
									if dep, err := ctx.TypedDI.Resolve(di.TokenReceivedDidRepository); err == nil {
										if repo, ok := dep.(*didrepo.ReceivedDidRepository); ok && repo != nil {
											// Skip actual save here to avoid type import cycles; handled elsewhere
											_ = repo
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if rec.TheirRecipientKey == "" && len(ctx.SenderKey) > 0 {
		rec.TheirRecipientKey = encoding.EncodeBase58(ctx.SenderKey)
	}
	if cs := getConnectionService(ctx); cs != nil && rec != nil {
		_ = cs.UpdateConnection(rec)
	}

	ourKey, err := walletService.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create responder key: %w", err)
	}
	endpoint := ""
	if cs := getConnectionService(ctx); cs != nil {
		endpoint = cs.GetDefaultServiceEndpoint()
	}
	ourDidDoc := peer.CreatePeerDidDocument(ourKey.PublicKey, endpoint)
	ourDid, err := peer.CreatePeerDid1(ourDidDoc)
	if err != nil {
		return nil, err
	}
	ourDidDoc.Id = ourDid
	rec.Did = ourDid
	rec.MyKeyId = ourKey.Id
	if cs := getConnectionService(ctx); cs != nil {
		_ = cs.UpdateConnection(rec)
	}

	resp, err := protocol.CreateResponse(ctx.AgentContext, rec, nil, nil)
	if err != nil {
		return nil, err
	}
	inboundForOutbound := &models.InboundMessageContext{
		Message:      &req,
		Raw:          ctx.Raw,
		Connection:   rec,
		SessionID:    ctx.SessionID,
		ReceivedAt:   ctx.ReceivedAt,
		SenderKey:    ctx.SenderKey,
		RecipientKey: ctx.RecipientKey,
		AgentContext: ctx.AgentContext,
		TypedDI:      ctx.TypedDI,
	}
	outboundCtx := models.NewOutboundMessageContext(resp, models.OutboundMessageContextParams{
		AgentContext:          ctx.AgentContext,
		Connection:            rec,
		AssociatedRecord:      rec,
		InboundMessageContext: inboundForOutbound,
	})
	return outboundCtx, nil
}

func DidExchangeResponseHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	logger.GetDefaultLogger().Info("🤝 (dispatcher) processing didexchange/1.1/response")
	protocol := getDidExchangeProtocol(ctx)
	if protocol == nil {
		return nil, fmt.Errorf("did exchange protocol not configured")
	}
	var resp services.DidExchangeResponseMessage
	if err := json.Unmarshal(ctx.Raw, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse didexchange response: %w", err)
	}
	// Find connection by thread id
	connectionSvc := getConnectionService(ctx)
	if connectionSvc == nil {
		return nil, fmt.Errorf("connection service not configured")
	}
	var rec *services.ConnectionRecord
	if conns, err := connectionSvc.GetAllConnections(); err == nil {
		for _, c := range conns {
			if c != nil && c.Tags != nil && c.Tags["threadId"] == resp.GetThreadId() {
				rec = c
				break
			}
		}
	}
	if rec == nil {
		return nil, fmt.Errorf("connection for thread not found")
	}
	// Process response to update state
	if err := protocol.ProcessResponse(ctx.AgentContext, &resp, rec); err != nil {
		return nil, err
	}
	// Update peer DID from response (extract from raw JSON)
	var rawMsg map[string]interface{}
	if err := json.Unmarshal(ctx.Raw, &rawMsg); err == nil {
		if d, ok := rawMsg["did"].(string); ok && d != "" {
			rec.TheirDid = d
			logger.GetDefaultLogger().Infof("Responder DID from response: %s", rec.TheirDid)
		} else {
			logger.GetDefaultLogger().Warn("Responder DID not found in response JSON")
		}
	} else {
		logger.GetDefaultLogger().Warnf("Failed to parse response JSON for DID extraction: %v", err)
	}
	// Always update TheirRecipientKey from authcrypt sender key (base58) so follow-up uses responder key even if DID resolution fails
	if ctx != nil && ctx.SenderKey != nil {
		senderB58 := encoding.EncodeBase58(ctx.SenderKey)
		if senderB58 != "" {
			rec.TheirRecipientKey = senderB58
			_ = connectionSvc.UpdateConnection(rec)
			logger.GetDefaultLogger().Infof("Set TheirRecipientKey from response sender key: %s", senderB58)
		}
	}
	// Parse did_rotate~attach to obtain rotated DID and kid if present (Credo-TS parity)
	if rawMsg != nil {
		if rot, ok := rawMsg["did_rotate~attach"].(map[string]interface{}); ok {
			if data, ok := rot["data"].(map[string]interface{}); ok {
				if b64, ok := data["base64"].(string); ok && b64 != "" {
					var decoded []byte
					if d, err := base64.RawURLEncoding.DecodeString(b64); err == nil {
						decoded = d
					} else if d, err := base64.StdEncoding.DecodeString(b64); err == nil {
						decoded = d
					}
					if len(decoded) > 0 {
						rotated := string(decoded)
						if strings.HasPrefix(rotated, "did:") {
							rec.TheirDid = rotated
							logger.GetDefaultLogger().Infof("Responder rotated DID from did_rotate~attach: %s", rec.TheirDid)
							_ = connectionSvc.UpdateConnection(rec)
						}
					}
				}
				// Attempt to derive rotated recipient key from JWS header kid (did:key) if present
				if jws, ok := data["jws"].(map[string]interface{}); ok {
					if hdr, ok := jws["header"].(map[string]interface{}); ok {
						if kid, ok := hdr["kid"].(string); ok && kid != "" {
							if derived := transport.DidKeyToBase58(kid); derived != "" {
								// Only set if not already updated by DIDDoc resolution later
								if rec.TheirRecipientKey == "" || rec.TheirRecipientKey == rec.InvitationKey {
									rec.TheirRecipientKey = derived
									logger.GetDefaultLogger().Infof("Derived rotated recipient key from did_rotate kid: %s", derived)
									_ = connectionSvc.UpdateConnection(rec)
								}
							}
						}
					}
				}
			}
		}
	}
	// Resolve responder DID to update endpoint + recipient key for post-handshake
	if rec.TheirDid != "" && ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenDidCommDocumentService); err == nil {
			if dcs, ok := dep.(*envelopeServices.DidCommDocumentService); ok && dcs != nil {
				if ep, keys, routing, rerr := dcs.ResolveService(ctx.AgentContext, ctx.TypedDI, rec.TheirDid); rerr == nil {
					rec.TheirEndpoint = ep
					if len(keys) > 0 {
						rec.TheirRecipientKey = keys[0]
					}
					rec.RoutingKeys = routing
					_ = connectionSvc.UpdateConnection(rec)
					logger.GetDefaultLogger().Infof("Responder DID resolved for post-handshake: endpoint=%s key=%s", rec.TheirEndpoint, rec.TheirRecipientKey)
				}
			}
		}
	}
	// Optionally enrich from OOB for follow-up send (complete)
	var oobRec *oob.OutOfBandRecord
	if repo := getOobRepository(ctx.AgentContext); repo != nil {
		pthid := resp.GetParentThreadId()
		if pthid == "" && rec != nil {
			pthid = rec.OutOfBandId
		}
		if pthid != "" {
			oobRec = repo.FindByInvitationThreadId(ctx.AgentContext, pthid)
			if oobRec != nil && rec != nil {
				if inv, ok := oobRec.OutOfBandInvitation.(*oobmsgs.OutOfBandInvitationMessage); ok {
					svcs := inv.GetServices()
					if len(svcs) > 0 {
						svc := svcs[0]
						if rec.TheirEndpoint == "" {
							if endpoint, ok := svc.ServiceEndpoint.(string); ok {
								rec.TheirEndpoint = endpoint
							}
						}
						if rec.InvitationKey == "" && len(svc.RecipientKeys) > 0 {
							rec.InvitationKey = svc.RecipientKeys[0]
						}
					}
				}
				_ = connectionSvc.UpdateConnection(rec)
			}
		}
	}
	// Create complete
	complete, err := protocol.CreateComplete(ctx.AgentContext, rec, nil)
	if err != nil {
		return nil, err
	}
	// Thread pthid to OOB invitation id to aid TS correlation
	// Prefer explicit invitationId, fallback to threadId tag, then the pthid from the original request
	if oobRec != nil && oobRec.Tags != nil {
		if invId, ok := oobRec.Tags["invitationId"]; ok && invId != "" {
			complete.SetParentThreadId(invId)
		} else if th, ok := oobRec.Tags["threadId"]; ok && th != "" {
			complete.SetParentThreadId(th)
		}
	}
	// If still not set, fallback to the parent thread id of the request we received
	if complete.GetParentThreadId() == "" {
		if p := resp.GetParentThreadId(); p != "" {
			complete.SetParentThreadId(p)
		} else if rec != nil && rec.OutOfBandId != "" {
			// As a last resort, use stored OutOfBandId if it contains the invitation id
			complete.SetParentThreadId(rec.OutOfBandId)
		}
	}
	// Provide inbound context to enable session return-routing for the Complete message
	inboundForOutbound := &models.InboundMessageContext{
		Message:      &resp,
		Raw:          ctx.Raw,
		Connection:   rec,
		SessionID:    ctx.SessionID,
		ReceivedAt:   ctx.ReceivedAt,
		SenderKey:    ctx.SenderKey,
		RecipientKey: ctx.RecipientKey,
		AgentContext: ctx.AgentContext,
		TypedDI:      ctx.TypedDI,
	}
	outboundCtx := models.NewOutboundMessageContext(complete, models.OutboundMessageContextParams{
		AgentContext:          ctx.AgentContext,
		Connection:            rec,
		AssociatedRecord:      rec,
		InboundMessageContext: inboundForOutbound,
		OutOfBand:             oobRec,
	})
	// Debug threading for complete
	logger.GetDefaultLogger().Debugf("Complete threading: thid=%s pthid=%s", complete.GetThreadId(), complete.GetParentThreadId())
	// Persist state transition to complete and emit event before sending complete
	if err := connectionSvc.UpdateConnectionState(rec.ID, services.ConnectionStateComplete); err == nil {
		if bus := getEventBus(ctx); bus != nil {
			bus.Publish(coreevents.EventConnectionStateChanged, map[string]interface{}{
				"connectionId": rec.ID,
				"state":        string(services.ConnectionStateComplete),
			})
		}
	}
	// Attach OOB to outbound context so sender can use inline service when needed
	outboundCtx.OutOfBand = oobRec
	// Update OOB state for receiver role: PrepareResponse -> Done when sending complete
	if oobRec != nil {
		// Receiver side should move to Done after we respond with complete
		if oobRec.Role == oob.OutOfBandRoleReceiver && oobRec.State == oob.OutOfBandStatePrepareResponse {
			oobRec.State = oob.OutOfBandStateDone
			if repo := getOobRepository(ctx.AgentContext); repo != nil {
				_ = repo.Update(ctx.AgentContext, oobRec)
			}
			if bus := getEventBus(ctx); bus != nil {
				bus.Publish(oob.OutOfBandEventStateChanged, map[string]interface{}{
					"outOfBandRecord": oobRec,
					"previousState":   oob.OutOfBandStatePrepareResponse,
					"state":           oob.OutOfBandStateDone,
				})
			}
		}
	}
	return outboundCtx, nil
}

func DidExchangeCompleteHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	logger.GetDefaultLogger().Info("🤝 (dispatcher) processing didexchange/1.1/complete")
	protocol := getDidExchangeProtocol(ctx)
	if protocol == nil {
		return nil, fmt.Errorf("did exchange protocol not configured")
	}
	var complete services.DidExchangeCompleteMessage
	if err := json.Unmarshal(ctx.Raw, &complete); err != nil {
		return nil, fmt.Errorf("failed to parse didexchange complete: %w", err)
	}
	// Find connection by thread id
	connectionSvc := getConnectionService(ctx)
	if connectionSvc == nil {
		return nil, fmt.Errorf("connection service not configured")
	}
	var rec *services.ConnectionRecord
	if conns, err := connectionSvc.GetAllConnections(); err == nil {
		for _, c := range conns {
			if c != nil && c.Tags != nil && c.Tags["threadId"] == complete.GetThreadId() {
				rec = c
				break
			}
		}
	}
	if rec == nil {
		return nil, fmt.Errorf("connection for thread not found")
	}
	if err := protocol.ProcessComplete(ctx.AgentContext, &complete, rec); err != nil {
		return nil, err
	}
	// Persist state and publish event
	connectionSvc.UpdateConnectionState(rec.ID, services.ConnectionStateComplete)
	// Update OOB record state for sender role on receiving complete
	if repo := getOobRepository(ctx.AgentContext); repo != nil {
		pthid := complete.GetParentThreadId()
		if pthid == "" && rec != nil {
			pthid = rec.OutOfBandId
		}
		if pthid != "" {
			if r := repo.FindByInvitationThreadId(ctx.AgentContext, pthid); r != nil {
				if r.Role == oob.OutOfBandRoleSender {
					// Non-reusable: Done; Reusable: stay in await-response
					if !r.ReusableConnection && r.State != oob.OutOfBandStateDone {
						prev := r.State
						r.State = oob.OutOfBandStateDone
						_ = repo.Update(ctx.AgentContext, r)
						if bus := getEventBus(ctx); bus != nil {
							bus.Publish(oob.OutOfBandEventStateChanged, map[string]interface{}{
								"outOfBandRecord": r,
								"previousState":   prev,
								"state":           r.State,
							})
						}
					}
				}
			}
		}
	}
	if bus := getEventBus(ctx); bus != nil {
		bus.Publish(coreevents.EventConnectionStateChanged, map[string]interface{}{
			"connectionId": rec.ID,
			"state":        string(services.ConnectionStateComplete),
		})
	}
	return nil, nil
}
