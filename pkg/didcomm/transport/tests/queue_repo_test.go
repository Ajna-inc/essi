package transport_test

import (
	"testing"
	"time"

	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

func TestQueueRepository_BasicOps(t *testing.T) {
	repo := transport.GetGlobalQueueRepository()
	repo.Clear()

	if msgs := repo.GetAll(); len(msgs) != 0 {
		t.Fatalf("expected empty queue, got %d", len(msgs))
	}

	m1 := &transport.QueuedMessage{ConnectionId: "c1", RecipientDids: []string{"did:peer:abc"}, Payload: &envelopeServices.EncryptedMessage{Ciphertext: "one"}, CreatedAt: time.Now()}
	m2 := &transport.QueuedMessage{ConnectionId: "c2", RecipientDids: []string{"did:key:xyz"}, Payload: &envelopeServices.EncryptedMessage{Ciphertext: "two"}, CreatedAt: time.Now()}
	m3 := &transport.QueuedMessage{ConnectionId: "c1", RecipientDids: []string{"did:peer:def"}, Payload: &envelopeServices.EncryptedMessage{Ciphertext: "three"}, CreatedAt: time.Now()}

	repo.Add(m1)
	repo.Add(m2)
	repo.Add(m3)

	if all := repo.GetAll(); len(all) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(all))
	}
	if c1 := repo.GetByConnection("c1"); len(c1) != 2 {
		t.Fatalf("expected 2 messages for c1, got %d", len(c1))
	}
	repo.Clear()
	if all := repo.GetAll(); len(all) != 0 {
		t.Fatalf("expected empty after clear, got %d", len(all))
	}
}
