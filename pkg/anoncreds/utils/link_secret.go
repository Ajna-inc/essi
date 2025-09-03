package utils

import (
	"fmt"
	"log"
	
	"github.com/google/uuid"
	"github.com/ajna-inc/essi/pkg/anoncreds/repository"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	agentcontext "github.com/ajna-inc/essi/pkg/core/context"
)

// StoreLinkSecretOptions contains options for storing a link secret
type StoreLinkSecretOptions struct {
	LinkSecretId    string
	LinkSecretValue string
	SetAsDefault    bool
}

// StoreLinkSecret stores a link secret and optionally sets it as default
func StoreLinkSecret(ctx *context.AgentContext, options StoreLinkSecretOptions) (*repository.LinkSecretRecord, error) {
	var linkSecretRepo repository.LinkSecretRepository
	if dm, ok := ctx.DependencyManager.(di.DependencyManager); ok {
		if dep, err := dm.Resolve(di.TokenLinkSecretRepository); err == nil {
			linkSecretRepo, _ = dep.(repository.LinkSecretRepository)
		}
	}
	if linkSecretRepo == nil {
		return nil, fmt.Errorf("link secret repository not available")
	}
	
	linkSecretId := options.LinkSecretId
	if linkSecretId == "" {
		linkSecretId = uuid.New().String()
	}
	
	record := repository.NewLinkSecretRecord(uuid.New().String(), linkSecretId)
	record.Value = options.LinkSecretValue
	
	// Check if this should be the default
	defaultRecord, _ := linkSecretRepo.FindDefault(ctx)
	if defaultRecord == nil || options.SetAsDefault {
		record.SetAsDefault(true)
		log.Printf("Setting link secret %s as default", linkSecretId)
	}
	
	// If setting as default and there's an existing default, unset it
	if defaultRecord != nil && options.SetAsDefault && defaultRecord.LinkSecretId != linkSecretId {
		defaultRecord.SetAsDefault(false)
		if err := linkSecretRepo.Update(ctx, defaultRecord); err != nil {
			log.Printf("Warning: Failed to unset previous default link secret: %v", err)
		}
	}
	
	// Save the new record
	if err := linkSecretRepo.Save(ctx, record); err != nil {
		return nil, fmt.Errorf("failed to save link secret: %w", err)
	}
	
	log.Printf("✅ Stored link secret %s (default: %v)", linkSecretId, record.IsDefault)
	return record, nil
}

// GetLinkSecret retrieves a link secret by ID
func GetLinkSecret(ctx *context.AgentContext, linkSecretId string) (string, error) {
	var linkSecretRepo repository.LinkSecretRepository
	if dm, ok := ctx.DependencyManager.(di.DependencyManager); ok {
		if dep, err := dm.Resolve(di.TokenLinkSecretRepository); err == nil {
			linkSecretRepo, _ = dep.(repository.LinkSecretRepository)
		}
	}
	if linkSecretRepo == nil {
		return "", fmt.Errorf("link secret repository not available")
	}
	
	record, err := linkSecretRepo.GetByLinkSecretId(ctx, linkSecretId)
	if err != nil {
		return "", fmt.Errorf("failed to get link secret %s: %w", linkSecretId, err)
	}
	
	if record.Value == "" {
		return "", fmt.Errorf("link secret value not stored for %s", linkSecretId)
	}
	
	return record.Value, nil
}

// GetDefaultLinkSecret retrieves the default link secret
func GetDefaultLinkSecret(ctx *context.AgentContext) (string, string, error) {
	var linkSecretRepo repository.LinkSecretRepository
	if dm, ok := ctx.DependencyManager.(di.DependencyManager); ok {
		if dep, err := dm.Resolve(di.TokenLinkSecretRepository); err == nil {
			linkSecretRepo, _ = dep.(repository.LinkSecretRepository)
		}
	}
	if linkSecretRepo == nil {
		return "", "", fmt.Errorf("link secret repository not available")
	}
	
	record, err := linkSecretRepo.GetDefault(ctx)
	if err != nil {
		return "", "", fmt.Errorf("no default link secret found: %w", err)
	}
	
	if record.Value == "" {
		return "", "", fmt.Errorf("default link secret value not stored")
	}
	
	return record.LinkSecretId, record.Value, nil
}

// GetOrCreateDefaultLinkSecret ensures a default link secret exists using typed DI only
func GetOrCreateDefaultLinkSecret(ctx *agentcontext.AgentContext, dm di.DependencyManager) (string, error) {
	repo := ResolveLinkSecretRepo(dm)
	if repo == nil { return "", nil }
	if rec, err := repo.FindDefault(ctx); err == nil && rec != nil && rec.Value != "" { return rec.Value, nil }
	return "", nil
}

// AssertLinkSecretsMatch verifies all link secrets in a list are the same
func AssertLinkSecretsMatch(linkSecretIds []string) (string, error) {
	if len(linkSecretIds) == 0 {
		return "", fmt.Errorf("no link secret IDs provided")
	}
	
	firstId := linkSecretIds[0]
	for _, id := range linkSecretIds {
		if id != firstId {
			return "", fmt.Errorf("all credentials in a proof must use the same link secret")
		}
	}
	
	return firstId, nil
}

// ResolveLinkSecretRepo resolves the link secret repository via typed DI
func ResolveLinkSecretRepo(dm di.DependencyManager) repository.LinkSecretRepository {
	if dm == nil { return nil }
	if any, err := dm.Resolve(di.TokenLinkSecretRepository); err == nil {
		if repo, ok := any.(repository.LinkSecretRepository); ok { return repo }
	}
	return nil
}