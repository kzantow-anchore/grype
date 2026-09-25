package v6

import (
	"fmt"

	"gorm.io/gorm"
)

type SearchRuleStoreReader interface {
	// GetSearchRules returns all search rules, or nil when the DB predates the table
	GetSearchRules() ([]SearchRule, error)
}

type searchRuleStore struct {
	db *gorm.DB
}

func newSearchRuleStore(db *gorm.DB) *searchRuleStore {
	return &searchRuleStore{db: db}
}

// GetSearchRules returns all search rules in no particular order. A DB built before the table existed
// returns nil, nil, and the caller falls back to KnownSearchRules.
func (s *searchRuleStore) GetSearchRules() ([]SearchRule, error) {
	if !s.db.Migrator().HasTable(&SearchRule{}) {
		return nil, nil
	}

	var rows []SearchRule
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("unable to read search rules: %w", err)
	}

	return rows, nil
}
