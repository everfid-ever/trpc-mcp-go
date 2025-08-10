package store

import (
	"context"
	"fmt"
	"time"
)

type CleanupScheduler struct {
	store    ClientStore
	interval time.Duration
	quit     chan struct{}
}

func NewCleanupScheduler(store ClientStore, interval time.Duration) *CleanupScheduler {
	return &CleanupScheduler{
		store:    store,
		interval: interval,
		quit:     make(chan struct{}),
	}
}
func (s *CleanupScheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.quit:
			return
		case <-ticker.C:
			count, err := s.store.CleanupExpired(ctx)
			if err != nil {
				fmt.Printf("Cleanup error: %v\n", err)
			} else if count > 0 {
				fmt.Printf("Cleaned up %d expired clients\n", count)
			}
		}
	}
}
func (s *CleanupScheduler) Stop() { close(s.quit) }
