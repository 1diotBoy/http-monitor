package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"kyanos-lite/internal/model"
)

type RedisStore struct {
	client   *redis.Client
	listKey  string
	maxItems int64
}

func NewRedisStore(addr, password string, db int, listKey string, maxItems int64) (*RedisStore, error) {
	if addr == "" || listKey == "" {
		return nil, nil
	}
	c := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	if maxItems <= 0 {
		maxItems = 2000
	}
	return &RedisStore{client: c, listKey: listKey, maxItems: maxItems}, nil
}

func (s *RedisStore) SaveFlow(flow model.FlowRecord) error {
	if s == nil || s.client == nil {
		return nil
	}
	b, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pipe := s.client.TxPipeline()
	pipe.LPush(ctx, s.listKey, string(b))
	pipe.LTrim(ctx, s.listKey, 0, s.maxItems-1)
	pipe.Expire(ctx, s.listKey, 7*24*time.Hour)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisStore) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}
