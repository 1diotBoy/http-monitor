package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"kyanos-lite/internal/model"
)

type RedisStore struct {
	client           *redis.Client
	listKey          string
	maxItems         int64
	failLogPath      string
	failLogFile      *os.File
	redisWorkers     int
	redisQueueSize   int
	redisBatchSize   int
	redisFlushEvery  time.Duration
	queue            chan model.FlowRecord
	closeOnce        sync.Once
	wg               sync.WaitGroup
	closed           atomic.Bool
	mu               sync.Mutex
	lastErr          string
	droppedReq       uint64
	droppedResp      uint64
	droppedQueueReq  uint64
	droppedQueueResp uint64
}

func NewRedisStore(addr, password string, db int, listKey string, maxItems int64, failLogPath string, workers, queueSize, batchSize int, flushInterval time.Duration) (*RedisStore, error) {
	if addr == "" || listKey == "" {
		return nil, nil
	}
	if workers <= 0 {
		workers = 1
	}
	if queueSize <= 0 {
		queueSize = 65536
	}
	if batchSize <= 0 {
		batchSize = 128
	}
	if flushInterval <= 0 {
		flushInterval = 20 * time.Millisecond
	}
	s := &RedisStore{
		listKey:         listKey,
		maxItems:        maxItems,
		failLogPath:     failLogPath,
		redisWorkers:    workers,
		redisQueueSize:  queueSize,
		redisBatchSize:  batchSize,
		redisFlushEvery: flushInterval,
		queue:           make(chan model.FlowRecord, queueSize),
	}
	c := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		s.lastErr = err.Error()
		s.logDropped("connect redis failed")
		return s, nil
	}
	s.client = c
	s.startWorkers()
	return s, nil
}

// SaveFlow is intentionally lightweight. It only enqueues the record so packet
// workers do not block on per-flow Redis round-trips under load.
func (s *RedisStore) SaveFlow(flow model.FlowRecord) error {
	if s == nil {
		return nil
	}
	if s.client == nil {
		s.recordDropped(flow.Kind, fmt.Errorf("%s", s.lastErr))
		return nil
	}
	if s.closed.Load() {
		err := fmt.Errorf("redis store closed")
		s.recordDropped(flow.Kind, err)
		return err
	}
	select {
	case s.queue <- flow:
		return nil
	default:
		err := fmt.Errorf("redis queue full")
		s.recordQueueDrop(flow.Kind, err)
		return err
	}
}

func (s *RedisStore) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.queue != nil {
			close(s.queue)
		}
		s.wg.Wait()
		s.mu.Lock()
		if s.failLogFile != nil {
			_ = s.failLogFile.Close()
			s.failLogFile = nil
		}
		s.mu.Unlock()
		if s.client != nil {
			_ = s.client.Close()
		}
	})
	return nil
}

func (s *RedisStore) startWorkers() {
	for i := 0; i < s.redisWorkers; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runWorker()
		}()
	}
}

func (s *RedisStore) runWorker() {
	timer := time.NewTimer(s.redisFlushEvery)
	defer timer.Stop()

	batch := make([]model.FlowRecord, 0, s.redisBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.flushBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case flow, ok := <-s.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, flow)
			if len(batch) >= s.redisBatchSize {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(s.redisFlushEvery)
			}
		case <-timer.C:
			flush()
			timer.Reset(s.redisFlushEvery)
		}
	}
}

func (s *RedisStore) flushBatch(batch []model.FlowRecord) {
	if len(batch) == 0 || s.client == nil {
		return
	}
	vals := make([]interface{}, 0, len(batch))
	var reqs, resps uint64
	for _, flow := range batch {
		b, err := json.Marshal(flow)
		if err != nil {
			s.recordDropped(flow.Kind, err)
			continue
		}
		vals = append(vals, string(b))
		switch flow.Kind {
		case "request":
			reqs++
		case "response":
			resps++
		}
	}
	if len(vals) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pipe := s.client.TxPipeline()
	pipe.LPush(ctx, s.listKey, vals...)
	if s.maxItems > 0 {
		pipe.LTrim(ctx, s.listKey, 0, s.maxItems-1)
	}
	pipe.Expire(ctx, s.listKey, 7*24*time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		s.recordDroppedBatch(reqs, resps, err)
	}
}

func (s *RedisStore) recordQueueDrop(kind string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr = err.Error()
	}
	switch kind {
	case "request":
		s.droppedReq++
		s.droppedQueueReq++
	case "response":
		s.droppedResp++
		s.droppedQueueResp++
	}
	s.logDropped("redis enqueue failed")
}

func (s *RedisStore) recordDropped(kind string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr = err.Error()
	}
	switch kind {
	case "request":
		s.droppedReq++
	case "response":
		s.droppedResp++
	}
	s.logDropped("redis save failed")
}

func (s *RedisStore) recordDroppedBatch(reqs, resps uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr = err.Error()
	}
	s.droppedReq += reqs
	s.droppedResp += resps
	s.logDropped("redis batch save failed")
}

func (s *RedisStore) logDropped(prefix string) {
	f, err := s.ensureFailLogFile()
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(
		f,
		"%s %s request_dropped=%d response_dropped=%d queue_request_dropped=%d queue_response_dropped=%d last_error=%s\n",
		time.Now().Format(time.RFC3339Nano),
		prefix,
		s.droppedReq,
		s.droppedResp,
		s.droppedQueueReq,
		s.droppedQueueResp,
		s.lastErr,
	)
}

func (s *RedisStore) ensureFailLogFile() (*os.File, error) {
	if s.failLogPath == "" {
		s.failLogPath = "kyanos-redis-failures.log"
	}
	if s.failLogFile != nil {
		return s.failLogFile, nil
	}
	f, err := os.OpenFile(s.failLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	s.failLogFile = f
	return f, nil
}
