// Package rediscache provides optional Redis-backed caching and rate limiting.
package rediscache

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps the Redis operations used by Mailhost integrations.
type Client struct {
	rdb *redis.Client
}

// New connects to Redis at the provided URL (e.g. redis://user:pass@localhost:6379/0).
func New(url string) (*Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	rdb := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, err
	}
	return &Client{rdb: rdb}, nil
}

// Ping checks connectivity to the Redis server.
func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.rdb == nil {
		return errors.New("redis client not initialized")
	}
	return c.rdb.Ping(ctx).Err()
}

// Get retrieves a key, returning (value, true, nil) on hit, (nil, false, nil) on miss.
func (c *Client) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if c == nil || c.rdb == nil {
		return nil, false, errors.New("redis client not initialized")
	}
	val, err := c.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return val, true, nil
}

// Set stores a value with an expiration TTL.
func (c *Client) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	if c == nil || c.rdb == nil {
		return errors.New("redis client not initialized")
	}
	return c.rdb.Set(ctx, key, val, ttl).Err()
}

// Delete removes one or more keys immediately.
func (c *Client) Delete(ctx context.Context, keys ...string) error {
	if c == nil || c.rdb == nil || len(keys) == 0 {
		return nil
	}
	return c.rdb.Del(ctx, keys...).Err()
}

// AllowRate implements an atomic sliding window rate limit counter in Redis.
// Returns true if allowed, false if limit exceeded.
func (c *Client) AllowRate(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	if limit <= 0 || c == nil || c.rdb == nil {
		return true, nil
	}
	now := time.Now().UnixNano()
	windowStart := now - int64(window)

	pipe := c.rdb.TxPipeline()
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(windowStart, 10))
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
	countCmd := pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, window*2)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}
	return countCmd.Val() <= limit, nil
}

// RawClient returns the underlying *redis.Client.
func (c *Client) RawClient() *redis.Client {
	if c == nil {
		return nil
	}
	return c.rdb
}

// AddSuppression adds an email address to the account's Redis suppression set for O(1) checks.
func (c *Client) AddSuppression(ctx context.Context, accountID, address string) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.SAdd(ctx, "sups:"+accountID, strings.ToLower(strings.TrimSpace(address))).Err()
}

// RemoveSuppression removes an address from the account's Redis suppression set.
func (c *Client) RemoveSuppression(ctx context.Context, accountID, address string) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.SRem(ctx, "sups:"+accountID, strings.ToLower(strings.TrimSpace(address))).Err()
}

// Close closes the underlying connection pool.
func (c *Client) Close() error {
	if c != nil && c.rdb != nil {
		return c.rdb.Close()
	}
	return nil
}
