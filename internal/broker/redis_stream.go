package broker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	StreamTransactional = "mailhost:stream:deliveries:transactional"
	StreamBulk          = "mailhost:stream:deliveries:bulk"
	StreamDLQ           = "mailhost:stream:deliveries:dlq"
	ConsumerGroup       = "mailhost:delivery-workers"
)

// RedisStreamClient implements high-throughput distributed queuing via Redis Streams (BullMQ/Kafka pattern).
type RedisStreamClient struct {
	rdb *redis.Client
}

// NewRedisStream initializes a Redis Stream queue broker and ensures consumer groups exist.
func NewRedisStream(rdb *redis.Client) *RedisStreamClient {
	c := &RedisStreamClient{rdb: rdb}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, stream := range []string{StreamTransactional, StreamBulk, StreamDLQ} {
		_ = c.rdb.XGroupCreateMkStream(ctx, stream, ConsumerGroup, "$").Err()
	}
	return c
}

// Publish enqueues a delivery message into Redis Streams with automatic stream capping.
func (c *RedisStreamClient) Publish(ctx context.Context, msg DeliveryMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	stream := StreamTransactional
	if msg.Priority > 0 {
		stream = StreamBulk
	}

	return c.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: stream,
		MaxLen: 1_000_000,
		Approx: true,
		Values: map[string]any{
			"id":   msg.DeliveryID,
			"data": data,
		},
	}).Err()
}

// PublishBatch stream-publishes a batch of delivery messages using Redis pipelining for maximum speed.
func (c *RedisStreamClient) PublishBatch(ctx context.Context, msgs []DeliveryMessage) error {
	if len(msgs) == 0 {
		return nil
	}
	pipe := c.rdb.Pipeline()
	for _, msg := range msgs {
		data, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		stream := StreamTransactional
		if msg.Priority > 0 {
			stream = StreamBulk
		}
		pipe.XAdd(ctx, &redis.XAddArgs{
			Stream: stream,
			MaxLen: 1_000_000,
			Approx: true,
			Values: map[string]any{
				"id":   msg.DeliveryID,
				"data": data,
			},
		})
	}
	_, err := pipe.Exec(ctx)
	return err
}

// Consume starts a streaming worker consuming delivery jobs from a Redis Stream with consumer group semantics.
func (c *RedisStreamClient) Consume(ctx context.Context, stream string, prefetch int) (<-chan DeliveryJob, error) {
	if stream == QueueTransactional {
		stream = StreamTransactional
	} else if stream == QueueBulk {
		stream = StreamBulk
	}
	consumerID := "worker-" + uuid.New().String()[:8]
	out := make(chan DeliveryJob, prefetch)

	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			entries, err := c.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    ConsumerGroup,
				Consumer: consumerID,
				Streams:  []string{stream, ">"},
				Count:    int64(prefetch),
				Block:    2 * time.Second,
			}).Result()

			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return
				}
				if strings.Contains(err.Error(), "NOGROUP") {
					_ = c.rdb.XGroupCreateMkStream(ctx, stream, ConsumerGroup, "$").Err()
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}

			for _, streamEntry := range entries {
				for _, xmsg := range streamEntry.Messages {
					dataStr, ok := xmsg.Values["data"].(string)
					if !ok {
						_ = c.rdb.XAck(ctx, stream, ConsumerGroup, xmsg.ID)
						continue
					}
					var dmsg DeliveryMessage
					if err := json.Unmarshal([]byte(dataStr), &dmsg); err != nil {
						_ = c.rdb.XAck(ctx, stream, ConsumerGroup, xmsg.ID)
						continue
					}

					msgID := xmsg.ID
					job := DeliveryJob{
						Msg: dmsg,
						ack: func() error {
							return c.rdb.XAck(context.Background(), stream, ConsumerGroup, msgID).Err()
						},
						nak: func(requeue bool) error {
							if !requeue {
								// Move to dead letter queue
								_ = c.rdb.XAdd(context.Background(), &redis.XAddArgs{
									Stream: StreamDLQ,
									Values: map[string]any{"id": dmsg.DeliveryID, "data": dataStr},
								})
							}
							return c.rdb.XAck(context.Background(), stream, ConsumerGroup, msgID).Err()
						},
					}

					select {
					case <-ctx.Done():
						return
					case out <- job:
					}
				}
			}
		}
	}()

	return out, nil
}
