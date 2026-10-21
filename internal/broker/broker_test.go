package broker

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestDeliveryJobAckNack(t *testing.T) {
	acked := false
	nacked := false
	requeued := false

	job := DeliveryJob{
		Msg: DeliveryMessage{DeliveryID: "dlv_1"},
		ack: func() error {
			acked = true
			return nil
		},
		nak: func(rq bool) error {
			nacked = true
			requeued = rq
			return nil
		},
	}

	if err := job.Ack(); err != nil || !acked {
		t.Fatalf("expected job.Ack() to succeed and set acked=true, err=%v", err)
	}

	if err := job.Nack(true); err != nil || !nacked || !requeued {
		t.Fatalf("expected job.Nack(true) to succeed, err=%v", err)
	}
}

func TestLiveRabbitMQClient(t *testing.T) {
	client, err := New("amqp://guest:guest@localhost:5673/")
	if err != nil {
		t.Skipf("skipping live rabbitmq test: %v", err)
		return
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msg := DeliveryMessage{
		DeliveryID: "00000000-0000-0000-0000-000000000001",
		AccountID:  "00000000-0000-0000-0000-000000000002",
		DomainID:   "00000000-0000-0000-0000-000000000003",
		DomainName: "test.example.com",
		EmailID:    "00000000-0000-0000-0000-000000000004",
		Recipient:  "user@remote.com",
		Priority:   0,
		Attempts:   1,
		Raw:        []byte("From: test\r\n\r\nHello"),
		CreatedAt:  time.Now(),
	}

	if err := client.Publish(ctx, msg); err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Publish bulk message (priority > 0)
	bulkMsg := msg
	bulkMsg.Priority = 1
	bulkMsg.DeliveryID = "00000000-0000-0000-0000-000000000005"
	if err := client.Publish(ctx, bulkMsg); err != nil {
		t.Fatalf("Publish bulk failed: %v", err)
	}

	// Empty batch should be a no-op
	if err := client.PublishBatch(ctx, nil); err != nil {
		t.Fatalf("PublishBatch empty failed: %v", err)
	}

	batch := []DeliveryMessage{msg, bulkMsg}
	if err := client.PublishBatch(ctx, batch); err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}

	// Test consuming from RabbitMQ
	jobs, err := client.Consume(ctx, QueueTransactional, 10)
	if err != nil {
		t.Fatalf("Consume failed: %v", err)
	}

	select {
	case job, ok := <-jobs:
		if !ok {
			t.Fatal("jobs channel closed unexpectedly")
		}
		if err := job.Ack(); err != nil {
			t.Errorf("job.Ack() failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Log("no message received within timeout")
	}

	// Double close should be idempotent
	if err := client.Close(); err != nil {
		t.Errorf("first Close() failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
}

func TestRabbitMQInvalidURL(t *testing.T) {
	_, err := New("amqp://invalid-host:99999/")
	if err == nil {
		t.Error("expected error for invalid amqp URL")
	}
}

func TestRedisStreamClient(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6380",
	})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("skipping redis stream tests, redis ping failed: %v", err)
		return
	}

	streamClient := NewRedisStream(rdb)

	msg := DeliveryMessage{
		DeliveryID: "00000000-0000-0000-0000-000000000010",
		AccountID:  "00000000-0000-0000-0000-000000000011",
		DomainID:   "00000000-0000-0000-0000-000000000012",
		DomainName: "redis.example.com",
		EmailID:    "00000000-0000-0000-0000-000000000013",
		Recipient:  "redis-user@remote.com",
		Priority:   0,
		Attempts:   1,
		Raw:        []byte("Redis Stream Message"),
		CreatedAt:  time.Now(),
	}

	// Test Publish transactional & bulk
	if err := streamClient.Publish(ctx, msg); err != nil {
		t.Fatalf("streamClient.Publish transactional failed: %v", err)
	}
	bulkMsg := msg
	bulkMsg.Priority = 1
	bulkMsg.DeliveryID = "00000000-0000-0000-0000-000000000014"
	if err := streamClient.Publish(ctx, bulkMsg); err != nil {
		t.Fatalf("streamClient.Publish bulk failed: %v", err)
	}

	// Test PublishBatch empty and multi
	if err := streamClient.PublishBatch(ctx, nil); err != nil {
		t.Fatalf("streamClient.PublishBatch empty failed: %v", err)
	}
	if err := streamClient.PublishBatch(ctx, []DeliveryMessage{msg, bulkMsg}); err != nil {
		t.Fatalf("streamClient.PublishBatch failed: %v", err)
	}

	// Test Consume
	consumeCtx, consumeCancel := context.WithCancel(ctx)
	jobs, err := streamClient.Consume(consumeCtx, StreamTransactional, 5)
	if err != nil {
		t.Fatalf("streamClient.Consume failed: %v", err)
	}

	select {
	case job, ok := <-jobs:
		if ok {
			if err := job.Ack(); err != nil {
				t.Errorf("job.Ack() failed: %v", err)
			}
		}
	case <-time.After(2 * time.Second):
		t.Log("consume timeout")
	}

	// Also test consuming and Nack with requeue=false (moves to DLQ)
	select {
	case job, ok := <-jobs:
		if ok {
			if err := job.Nack(false); err != nil {
				t.Errorf("job.Nack(false) failed: %v", err)
			}
		}
	case <-time.After(1 * time.Second):
	}

	consumeCancel()

	// Test stream mapping QueueTransactional and QueueBulk
	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	jobsBulk, err := streamClient.Consume(ctx2, QueueBulk, 1)
	if err != nil {
		t.Fatalf("Consume with QueueBulk failed: %v", err)
	}
	jobsTx, err := streamClient.Consume(ctx2, QueueTransactional, 1)
	if err != nil {
		t.Fatalf("Consume with QueueTransactional failed: %v", err)
	}
	_ = jobsBulk
	_ = jobsTx

	// Malformed payload in Redis stream to trigger unmarshal error path
	_ = rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: StreamTransactional,
		Values: map[string]any{"data": "not-valid-json"},
	}).Err()
	// Non-string data payload to trigger bad value path
	_ = rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: StreamTransactional,
		Values: map[string]any{"data": 12345},
	}).Err()
}

func TestRabbitMQChannelEdgeCases(t *testing.T) {
	client, err := New("amqp://guest:guest@localhost:5673/")
	if err != nil {
		t.Skipf("skipping: %v", err)
		return
	}
	defer client.Close()

	// releaseChannel with nil
	client.releaseChannel(nil)

	// acquireChannel and release
	ch, err := client.acquireChannel(context.Background())
	if err != nil {
		t.Fatalf("acquireChannel failed: %v", err)
	}
	client.releaseChannel(ch)

	// releaseChannel with closed channel
	closedCh, err := client.conn.Channel()
	if err == nil {
		_ = closedCh.Close()
		client.releaseChannel(closedCh)
	}
}



