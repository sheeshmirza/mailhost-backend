package broker

import (
	"context"
	"testing"
	"time"
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
		DeliveryID: "dlv_test_123",
		AccountID:  "acct_test",
		DomainID:   "dom_test",
		DomainName: "test.example.com",
		EmailID:    "email_test",
		Recipient:  "user@remote.com",
		Priority:   0,
		Attempts:   1,
		Raw:        []byte("From: test\r\n\r\nHello"),
		CreatedAt:  time.Now(),
	}

	if err := client.Publish(ctx, msg); err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	batch := []DeliveryMessage{msg}
	if err := client.PublishBatch(ctx, batch); err != nil {
		t.Fatalf("PublishBatch failed: %v", err)
	}
}

