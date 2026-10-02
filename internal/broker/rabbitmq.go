// Package broker provides optional delivery queue transports.
package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	ExchangeName       = "mailhost.direct"
	DLXName            = "mailhost.dlx"
	QueueTransactional = "mailhost.deliveries.transactional"
	QueueBulk          = "mailhost.deliveries.bulk"
	QueueDLQ           = "mailhost.deliveries.dlq"

	RoutingTransactional = "delivery.transactional"
	RoutingBulk          = "delivery.bulk"
	RoutingDLQ           = "delivery.dead"
)

// DeliveryMessage is the queue payload consumed by delivery workers.
type DeliveryMessage struct {
	DeliveryID string    `json:"delivery_id"`
	AccountID  string    `json:"account_id"`
	DomainID   string    `json:"domain_id"`
	DomainName string    `json:"domain_name"`
	EmailID    string    `json:"email_id"`
	Recipient  string    `json:"recipient"`
	Priority   int16     `json:"priority"` // 0 = transactional, 1 = bulk
	Attempts   int       `json:"attempts"`
	Raw        []byte    `json:"raw"`
	CreatedAt  time.Time `json:"created_at"`
}

// DeliveryJob wraps a delivery message with acknowledgement operations.
type DeliveryJob struct {
	Msg DeliveryMessage
	ack func() error
	nak func(requeue bool) error
}

// Ack acknowledges successful processing of the delivery.
func (j *DeliveryJob) Ack() error { return j.ack() }

// Nack rejects the delivery and optionally asks the broker to requeue it.
func (j *DeliveryJob) Nack(requeue bool) error { return j.nak(requeue) }

// Client publishes and consumes delivery messages through RabbitMQ.
type Client struct {
	conn      *amqp.Connection
	url       string
	pubPool   chan *amqp.Channel
	closeOnce sync.Once
}

// New connects to RabbitMQ, declares durable exchanges, queues and dead-letter configurations,
// and pre-warms a high-throughput multiplexed channel pool for concurrent, lock-free publishing.
func New(url string) (*Client, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq dial: %w", err)
	}

	setupCh, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("rabbitmq setup channel: %w", err)
	}

	poolCap := max(32, runtime.GOMAXPROCS(0)*4)
	c := &Client{
		conn:    conn,
		url:     url,
		pubPool: make(chan *amqp.Channel, poolCap),
	}

	if err := c.setupTopology(setupCh); err != nil {
		setupCh.Close()
		conn.Close()
		return nil, err
	}
	c.pubPool <- setupCh

	return c, nil
}

func (c *Client) setupTopology(ch *amqp.Channel) error {
	// Declare main direct exchange and dead-letter exchange
	if err := ch.ExchangeDeclare(ExchangeName, "direct", true, false, false, false, nil); err != nil {
		return fmt.Errorf("declare exchange %s: %w", ExchangeName, err)
	}
	if err := ch.ExchangeDeclare(DLXName, "direct", true, false, false, false, nil); err != nil {
		return fmt.Errorf("declare exchange %s: %w", DLXName, err)
	}

	// Declare DLQ
	if _, err := ch.QueueDeclare(QueueDLQ, true, false, false, false, nil); err != nil {
		return fmt.Errorf("declare queue %s: %w", QueueDLQ, err)
	}
	if err := ch.QueueBind(QueueDLQ, RoutingDLQ, DLXName, false, nil); err != nil {
		return fmt.Errorf("bind dlq: %w", err)
	}

	// Common arguments with dead-letter exchange
	args := amqp.Table{
		"x-dead-letter-exchange":    DLXName,
		"x-dead-letter-routing-key": RoutingDLQ,
	}

	// Transactional delivery queue
	if _, err := ch.QueueDeclare(QueueTransactional, true, false, false, false, args); err != nil {
		return fmt.Errorf("declare queue %s: %w", QueueTransactional, err)
	}
	if err := ch.QueueBind(QueueTransactional, RoutingTransactional, ExchangeName, false, nil); err != nil {
		return fmt.Errorf("bind queue %s: %w", QueueTransactional, err)
	}

	// Bulk delivery queue
	if _, err := ch.QueueDeclare(QueueBulk, true, false, false, false, args); err != nil {
		return fmt.Errorf("declare queue %s: %w", QueueBulk, err)
	}
	if err := ch.QueueBind(QueueBulk, RoutingBulk, ExchangeName, false, nil); err != nil {
		return fmt.Errorf("bind queue %s: %w", QueueBulk, err)
	}

	return nil
}

func (c *Client) acquireChannel(ctx context.Context) (*amqp.Channel, error) {
	select {
	case ch := <-c.pubPool:
		if !ch.IsClosed() {
			return ch, nil
		}
		return c.conn.Channel()
	default:
		return c.conn.Channel()
	}
}

func (c *Client) releaseChannel(ch *amqp.Channel) {
	if ch == nil || ch.IsClosed() {
		return
	}
	select {
	case c.pubPool <- ch:
	default:
		_ = ch.Close()
	}
}

// Publish enqueues a delivery message into RabbitMQ using a pooled channel with zero lock contention.
func (c *Client) Publish(ctx context.Context, msg DeliveryMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	routingKey := RoutingTransactional
	if msg.Priority > 0 {
		routingKey = RoutingBulk
	}

	ch, err := c.acquireChannel(ctx)
	if err != nil {
		return err
	}
	defer c.releaseChannel(ch)

	return ch.PublishWithContext(ctx,
		ExchangeName,
		routingKey,
		false, // mandatory
		false, // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "application/json",
			MessageId:    msg.DeliveryID,
			Timestamp:    msg.CreatedAt,
			Body:         body,
		},
	)
}

// PublishBatch stream-publishes a batch of delivery messages over an acquired channel in a single pass.
func (c *Client) PublishBatch(ctx context.Context, msgs []DeliveryMessage) error {
	if len(msgs) == 0 {
		return nil
	}
	ch, err := c.acquireChannel(ctx)
	if err != nil {
		return err
	}
	defer c.releaseChannel(ch)

	for _, msg := range msgs {
		body, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		routingKey := RoutingTransactional
		if msg.Priority > 0 {
			routingKey = RoutingBulk
		}
		err = ch.PublishWithContext(ctx,
			ExchangeName,
			routingKey,
			false,
			false,
			amqp.Publishing{
				DeliveryMode: amqp.Persistent,
				ContentType:  "application/json",
				MessageId:    msg.DeliveryID,
				Timestamp:    msg.CreatedAt,
				Body:         body,
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// Consume starts consuming delivery jobs from RabbitMQ in real-time.
func (c *Client) Consume(ctx context.Context, queueName string, prefetch int) (<-chan DeliveryJob, error) {
	ch, err := c.conn.Channel()
	if err != nil {
		return nil, err
	}
	if err := ch.Qos(prefetch, 0, false); err != nil {
		ch.Close()
		return nil, err
	}
	deliveries, err := ch.ConsumeWithContext(ctx,
		queueName,
		"",    // consumer tag (auto)
		false, // autoAck (false = manual ack for delivery guarantees)
		false, // exclusive
		false, // noLocal
		false, // noWait
		nil,   // args
	)
	if err != nil {
		ch.Close()
		return nil, err
	}

	out := make(chan DeliveryJob, prefetch)
	go func() {
		defer ch.Close()
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case d, ok := <-deliveries:
				if !ok {
					return
				}
				var msg DeliveryMessage
				if err := json.Unmarshal(d.Body, &msg); err != nil {
					_ = d.Nack(false, false) // send malformed payload directly to DLQ
					continue
				}
				job := DeliveryJob{
					Msg: msg,
					ack: func() error { return d.Ack(false) },
					nak: func(requeue bool) error { return d.Nack(false, requeue) },
				}
				select {
				case <-ctx.Done():
					_ = d.Nack(false, true) // requeue if shutting down
					return
				case out <- job:
				}
			}
		}
	}()

	return out, nil
}

// Close closes pooled channels and connection cleanly.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		for {
			select {
			case ch := <-c.pubPool:
				_ = ch.Close()
			default:
				goto drained
			}
		}
	drained:
		if c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}
