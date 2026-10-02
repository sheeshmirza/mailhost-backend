// Package docstore stores large email and inbound payloads outside PostgreSQL.
package docstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// EmailDocument represents an enterprise document model for emails in MongoDB.
// Storing MIME payloads and attachments in MongoDB eliminates PostgreSQL TOAST table bloat.
type EmailDocument struct {
	ID         string            `bson:"_id"`
	AccountID  string            `bson:"account_id"`
	DomainID   string            `bson:"domain_id"`
	BatchID    string            `bson:"batch_id,omitempty"`
	From       string            `bson:"from"`
	Recipients []string          `bson:"recipients"`
	Subject    string            `bson:"subject"`
	HTML       string            `bson:"html,omitempty"`
	Text       string            `bson:"text,omitempty"`
	Headers    map[string]string `bson:"headers,omitempty"`
	Raw        []byte            `bson:"raw,omitempty"`
	Size       int               `bson:"size"`
	CreatedAt  time.Time         `bson:"created_at"`
	ExpiresAt  time.Time         `bson:"expires_at,omitempty"`
}

// InboundDocument represents an enterprise document model for received inbound emails.
type InboundDocument struct {
	ID          string    `bson:"_id"`
	AccountID   string    `bson:"account_id"`
	DomainID    string    `bson:"domain_id"`
	MailFrom    string    `bson:"mail_from"`
	RcptTo      []string  `bson:"rcpt_to"`
	FromHeader  string    `bson:"from_header"`
	Subject     string    `bson:"subject"`
	MessageID   string    `bson:"message_id"`
	TextBody    string    `bson:"text_body"`
	HTMLBody    string    `bson:"html_body"`
	Attachments []any     `bson:"attachments"`
	Size        int       `bson:"size"`
	Raw         []byte    `bson:"raw"`
	CreatedAt   time.Time `bson:"created_at"`
}

// Client provides access to the configured MongoDB document collections.
type Client struct {
	client  *mongo.Client
	db      *mongo.Database
	emails  *mongo.Collection
	inbound *mongo.Collection
}

// New connects to MongoDB at the provided URI, sets pool limits, and creates TTL/query indexes.
func New(uri, database string) (*Client, error) {
	if uri == "" {
		return nil, errors.New("mongodb uri is required")
	}
	if database == "" {
		database = "mailhost"
	}

	opts := options.Client().
		ApplyURI(uri).
		SetMaxPoolSize(100).
		SetMinPoolSize(10).
		SetMaxConnIdleTime(5 * time.Minute).
		SetTimeout(5 * time.Second)

	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, fmt.Errorf("mongo connect: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("mongo ping: %w", err)
	}

	db := client.Database(database)
	emailsCol := db.Collection("emails")
	inboundCol := db.Collection("inbound_emails")

	c := &Client{
		client:  client,
		db:      db,
		emails:  emailsCol,
		inbound: inboundCol,
	}

	_ = c.ensureIndexes(ctx)
	return c, nil
}

func (c *Client) ensureIndexes(ctx context.Context) error {
	// 1. Emails: account_id + created_at compound index
	_, _ = c.emails.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "account_id", Value: 1},
			{Key: "created_at", Value: -1},
		},
	})

	// 2. Emails: automatic TTL expiration index on expires_at
	_, _ = c.emails.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})

	// 3. Inbound: account_id + created_at compound index
	_, _ = c.inbound.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "account_id", Value: 1},
			{Key: "created_at", Value: -1},
		},
	})
	return nil
}

func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.client == nil {
		return errors.New("mongodb client not initialized")
	}
	return c.client.Ping(ctx, nil)
}

func updateFields(doc any) (bson.M, error) {
	encoded, err := bson.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var fields bson.M
	if err := bson.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	delete(fields, "_id")
	return fields, nil
}

func saveDocument(ctx context.Context, collection *mongo.Collection, id string, doc any) error {
	fields, err := updateFields(doc)
	if err != nil {
		return err
	}
	_, err = collection.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": fields}, options.UpdateOne().SetUpsert(true))
	return err
}

func (c *Client) SaveEmail(ctx context.Context, doc EmailDocument) error {
	if c == nil || c.emails == nil {
		return errors.New("mongodb client not initialized")
	}
	return saveDocument(ctx, c.emails, doc.ID, doc)
}

func (c *Client) GetEmail(ctx context.Context, id string) (*EmailDocument, error) {
	if c == nil || c.emails == nil {
		return nil, errors.New("mongodb client not initialized")
	}
	var doc EmailDocument
	err := c.emails.FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

func (c *Client) SaveInbound(ctx context.Context, doc InboundDocument) error {
	if c == nil || c.inbound == nil {
		return errors.New("mongodb client not initialized")
	}
	return saveDocument(ctx, c.inbound, doc.ID, doc)
}

func (c *Client) GetInbound(ctx context.Context, id string) (*InboundDocument, error) {
	if c == nil || c.inbound == nil {
		return nil, errors.New("mongodb client not initialized")
	}
	var doc InboundDocument
	err := c.inbound.FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

func (c *Client) Close(ctx context.Context) error {
	if c != nil && c.client != nil {
		return c.client.Disconnect(ctx)
	}
	return nil
}
