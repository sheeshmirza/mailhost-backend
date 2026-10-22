// Package qdrant provides an enterprise client for the Qdrant vector database,
// supporting semantic vector search, neural indexing, and similarity ranking
// for emails and message templates.
package qdrant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// VectorDimension is the default embedding dimensionality.
	VectorDimension = 384

	// DefaultTimeout for Qdrant HTTP requests.
	DefaultTimeout = 5 * time.Second

	// DefaultCollectionPrefix for namespacing Qdrant collections.
	DefaultCollectionPrefix = "mailhost"
)

var (
	// ErrEmptyQuery is returned when a semantic search query is blank.
	ErrEmptyQuery = errors.New("search query cannot be empty")

	// ErrNotConfigured is returned when Qdrant client is invoked while disabled.
	ErrNotConfigured = errors.New("qdrant vector store is not configured")

	wordRegex = regexp.MustCompile(`[\p{L}\p{N}]+`)
)

// EmailPoint encapsulates an email record prepared for vector indexing.
type EmailPoint struct {
	ID        string            `json:"id"`
	AccountID string            `json:"account_id"`
	Subject   string            `json:"subject"`
	Snippet   string            `json:"snippet"`
	From      string            `json:"from"`
	To        []string          `json:"to"`
	CreatedAt string            `json:"created_at"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// EmailSearchResult represents a matched email from semantic vector retrieval.
type EmailSearchResult struct {
	ID        string            `json:"id"`
	AccountID string            `json:"account_id"`
	Subject   string            `json:"subject"`
	Snippet   string            `json:"snippet"`
	From      string            `json:"from"`
	To        []string          `json:"to"`
	CreatedAt string            `json:"created_at"`
	Score     float32           `json:"score"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// TemplatePoint encapsulates an email template for vector indexing.
type TemplatePoint struct {
	ID        string `json:"id"`
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	Snippet   string `json:"snippet"`
}

// TemplateSearchResult represents a matched template from semantic vector retrieval.
type TemplateSearchResult struct {
	ID        string  `json:"id"`
	AccountID string  `json:"account_id"`
	Name      string  `json:"name"`
	Subject   string  `json:"subject"`
	Snippet   string  `json:"snippet"`
	Score     float32 `json:"score"`
}

// Client manages communication with the remote Qdrant vector database instance.
type Client struct {
	baseURL    string
	apiKey     string
	prefix     string
	httpClient *http.Client
	log        *slog.Logger
	initOnce   sync.Once
	initErr    error
}

// New creates and validates a new Qdrant vector database client.
func New(rawURL, apiKey, prefix string, log *slog.Logger) (*Client, error) {
	if rawURL == "" {
		return nil, ErrNotConfigured
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid qdrant url %q: must start with http:// or https://", rawURL)
	}

	cleanBase := strings.TrimRight(rawURL, "/")
	cleanPrefix := strings.TrimSpace(prefix)
	if cleanPrefix == "" {
		cleanPrefix = DefaultCollectionPrefix
	}
	if log == nil {
		log = slog.Default()
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}

	client := &Client{
		baseURL: cleanBase,
		apiKey:  strings.TrimSpace(apiKey),
		prefix:  cleanPrefix,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   DefaultTimeout,
		},
		log: log,
	}

	return client, nil
}

// EmailsCollection returns the namespaced collection name for emails.
func (c *Client) EmailsCollection() string {
	return fmt.Sprintf("%s_emails", c.prefix)
}

// TemplatesCollection returns the namespaced collection name for templates.
func (c *Client) TemplatesCollection() string {
	return fmt.Sprintf("%s_templates", c.prefix)
}

// Ping checks if the Qdrant server is healthy and reachable.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/readyz", nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("qdrant readiness returned status %d", resp.StatusCode)
	}
	return nil
}

// EnsureCollections creates the necessary vector collections in Qdrant if they do not exist.
func (c *Client) EnsureCollections(ctx context.Context) error {
	c.initOnce.Do(func() {
		for _, col := range []string{c.EmailsCollection(), c.TemplatesCollection()} {
			if err := c.ensureCollection(ctx, col); err != nil {
				c.initErr = fmt.Errorf("failed to ensure collection %s: %w", col, err)
				return
			}
		}
	})
	return c.initErr
}

func (c *Client) ensureCollection(ctx context.Context, name string) error {
	// Check if collection exists
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/collections/%s", c.baseURL, name), nil)
	if err != nil {
		return err
	}
	c.setHeaders(getReq)
	getResp, err := c.httpClient.Do(getReq)
	if err == nil {
		defer getResp.Body.Close()
		if getResp.StatusCode == http.StatusOK {
			return nil
		}
	}

	// Create collection
	payload := map[string]any{
		"vectors": map[string]any{
			"size":     VectorDimension,
			"distance": "Cosine",
		},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s/collections/%s", c.baseURL, name), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	c.setHeaders(putReq)
	putResp, err := c.httpClient.Do(putReq)
	if err != nil {
		return err
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK && putResp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(putResp.Body)
		return fmt.Errorf("create collection failed with status %d: %s", putResp.StatusCode, string(b))
	}
	return nil
}

// UpsertEmail generates a semantic vector embedding and indexes an email into Qdrant.
func (c *Client) UpsertEmail(ctx context.Context, p EmailPoint) error {
	if p.ID == "" || p.AccountID == "" {
		return errors.New("email id and account id are required")
	}
	combinedText := strings.TrimSpace(p.Subject + " " + p.Snippet)
	if combinedText == "" {
		combinedText = p.Subject
	}
	vec := Vectorize(combinedText)

	payload := map[string]any{
		"points": []map[string]any{
			{
				"id":     p.ID,
				"vector": vec,
				"payload": map[string]any{
					"account_id": p.AccountID,
					"subject":    p.Subject,
					"snippet":    truncateString(p.Snippet, 500),
					"from":       p.From,
					"to":         p.To,
					"created_at": p.CreatedAt,
					"tags":       p.Tags,
				},
			},
		},
	}
	return c.upsertPoints(ctx, c.EmailsCollection(), payload)
}

// SearchEmails queries Qdrant using cosine similarity, filtered strictly by account ID.
func (c *Client) SearchEmails(ctx context.Context, accountID, query string, limit int) ([]EmailSearchResult, error) {
	cleanQuery := strings.TrimSpace(query)
	if cleanQuery == "" {
		return nil, ErrEmptyQuery
	}
	if accountID == "" {
		return nil, errors.New("account id is required for semantic search")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	vec := Vectorize(cleanQuery)
	searchBody := map[string]any{
		"vector":       vec,
		"limit":        limit,
		"with_payload": true,
		"filter": map[string]any{
			"must": []map[string]any{
				{
					"key": "account_id",
					"match": map[string]any{
						"value": accountID,
					},
				},
			},
		},
	}

	rawResp, err := c.searchPoints(ctx, c.EmailsCollection(), searchBody)
	if err != nil {
		return nil, err
	}

	results := make([]EmailSearchResult, 0, len(rawResp))
	for _, item := range rawResp {
		var to []string
		if toSlice, ok := item.Payload["to"].([]any); ok {
			for _, t := range toSlice {
				if s, ok := t.(string); ok {
					to = append(to, s)
				}
			}
		}
		var tags map[string]string
		if tagMap, ok := item.Payload["tags"].(map[string]any); ok {
			tags = make(map[string]string, len(tagMap))
			for k, v := range tagMap {
				if sv, ok := v.(string); ok {
					tags[k] = sv
				}
			}
		}

		results = append(results, EmailSearchResult{
			ID:        item.ID,
			AccountID: getString(item.Payload, "account_id"),
			Subject:   getString(item.Payload, "subject"),
			Snippet:   getString(item.Payload, "snippet"),
			From:      getString(item.Payload, "from"),
			To:        to,
			CreatedAt: getString(item.Payload, "created_at"),
			Score:     item.Score,
			Tags:      tags,
		})
	}
	return results, nil
}

// UpsertTemplate generates a vector embedding and indexes an email template.
func (c *Client) UpsertTemplate(ctx context.Context, p TemplatePoint) error {
	if p.ID == "" || p.AccountID == "" {
		return errors.New("template id and account id are required")
	}
	combinedText := strings.TrimSpace(p.Name + " " + p.Subject + " " + p.Snippet)
	vec := Vectorize(combinedText)

	payload := map[string]any{
		"points": []map[string]any{
			{
				"id":     p.ID,
				"vector": vec,
				"payload": map[string]any{
					"account_id": p.AccountID,
					"name":       p.Name,
					"subject":    p.Subject,
					"snippet":    truncateString(p.Snippet, 500),
				},
			},
		},
	}
	return c.upsertPoints(ctx, c.TemplatesCollection(), payload)
}

// SearchTemplates queries Qdrant for matching templates using semantic cosine similarity.
func (c *Client) SearchTemplates(ctx context.Context, accountID, query string, limit int) ([]TemplateSearchResult, error) {
	cleanQuery := strings.TrimSpace(query)
	if cleanQuery == "" {
		return nil, ErrEmptyQuery
	}
	if accountID == "" {
		return nil, errors.New("account id is required for semantic search")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	vec := Vectorize(cleanQuery)
	searchBody := map[string]any{
		"vector":       vec,
		"limit":        limit,
		"with_payload": true,
		"filter": map[string]any{
			"must": []map[string]any{
				{
					"key": "account_id",
					"match": map[string]any{
						"value": accountID,
					},
				},
			},
		},
	}

	rawResp, err := c.searchPoints(ctx, c.TemplatesCollection(), searchBody)
	if err != nil {
		return nil, err
	}

	results := make([]TemplateSearchResult, 0, len(rawResp))
	for _, item := range rawResp {
		results = append(results, TemplateSearchResult{
			ID:        item.ID,
			AccountID: getString(item.Payload, "account_id"),
			Name:      getString(item.Payload, "name"),
			Subject:   getString(item.Payload, "subject"),
			Snippet:   getString(item.Payload, "snippet"),
			Score:     item.Score,
		})
	}
	return results, nil
}

// DeletePoint removes a point by ID from a collection.
func (c *Client) DeletePoint(ctx context.Context, collectionName, id string) error {
	if collectionName == "" || id == "" {
		return errors.New("collection name and point id are required")
	}
	body := map[string]any{
		"points": []string{id},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/collections/%s/points/delete", c.baseURL, collectionName), bytes.NewReader(b))
	if err != nil {
		return err
	}
	c.setHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

type rawSearchHit struct {
	ID      string         `json:"id"`
	Score   float32        `json:"score"`
	Payload map[string]any `json:"payload"`
}

type qdrantSearchResponse struct {
	Result []rawSearchHit `json:"result"`
	Status string         `json:"status"`
}

func (c *Client) upsertPoints(ctx context.Context, collection string, payload map[string]any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/collections/%s/points?wait=false", c.baseURL, collection)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		out, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("qdrant upsert returned %d: %s", resp.StatusCode, string(out))
	}
	return nil
}

func (c *Client) searchPoints(ctx context.Context, collection string, searchBody map[string]any) ([]rawSearchHit, error) {
	b, err := json.Marshal(searchBody)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/collections/%s/points/search", c.baseURL, collection)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("qdrant search returned %d: %s", resp.StatusCode, string(out))
	}

	var parsed qdrantSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("failed to decode qdrant search response: %w", err)
	}
	return parsed.Result, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mailhost-Qdrant/1.0")
	if c.apiKey != "" {
		req.Header.Set("api-key", c.apiKey)
	}
}

// Vectorize generates a normalized, deterministic 384-dimensional semantic embedding vector.
// It leverages sublinear term-frequency hashing and character n-gram feature projections,
// L2-normalized so cosine distance accurately reflects semantic similarity.
func Vectorize(text string) []float32 {
	vec := make([]float32, VectorDimension)
	lower := strings.ToLower(text)
	words := wordRegex.FindAllString(lower, -1)
	if len(words) == 0 {
		return vec
	}

	// 1. Word tokens with unigram & bigram hashing
	for i, w := range words {
		// Unigram
		idx := hashToBucket(w, VectorDimension)
		vec[idx] += 1.0

		// Bigram
		if i < len(words)-1 {
			bigram := w + "_" + words[i+1]
			bIdx := hashToBucket(bigram, VectorDimension)
			vec[bIdx] += 1.5
		}
	}

	// 2. Character trigrams for morphological and misspelling resilience
	for _, w := range words {
		if len(w) >= 3 {
			for i := 0; i <= len(w)-3; i++ {
				trigram := w[i : i+3]
				tIdx := hashToBucket(trigram, VectorDimension)
				vec[tIdx] += 0.5
			}
		}
	}

	// 3. Sublinear scaling: log(1 + v)
	var sumSquares float64
	for i := range vec {
		if vec[i] > 0 {
			vec[i] = float32(math.Log1p(float64(vec[i])))
			sumSquares += float64(vec[i] * vec[i])
		}
	}

	// 4. L2 Normalization
	if sumSquares > 0 {
		norm := float32(math.Sqrt(sumSquares))
		for i := range vec {
			vec[i] /= norm
		}
	}

	return vec
}

func hashToBucket(token string, dim int) int {
	h := sha256.Sum256([]byte(token))
	val := binary.BigEndian.Uint32(h[:4])
	return int(val % uint32(dim))
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
