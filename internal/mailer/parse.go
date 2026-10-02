package mailer

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
)

// ParsedAttachment contains safe metadata extracted from a MIME attachment.
type ParsedAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
}

// Parsed contains the useful headers, bodies, and attachment metadata extracted from a message.
type Parsed struct {
	From, To, Subject, MessageID string
	Text, HTML                   string
	Attachments                  []ParsedAttachment
}

const maxParts = 1_000
const maxBodyPartBytes = 10 << 20 // 10MB limit for body text/html

// Parse extracts headers, the first text/html bodies and attachment metadata. It never fails;
// unparseable content simply yields empty fields.
func Parse(raw []byte) Parsed {
	p := Parsed{Attachments: []ParsedAttachment{}}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return p
	}
	dec := new(mime.WordDecoder)
	decode := func(s string) string {
		if d, err := dec.DecodeHeader(s); err == nil {
			return clean(d)
		}
		return clean(s)
	}
	p.From = decode(msg.Header.Get("From"))
	p.To = decode(msg.Header.Get("To"))
	p.Subject = decode(msg.Header.Get("Subject"))
	p.MessageID = clean(strings.Trim(msg.Header.Get("Message-Id"), "<> "))
	n := 0
	walk(&p, textproto.MIMEHeader(msg.Header), msg.Body, 0, &n)
	p.Text, p.HTML = clean(p.Text), clean(p.HTML)
	return p
}

func walk(p *Parsed, h textproto.MIMEHeader, body io.Reader, depth int, n *int) {
	if depth > 50 || *n >= maxParts {
		return
	}
	*n++
	ct, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		ct = "text/plain"
	}
	if strings.HasPrefix(ct, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for *n < maxParts {
			part, err := mr.NextRawPart()
			if err != nil {
				return
			}
			walk(p, part.Header, part, depth+1, n)
		}
		return
	}
	reader := transferDecoder(h.Get("Content-Transfer-Encoding"), body)
	disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	filename := dparams["filename"]
	if filename == "" {
		filename = params["name"]
	}
	if disp == "attachment" || filename != "" {
		nWritten, _ := io.Copy(io.Discard, reader)
		p.Attachments = append(p.Attachments, ParsedAttachment{
			Filename:    clean(filename),
			ContentType: ct,
			Size:        int(nWritten),
		})
		return
	}
	lr := io.LimitReader(reader, maxBodyPartBytes)
	data, err := io.ReadAll(lr)
	if err != nil {
		return
	}
	switch {
	case ct == "text/plain" && p.Text == "":
		p.Text = string(data)
	case ct == "text/html" && p.HTML == "":
		p.HTML = string(data)
	}
}

func transferDecoder(enc string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r
}

// clean makes strings safe for Postgres text columns.
func clean(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "\uFFFD"), "\x00", "")
}
