package api

import (
	"encoding/json"
	"net/http"
)

// pluginManifest serves the OpenAI ChatGPT Plugin manifest at /.well-known/ai-plugin.json
func (s *Server) pluginManifest(w http.ResponseWriter, r *http.Request) {
	auth := map[string]any{
		"type":               "service_http",
		"authorization_type": "bearer",
	}
	if s.cfg.OpenAIPluginToken != "" {
		auth["verification_tokens"] = map[string]string{"openai": s.cfg.OpenAIPluginToken}
	}
	manifest := map[string]any{
		"schema_version":        "v1",
		"name_for_human":        "Mailhost",
		"name_for_model":        "mailhost",
		"description_for_human": "High-performance enterprise email: send emails, track delivery, manage domains, and generate SMTP passwords.",
		"description_for_model": "Send emails, check delivery status, manage sender domains, configure aliases, inspect inbound mail, and generate application passwords for SMTP client access.",
		"auth":                  auth,
		"api": map[string]any{
			"type": "openapi",
			"url":  "/openapi.json",
		},
		"logo_url":       "/logo.png",
		"contact_email":  s.cfg.SupportEmail,
		"legal_info_url": "/legal",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(manifest)
}

// pluginLogo serves a clean 128x128 SVG icon for the plugin.
func (s *Server) pluginLogo(w http.ResponseWriter, r *http.Request) {
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <rect width="128" height="128" rx="28" fill="#18181b"/>
  <path d="M28 40 L64 68 L100 40 Z" fill="#3b82f6"/>
  <path d="M26 42 L64 72 L102 42 L102 88 L26 88 Z" fill="none" stroke="#60a5fa" stroke-width="6" stroke-linejoin="round" stroke-linecap="round"/>
</svg>`
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(svg))
}

// pluginLegal serves basic legal/terms text required by OpenAI plugin manifest.
func (s *Server) pluginLegal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Mailhost Enterprise Email Platform - Terms and Privacy Policy"))
}

// openapiSpec serves the OpenAPI 3.1.0 specification in JSON format.
func (s *Server) openapiSpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(openapiJSON))
}

// openapiSpecYAML serves the OpenAPI specification in YAML-compatible format.
func (s *Server) openapiSpecYAML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(openapiJSON))
}

const openapiJSON = `{
  "openapi": "3.1.0",
  "info": {
    "title": "Mailhost API",
    "description": "Enterprise-grade high-throughput email platform API for sending emails, tracking deliveries, managing domains and aliases, and generating per-email SMTP application passwords.",
    "version": "1.0.0"
  },
  "servers": [
    {
      "url": "/",
      "description": "Current Mailhost server"
    }
  ],
  "paths": {
    "/v1/emails": {
      "post": {
        "operationId": "sendEmail",
        "summary": "Send an email",
        "description": "Enqueues an email to be sent to one or more recipients with DKIM signing.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["from", "to", "subject"],
                "properties": {
                  "from": {
                    "type": "string",
                    "description": "Sender email address (must be from a verified domain on this account)"
                  },
                  "to": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "List of recipient email addresses"
                  },
                  "subject": {
                    "type": "string",
                    "description": "Email subject line"
                  },
                  "html": {
                    "type": "string",
                    "description": "HTML version of the message body"
                  },
                  "text": {
                    "type": "string",
                    "description": "Plain text version of the message body"
                  },
                  "cc": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Carbon copy recipients"
                  },
                  "bcc": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Blind carbon copy recipients"
                  },
                  "reply_to": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Reply-to addresses"
                  },
                  "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "Custom email headers"
                  },
                  "attachments": {
                    "type": "array",
                    "description": "List of file attachments",
                    "items": {
                      "type": "object",
                      "required": ["filename", "content"],
                      "properties": {
                        "filename": { "type": "string" },
                        "content": { "type": "string", "description": "Base64 encoded file content" },
                        "content_type": { "type": "string", "description": "MIME type of attachment" }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        "responses": {
          "202": {
            "description": "Email successfully queued for delivery",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "status": { "type": "string", "example": "queued" }
                  }
                }
              }
            }
          },
          "422": { "description": "Validation error" }
        }
      },
      "get": {
        "operationId": "listEmails",
        "summary": "List sent emails",
        "description": "Retrieves recent outbound emails sent by this account.",
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "description": "Number of emails to return (default 1000)",
            "schema": { "type": "integer" }
          },
          {
            "name": "before",
            "in": "query",
            "description": "RFC 3339 timestamp cursor for pagination",
            "schema": { "type": "string", "format": "date-time" }
          }
        ],
        "responses": {
          "200": {
            "description": "List of sent emails",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id": { "type": "string", "format": "uuid" },
                          "from": { "type": "string" },
                          "subject": { "type": "string" },
                          "created_at": { "type": "string", "format": "date-time" }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/v1/emails/{id}": {
      "get": {
        "operationId": "getEmail",
        "summary": "Get email status and delivery details",
        "description": "Returns full delivery progress, attempts, last errors, and event log for an email.",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "description": "Email UUID",
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": {
            "description": "Email details and delivery status",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "from": { "type": "string" },
                    "subject": { "type": "string" },
                    "created_at": { "type": "string", "format": "date-time" },
                    "deliveries": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id": { "type": "string" },
                          "recipient": { "type": "string" },
                          "status": { "type": "string", "enum": ["queued", "sending", "delivered", "bounced", "deferred", "failed"] },
                          "attempts": { "type": "integer" },
                          "last_error": { "type": "string" }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          "404": { "description": "Email not found" }
        }
      }
    },
    "/v1/smtp-credentials": {
      "post": {
        "operationId": "createSMTPCredential",
        "summary": "Generate an SMTP application password",
        "description": "Generates a dedicated application password for a particular email address to allow standard SMTP client access (e.g., WordPress, Nodemailer, Django).",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["email"],
                "properties": {
                  "email": {
                    "type": "string",
                      "description": "The email address this credential will send as"
                  },
                  "name": {
                    "type": "string",
                    "description": "Friendly name for the application using this password",
                    "example": "WordPress Storefront"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Credential created successfully (password returned once)",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "email": { "type": "string" },
                    "username": { "type": "string" },
                    "password": { "type": "string", "description": "Generated application password" },
                    "smtp_host": { "type": "string" },
                    "smtp_port": { "type": "integer", "example": 587 },
                    "tls": { "type": "string", "example": "STARTTLS" }
                  }
                }
              }
            }
          },
          "422": { "description": "Domain not verified or invalid email" }
        }
      },
      "get": {
        "operationId": "listSMTPCredentials",
        "summary": "List SMTP application credentials",
        "description": "Lists all active SMTP application passwords created for this account.",
        "parameters": [
          {
            "name": "email",
            "in": "query",
            "description": "Optional email filter",
            "schema": { "type": "string" }
          }
        ],
        "responses": {
          "200": {
            "description": "List of active SMTP credentials",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id": { "type": "string", "format": "uuid" },
                          "email": { "type": "string" },
                          "name": { "type": "string" },
                          "username": { "type": "string" },
                          "created_at": { "type": "string", "format": "date-time" }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/v1/smtp-credentials/{id}": {
      "delete": {
        "operationId": "deleteSMTPCredential",
        "summary": "Revoke an SMTP application credential",
        "description": "Permanently revokes an SMTP application password.",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "204": { "description": "Credential revoked" },
          "404": { "description": "Credential not found" }
        }
      }
    },
    "/v1/domains": {
      "get": {
        "operationId": "listDomains",
        "summary": "List sender domains",
        "description": "Lists all sender domains and their DKIM / SPF verification status.",
        "responses": {
          "200": {
            "description": "List of domains",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id": { "type": "string", "format": "uuid" },
                          "name": { "type": "string" },
                          "status": { "type": "string", "enum": ["pending", "verified", "failed"] }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "post": {
        "operationId": "createDomain",
        "summary": "Add a new sender domain",
        "description": "Registers a new sender domain and returns the required DNS records for DKIM, SPF, and ownership.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                  "name": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Domain created with required DNS records" }
        }
      }
    },
    "/v1/domains/{id}": {
      "get": {
        "operationId": "getDomain",
        "summary": "Get domain details and DNS records",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": { "description": "Domain information including DNS records" },
          "404": { "description": "Domain not found" }
        }
      }
    },
    "/v1/domains/{id}/verify": {
      "post": {
        "operationId": "verifyDomain",
        "summary": "Trigger domain DNS verification",
        "description": "Checks the DNS TXT/MX records for DKIM, SPF, and ownership.",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": { "description": "Verification result" }
        }
      }
    },
    "/v1/aliases": {
      "get": {
        "operationId": "listAliases",
        "summary": "List email aliases",
        "description": "Lists all email forwarding aliases configured for this account.",
        "responses": {
          "200": { "description": "List of aliases" }
        }
      },
      "post": {
        "operationId": "createAlias",
        "summary": "Create an email forwarding alias",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["domain_id", "name"],
                "properties": {
                  "domain_id": { "type": "string", "format": "uuid" },
                  "name": { "type": "string", "description": "Local part (e.g., support or *)" },
                  "destinations": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Forwarding destination email addresses"
                  },
                  "store_copy": { "type": "boolean" }
                }
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Alias created" }
        }
      }
    },
    "/v1/inbound": {
      "get": {
        "operationId": "listInboundEmails",
        "summary": "List received inbound emails",
        "description": "Lists incoming emails delivered to verified domains on this account.",
        "responses": {
          "200": { "description": "List of received inbound messages" }
        }
      }
    },
    "/v1/analytics": {
      "get": {
        "operationId": "getAnalytics",
        "summary": "Get email analytics",
        "description": "Retrieves aggregated counts of sent, delivered, bounced, and failed emails.",
        "parameters": [
          { "name": "interval", "in": "query", "schema": { "type": "string", "enum": ["hour", "day", "week", "month"] } },
          { "name": "from", "in": "query", "schema": { "type": "string", "format": "date-time" } },
          { "name": "to", "in": "query", "schema": { "type": "string", "format": "date-time" } }
        ],
        "responses": {
          "200": { "description": "Aggregated analytics data" }
        }
      }
    },
    "/healthz": {
      "get": {
        "operationId": "healthCheck",
        "summary": "Service health check",
        "responses": {
          "200": { "description": "Service is healthy" }
        }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "BearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "API_KEY",
        "description": "Enter your Mailhost API key (e.g., re_live_...)"
      }
    }
  },
  "security": [
    {
      "BearerAuth": []
    }
  ]
}`
