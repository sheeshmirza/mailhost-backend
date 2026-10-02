package api

import (
	"net/http"
	"regexp"
	"strings"
)

type renderRequest struct {
	Component string         `json:"component,omitempty"` // "Html", "Tailwind", "Markdown"
	HTML      string         `json:"html"`
	Text      string         `json:"text,omitempty"`
	Variables map[string]any `json:"variables,omitempty"`
	InlineCSS bool           `json:"inline_css"`
}

type renderResponse struct {
	HTML string `json:"html"`
	Text string `json:"text"`
}

var (
	htmlTagRegex = regexp.MustCompile(`<[^>]*>`)
	wsRegex      = regexp.MustCompile(`\s{2,}`)
)

// htmlToPlainText converts HTML markup to readable plain text.
func htmlToPlainText(htmlContent string) string {
	text := strings.ReplaceAll(htmlContent, "<br>", "\n")
	text = strings.ReplaceAll(text, "<br/>", "\n")
	text = strings.ReplaceAll(text, "<br />", "\n")
	text = strings.ReplaceAll(text, "</p>", "\n\n")
	text = strings.ReplaceAll(text, "</div>", "\n")
	text = strings.ReplaceAll(text, "</li>", "\n")
	text = strings.ReplaceAll(text, "</tr>", "\n")

	cleaned := htmlTagRegex.ReplaceAllString(text, "")
	cleaned = wsRegex.ReplaceAllString(cleaned, " ")
	return strings.TrimSpace(cleaned)
}

// wrapEmailBoilerplate surrounds email HTML with email client resets, viewport, and Outlook MSO comments.
func wrapEmailBoilerplate(content string) string {
	if strings.Contains(strings.ToLower(content), "<!doctype html>") || strings.Contains(strings.ToLower(content), "<html") {
		return content
	}

	return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html dir="ltr" lang="en">
<head>
  <meta content="text/html; charset=UTF-8" http-equiv="Content-Type" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <!--[if mso]>
  <noscript>
    <xml>
      <o:OfficeDocumentSettings>
        <o:PixelsPerInch>96</o:PixelsPerInch>
      </o:OfficeDocumentSettings>
    </xml>
  </noscript>
  <![endif]-->
  <style>
    body { margin: 0; padding: 0; width: 100% !important; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
    img { border: 0; outline: none; text-decoration: none; -ms-interpolation-mode: bicubic; }
    table { border-collapse: collapse; mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
  </style>
</head>
<body style="background-color:#ffffff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen-Sans,Ubuntu,Cantarell,'Helvetica Neue',sans-serif">
  <table align="center" width="100%" border="0" cellPadding="0" cellSpacing="0" role="presentation" style="max-width:600px;margin:0 auto">
    <tbody>
      <tr>
        <td>
          ` + content + `
        </td>
      </tr>
    </tbody>
  </table>
</body>
</html>`
}

func (s *Server) renderEmail(w http.ResponseWriter, r *http.Request) {
	var req renderRequest
	if !decode(w, r, 0, &req) {
		return
	}

	rawHTML := req.HTML
	if rawHTML == "" && req.Text == "" {
		writeError(w, http.StatusUnprocessableEntity, "html or text is required")
		return
	}

	// Apply variable interpolation if provided
	if len(req.Variables) > 0 {
		_, rawHTML, req.Text = RenderTemplate("", rawHTML, req.Text, req.Variables)
	}

	// Wrap with responsive table boilerplate
	renderedHTML := wrapEmailBoilerplate(rawHTML)

	// Generate text version if absent
	renderedText := req.Text
	if renderedText == "" {
		renderedText = htmlToPlainText(rawHTML)
	}

	writeJSON(w, http.StatusOK, renderResponse{
		HTML: renderedHTML,
		Text: renderedText,
	})
}
