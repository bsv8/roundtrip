// Package http adapts the shell to plain HTTP: a signed request in, a signed
// response out, on one fixed entry path.
//
// HTTP already pairs a request with a response, which is exactly why the shell
// still carries reply_to: an attacker on a plain HTTP path can substitute an
// older validly signed response, and only the correlation field stops it.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/bsv8/roundtrip/go/core"
)

// Path is the fixed entry. The operation only comes from the signed body.op.
const Path = "/roundtrip"

// ContentType is the only accepted request media type.
const ContentType = "application/json"

// DefaultMaxBodyBytes is the local entry limit. A receiver enforces its own
// limits and never negotiates them online.
const DefaultMaxBodyBytes = 1024 * 1024

// RequestView is the transport neutral view of one HTTP request.
type RequestView struct {
	Method      string
	Path        string
	ContentType string
	Body        []byte
}

// ResponseView is what the entry answers with.
type ResponseView struct {
	Status      int
	ContentType string
	Body        []byte
}

// Endpoint handles one request view and returns one response view.
type Endpoint func(ctx context.Context, request RequestView) (ResponseView, error)

// Options configures the endpoint.
type Options struct {
	// Path overrides the fixed entry path.
	Path string
	// MaxBodyBytes overrides the local entry limit.
	MaxBodyBytes int
}

// NewEndpoint builds the entry: POST on one path, signed shell in, signed shell
// out.
func NewEndpoint(protocol *core.Core, options Options) Endpoint {
	path := options.Path
	if path == "" {
		path = Path
	}
	return func(ctx context.Context, request RequestView) (ResponseView, error) {
		if request.Path != path {
			return errorResponse(404, "NOT_FOUND", "unknown entry path"), nil
		}
		if request.Method != http.MethodPost {
			return errorResponse(405, "METHOD_NOT_ALLOWED", "only POST is accepted"), nil
		}
		// A charset parameter must not change the decision.
		if request.ContentType != "" {
			media := strings.ToLower(strings.TrimSpace(strings.Split(request.ContentType, ";")[0]))
			if media != ContentType {
				return errorResponse(415, "UNSUPPORTED_MEDIA_TYPE", "content type must be application/json"), nil
			}
		}
		processed, err := protocol.Handle(ctx, request.Body, core.HandleOptions{})
		if err != nil {
			// An entry error is unsigned on purpose: a status code or a proxy
			// error page must never look like a signed business result.
			return errorResponse(statusForCode(err), string(core.CodeOf(err)), err.Error()), nil
		}
		return ResponseView{Status: 200, ContentType: ContentType, Body: processed.Bytes}, nil
	}
}

func statusForCode(err error) int {
	switch core.CodeOf(err) {
	case core.ErrMessageTooLarge, core.ErrResponseSize:
		return 413
	case core.ErrRecipient, core.ErrCallerIdentity:
		return 403
	case core.ErrNoHandler, core.ErrSignerKey, core.ErrSignerFailed:
		return 500
	default:
		return 400
	}
}

func errorResponse(status int, code, message string) ResponseView {
	body, err := json.Marshal(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
	if err != nil {
		// Encoding a two string map cannot fail; fall back to a literal rather
		// than returning an empty body.
		body = []byte(`{"error":{"code":"INTERNAL","message":"the entry could not answer"}}`)
	}
	return ResponseView{Status: status, ContentType: ContentType, Body: body}
}

// Handler binds the endpoint to net/http.
func Handler(endpoint Endpoint, maxBodyBytes int) http.Handler {
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		body, err := readBody(request, maxBodyBytes)
		if err != nil {
			// The connection is only closed after the response is on the wire,
			// otherwise the caller could not tell this apart from a broken
			// network.
			view := errorResponse(413, string(core.ErrMessageTooLarge), err.Error())
			respond(writer, view, true)
			return
		}
		view, err := endpoint(request.Context(), RequestView{
			Method:      request.Method,
			Path:        path,
			ContentType: request.Header.Get("Content-Type"),
			Body:        body,
		})
		if err != nil {
			view = errorResponse(500, "INTERNAL", "the request could not be processed")
		}
		respond(writer, view, false)
	})
}

func respond(writer http.ResponseWriter, view ResponseView, close bool) {
	header := writer.Header()
	header.Set("Content-Type", view.ContentType)
	header.Set("Content-Length", itoa(len(view.Body)))
	if close {
		header.Set("Connection", "close")
	}
	writer.WriteHeader(view.Status)
	//nolint:errcheck // the status is already on the wire; a write error adds nothing
	writer.Write(view.Body)
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 20)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// readBody buffers at most maxBodyBytes. The declared length is checked first,
// so an oversized body is usually refused before it is read at all.
func readBody(request *http.Request, maxBodyBytes int) ([]byte, error) {
	if request.ContentLength > int64(maxBodyBytes) {
		return nil, errors.New("request body exceeds the local limit")
	}
	limited := io.LimitReader(request.Body, int64(maxBodyBytes)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodyBytes {
		return nil, errors.New("request body exceeds the local limit")
	}
	return body, nil
}
