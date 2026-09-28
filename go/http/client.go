package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/bsv8/roundtrip/go/core"
)

// ExchangeOptions configures the client side exchange.
type ExchangeOptions struct {
	// Client is the HTTP client. nil uses http.DefaultClient.
	Client *http.Client
	// MaxResponseBytes bounds what the client will read from the network.
	MaxResponseBytes int
	// Headers are added to every request, for example a proxy or a trace id.
	Headers map[string]string
}

// DefaultMaxResponseBytes is the local response limit.
const DefaultMaxResponseBytes = 1024 * 1024

// Exchange moves one signed request to one signed response over POST.
//
// There is no global waiting table and no response dispatch loop: the HTTP call
// that sends the request is the call that waits for its answer. A non 2xx status
// is reported as a transport failure, because an unsigned status code or a proxy
// error page is not a signed business result.
func Exchange(url string, options ExchangeOptions) core.Exchange {
	client := options.Client
	if client == nil {
		client = http.DefaultClient
	}
	maxResponse := options.MaxResponseBytes
	if maxResponse <= 0 {
		maxResponse = DefaultMaxResponseBytes
	}
	return func(ctx context.Context, requestBytes []byte) ([]byte, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestBytes))
		if err != nil {
			return nil, &core.Error{Code: core.ErrTransport, Err: err}
		}
		request.Header.Set("Content-Type", ContentType)
		for name, value := range options.Headers {
			request.Header.Set(name, value)
		}
		response, err := client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return nil, &core.Error{Code: core.ErrCallAborted, Err: ctx.Err()}
			}
			return nil, &core.Error{Code: core.ErrTransport, Err: err}
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode > 299 {
			// Drain so the connection can be reused, then report the failure.
			//nolint:errcheck // draining is best effort
			io.Copy(io.Discard, io.LimitReader(response.Body, int64(maxResponse)))
			return nil, &core.Error{
				Code: core.ErrHTTPStatus,
				Err:  fmt.Errorf("unexpected HTTP status %d", response.StatusCode),
			}
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, int64(maxResponse)+1))
		if err != nil {
			return nil, &core.Error{Code: core.ErrTransport, Err: err}
		}
		if len(body) > maxResponse {
			return nil, &core.Error{Code: core.ErrResponseSize, Err: errors.New("response exceeds the local message limit")}
		}
		return body, nil
	}
}
