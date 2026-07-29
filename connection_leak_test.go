package elasticsearch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hi")
	}))
}

func runConnectionTest(t *testing.T, serverURL string, useCleanHTTP bool) (initialGoroutines, finalGoroutines, requestCount int) {
	initialGoroutines = runtime.NumGoroutine()
	t.Logf("Initial goroutines: %d", initialGoroutines)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	requestCount = 0
	for {
		select {
		case <-ticker.C:
			client := retryablehttp.NewClient()
			if useCleanHTTP {
				client.HTTPClient.Transport = cleanhttp.DefaultTransport()
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL, nil)
			require.NoError(t, err)

			resp, err := client.HTTPClient.Do(req)
			if err != nil {
				t.Logf("Request failed: %v", err)
				continue
			}

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			requestCount++
			if requestCount >= 50 {
				cancel()
			}

		case <-ctx.Done():
			goto done
		}
	}

done:
	finalGoroutines = runtime.NumGoroutine()
	t.Logf("Final goroutines: %d", finalGoroutines)
	t.Logf("Requests made: %d", requestCount)

	return initialGoroutines, finalGoroutines, requestCount
}

func TestConnectionLeakDetection(t *testing.T) {
	tests := []struct {
		name         string
		useCleanHTTP bool
		expectLeak   bool
		maxGrowth    int
	}{
		{
			name:         "No connection leak with cleanhttp transport",
			useCleanHTTP: true,
			expectLeak:   false,
			maxGrowth:    10,
		},
		{
			name:         "Connection leak without cleanhttp transport",
			useCleanHTTP: false,
			expectLeak:   true,
			maxGrowth:    10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer(t)
			defer server.Close()

			initialGoroutines, finalGoroutines, _ := runConnectionTest(t, server.URL, tt.useCleanHTTP)

			if tt.expectLeak {
				assert.Greater(t, finalGoroutines, initialGoroutines+tt.maxGrowth,
					"Expected connection leak not detected")
			} else {
				assert.LessOrEqual(t, finalGoroutines, initialGoroutines+tt.maxGrowth,
					"Too many goroutines remaining, possible connection leak")
			}
		})
	}
}
