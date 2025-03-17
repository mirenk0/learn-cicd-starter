package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		expectKey string
		expectErr error
	}{
		{
			name:      "Valid API Key",
			headers:   http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectKey: "my-secret-key",
			expectErr: nil,
		},
		{
			name:      "No Authorization Header",
			headers:   http.Header{},
			expectKey: "",
			expectErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "Malformed Authorization Header (Missing ApiKey prefix)",
			headers:   http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expectKey: "",
			expectErr: errors.New("malformed authorization header"),
		},
		{
			name:      "Malformed Authorization Header (Missing Key)",
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			expectKey: "",
			expectErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectKey {
				t.Errorf("expected key %q, got %q", tt.expectKey, key)
			}

			if (err == nil) != (tt.expectErr == nil) || (err != nil && err.Error() != tt.expectErr.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}
		})
	}
}
