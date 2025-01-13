package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "Valid API key",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "No Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization header (missing value)",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed Authorization header (wrong format)",
			headers:     http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Empty Authorization header",
			headers:     http.Header{"Authorization": []string{""}},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := GetAPIKey(test.headers)

			if key != test.expectedKey {
				t.Errorf("expected key %q, got %q", test.expectedKey, key)
			}

			if (err != nil && test.expectedErr == nil) || (err == nil && test.expectedErr != nil) || (err != nil && err.Error() != test.expectedErr.Error()) {
				t.Errorf("expected error %v, got %v", test.expectedErr, err)
			}
		})
	}
}
