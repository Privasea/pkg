package secret

import (
	"testing"
)

func TestNewCipher(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		want      Secret
	}{
		{
			name:      "Test AES algorithm",
			algorithm: "AES",
			want:      &AesSecret{},
		},
		{
			name:      "Test unknown algorithm",
			algorithm: "Unknown",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewCipher(tt.algorithm)
			if (got == nil && tt.want != nil) || (got != nil && tt.want == nil) {
				t.Errorf("NewCipher() = %v, want %v", got, tt.want)
			}
		})
	}
}
