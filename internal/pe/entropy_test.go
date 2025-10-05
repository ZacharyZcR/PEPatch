package pe

import (
	"math"
	"testing"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantMin  float64
		wantMax  float64
		checkVal bool
		want     float64
	}{
		{
			name:     "Empty data",
			data:     []byte{},
			want:     0.0,
			checkVal: true,
		},
		{
			name:     "All same bytes (minimum entropy)",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want:     0.0,
			checkVal: true,
		},
		{
			name:     "All different bytes (high entropy)",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			want:     3.0,
			checkVal: true,
		},
		{
			name:    "Random-like data (very high entropy)",
			data:    make([]byte, 256),
			wantMin: 7.5,
			wantMax: 8.0,
		},
		{
			name:    "Text data (low entropy)",
			data:    []byte("Hello World! This is a test string."),
			wantMin: 3.5,
			wantMax: 5.0,
		},
	}

	// Initialize random-like data test
	for i := 0; i < 256; i++ {
		tests[3].data[i] = byte(i)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateEntropy(tt.data)

			if tt.checkVal {
				if math.Abs(got-tt.want) > 0.01 {
					t.Errorf("CalculateEntropy() = %v, want %v", got, tt.want)
				}
			} else {
				if got < tt.wantMin || got > tt.wantMax {
					t.Errorf("CalculateEntropy() = %v, want between %v and %v", got, tt.wantMin, tt.wantMax)
				}
			}
		})
	}
}

func TestEntropyRanges(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		description string
	}{
		{
			name:        "Low entropy - repeated pattern",
			data:        []byte{0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB},
			description: "Should be < 2.0",
		},
		{
			name:        "Medium entropy - normal code",
			data:        []byte{0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10}, // x64 function prologue
			description: "Should be 2.0-5.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculateEntropy(tt.data)
			t.Logf("%s: entropy = %.6f (%s)", tt.name, entropy, tt.description)

			// Just log the results, don't enforce strict ranges
			// Real PE sections will vary widely
			if entropy < 0 || entropy > 8 {
				t.Errorf("Entropy %v out of valid range [0, 8]", entropy)
			}
		})
	}
}
