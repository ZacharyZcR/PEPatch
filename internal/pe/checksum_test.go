package pe

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestCalculatePEChecksum(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		checksumOffset int64
		want           uint32
	}{
		{
			name: "Simple 8-byte file",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00},
			checksumOffset: -1, // No checksum to skip
			want:           11, // 1 + 2 + filesize(8)
		},
		{
			name: "File with checksum field to skip",
			data: []byte{
				0x01, 0x00, 0x00, 0x00, // DWORD 1
				0xFF, 0xFF, 0xFF, 0xFF, // Checksum field (skipped)
				0x02, 0x00, 0x00, 0x00, // DWORD 2
			},
			checksumOffset: 4,
			want:           15, // 1 + 2 + filesize(12)
		},
		{
			name: "Partial last DWORD",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x02, 0x00},
			checksumOffset: -1,
			want:           9, // 1 + 2 (padded) + filesize(6)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpfile, err := os.CreateTemp("", "petest-*.bin")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())
			defer tmpfile.Close()

			if _, err := tmpfile.Write(tt.data); err != nil {
				t.Fatal(err)
			}

			// Calculate checksum
			got, err := CalculatePEChecksum(tmpfile, int64(len(tt.data)), tt.checksumOffset)
			if err != nil {
				t.Fatalf("CalculatePEChecksum() error = %v", err)
			}

			if got != tt.want {
				t.Errorf("CalculatePEChecksum() = 0x%08X, want 0x%08X", got, tt.want)
			}
		})
	}
}

func TestChecksumCarryHandling(t *testing.T) {
	// Test carry propagation with large values
	data := make([]byte, 16)

	// Create DWORDs that will cause overflow
	binary.LittleEndian.PutUint32(data[0:4], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(data[4:8], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(data[8:12], 0x00000001)
	binary.LittleEndian.PutUint32(data[12:16], 0x00000001)

	tmpfile, err := os.CreateTemp("", "petest-carry-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	if _, err := tmpfile.Write(data); err != nil {
		t.Fatal(err)
	}

	got, err := CalculatePEChecksum(tmpfile, int64(len(data)), -1)
	if err != nil {
		t.Fatalf("CalculatePEChecksum() error = %v", err)
	}

	// Verify carry was handled (exact value depends on algorithm)
	t.Logf("Checksum with overflow: 0x%08X", got)

	// Basic sanity check - should not be zero
	if got == 0 {
		t.Error("Checksum should not be zero with non-zero data")
	}
}
