package pe

import (
	"bytes"
	"testing"
)

func TestReadCString(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		offset  int64
		want    string
		wantErr bool
	}{
		{
			name:    "Simple string",
			data:    []byte("Hello\x00World"),
			offset:  0,
			want:    "Hello",
			wantErr: false,
		},
		{
			name:    "String with offset",
			data:    []byte("Hello\x00World\x00"),
			offset:  6,
			want:    "World",
			wantErr: false,
		},
		{
			name:    "Empty string",
			data:    []byte("\x00"),
			offset:  0,
			want:    "",
			wantErr: false,
		},
		{
			name:    "String with special chars",
			data:    []byte("Test123!@#\x00"),
			offset:  0,
			want:    "Test123!@#",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.data)
			got, err := readCString(reader, tt.offset)

			if (err != nil) != tt.wantErr {
				t.Errorf("readCString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("readCString() = %v, want %v", got, tt.want)
			}
		})
	}
}
