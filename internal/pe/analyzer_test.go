package pe

import (
	"debug/pe"
	"testing"
)

func TestGetSectionPermissions(t *testing.T) {
	tests := []struct {
		name string
		char uint32
		want string
	}{
		{
			name: "Read only",
			char: pe.IMAGE_SCN_MEM_READ,
			want: "R--",
		},
		{
			name: "Read Write",
			char: pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE,
			want: "RW-",
		},
		{
			name: "Read Execute",
			char: pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE,
			want: "R-X",
		},
		{
			name: "Read Write Execute (RWX - suspicious)",
			char: pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE | pe.IMAGE_SCN_MEM_EXECUTE,
			want: "RWX",
		},
		{
			name: "Write Execute",
			char: pe.IMAGE_SCN_MEM_WRITE | pe.IMAGE_SCN_MEM_EXECUTE,
			want: "-WX",
		},
		{
			name: "No permissions",
			char: 0,
			want: "---",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getSectionPermissions(tt.char)
			if got != tt.want {
				t.Errorf("getSectionPermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetSubsystem(t *testing.T) {
	tests := []struct {
		name      string
		subsystem uint16
		want      string
	}{
		{
			name:      "Windows GUI",
			subsystem: pe.IMAGE_SUBSYSTEM_WINDOWS_GUI,
			want:      "Windows GUI",
		},
		{
			name:      "Windows Console",
			subsystem: pe.IMAGE_SUBSYSTEM_WINDOWS_CUI,
			want:      "Windows 控制台",
		},
		{
			name:      "Native",
			subsystem: pe.IMAGE_SUBSYSTEM_NATIVE,
			want:      "Native",
		},
		{
			name:      "Unknown subsystem",
			subsystem: 0xFF,
			want:      "未知 (0xFF)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getSubsystem(tt.subsystem)
			if got != tt.want {
				t.Errorf("getSubsystem() = %v, want %v", got, tt.want)
			}
		})
	}
}
