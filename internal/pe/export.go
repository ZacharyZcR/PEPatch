package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// ExportDirectory represents the PE export directory table.
type ExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// parseExports extracts exported function names from a PE file.
func parseExports(f *pe.File, r io.ReaderAt) ([]string, error) {
	// Get export data directory RVA and size
	var exportDirRVA, exportDirSize uint32

	if oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 0 {
			exportDirRVA = oh32.DataDirectory[0].VirtualAddress
			exportDirSize = oh32.DataDirectory[0].Size
		}
	} else if oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		if len(oh64.DataDirectory) > 0 {
			exportDirRVA = oh64.DataDirectory[0].VirtualAddress
			exportDirSize = oh64.DataDirectory[0].Size
		}
	}

	// No exports
	if exportDirRVA == 0 || exportDirSize == 0 {
		return nil, nil
	}

	// Convert RVA to file offset
	exportDirOffset, err := rvaToOffset(f, exportDirRVA)
	if err != nil {
		return nil, fmt.Errorf("无法定位导出表: %w", err)
	}

	// Read export directory
	var exportDir ExportDirectory
	sr := io.NewSectionReader(r, int64(exportDirOffset), int64(exportDirSize))
	if err := binary.Read(sr, binary.LittleEndian, &exportDir); err != nil {
		return nil, fmt.Errorf("读取导出目录失败: %w", err)
	}

	// No named exports
	if exportDir.NumberOfNames == 0 {
		return nil, nil
	}

	// Read export name pointers
	namePointersOffset, err := rvaToOffset(f, exportDir.AddressOfNames)
	if err != nil {
		return nil, err
	}

	namePointers := make([]uint32, exportDir.NumberOfNames)
	sr = io.NewSectionReader(r, int64(namePointersOffset), int64(exportDir.NumberOfNames*4))
	if err := binary.Read(sr, binary.LittleEndian, &namePointers); err != nil {
		return nil, fmt.Errorf("读取导出名称指针失败: %w", err)
	}

	// Read export names
	var exports []string
	for _, nameRVA := range namePointers {
		nameOffset, err := rvaToOffset(f, nameRVA)
		if err != nil {
			continue
		}

		name, err := readCString(r, int64(nameOffset))
		if err != nil {
			continue
		}

		exports = append(exports, name)
	}

	return exports, nil
}

// rvaToOffset converts RVA to file offset.
func rvaToOffset(f *pe.File, rva uint32) (uint32, error) {
	for _, section := range f.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return rva - section.VirtualAddress + section.Offset, nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%X 不在任何节区内", rva)
}

// readCString reads a null-terminated string from the reader.
func readCString(r io.ReaderAt, offset int64) (string, error) {
	var result []byte
	buf := make([]byte, 1)

	for i := 0; i < 256; i++ { // Max 256 chars
		_, err := r.ReadAt(buf, offset+int64(i))
		if err != nil {
			return "", err
		}
		if buf[0] == 0 {
			break
		}
		result = append(result, buf[0])
	}

	return string(result), nil
}
