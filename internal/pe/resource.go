package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// ResourceInfo contains PE resource information.
type ResourceInfo struct {
	VersionInfo *VersionInfo
	HasIcon     bool
	IconCount   int
	StringCount int
}

// VersionInfo contains version information from RT_VERSION resource.
type VersionInfo struct {
	FileVersion    string
	ProductVersion string
	CompanyName    string
	ProductName    string
	FileDescription string
	InternalName   string
	OriginalFilename string
	LegalCopyright string
}

// Resource types.
const (
	RT_ICON        = 3
	RT_STRING      = 6
	RT_GROUP_ICON  = 14
	RT_VERSION     = 16
)

// IMAGE_RESOURCE_DIRECTORY structure.
type resourceDirectory struct {
	Characteristics      uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NumberOfNamedEntries uint16
	NumberOfIdEntries    uint16
}

// IMAGE_RESOURCE_DIRECTORY_ENTRY structure.
type resourceDirectoryEntry struct {
	NameOrID uint32
	OffsetToDataOrDirectory uint32
}

// IMAGE_RESOURCE_DATA_ENTRY structure.
type resourceDataEntry struct {
	OffsetToData uint32
	Size         uint32
	CodePage     uint32
	Reserved     uint32
}

// ParseResources extracts resource information from PE file.
func ParseResources(f *pe.File, r io.ReaderAt) (*ResourceInfo, error) {
	info := &ResourceInfo{}

	// Get Resource Directory (Data Directory[2])
	var resDirRVA, resDirSize uint32

	if oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 2 {
			resDirRVA = oh32.DataDirectory[2].VirtualAddress
			resDirSize = oh32.DataDirectory[2].Size
		}
	} else if oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		if len(oh64.DataDirectory) > 2 {
			resDirRVA = oh64.DataDirectory[2].VirtualAddress
			resDirSize = oh64.DataDirectory[2].Size
		}
	}

	if resDirRVA == 0 || resDirSize == 0 {
		return info, nil // No resources
	}

	// Convert RVA to file offset
	resOffset, err := rvaToOffset(f, resDirRVA)
	if err != nil {
		return info, err
	}

	// Parse resource directory tree
	err = parseResourceDirectory(f, r, int64(resOffset), int64(resOffset), info)
	if err != nil {
		return info, err
	}

	return info, nil
}

func parseResourceDirectory(f *pe.File, r io.ReaderAt, baseOffset, currentOffset int64, info *ResourceInfo) error {
	var dir resourceDirectory
	err := binary.Read(io.NewSectionReader(r, currentOffset, 16), binary.LittleEndian, &dir)
	if err != nil {
		return err
	}

	totalEntries := int(dir.NumberOfNamedEntries + dir.NumberOfIdEntries)

	// Read all directory entries
	for i := 0; i < totalEntries; i++ {
		var entry resourceDirectoryEntry
		entryOffset := currentOffset + 16 + int64(i*8)
		err := binary.Read(io.NewSectionReader(r, entryOffset, 8), binary.LittleEndian, &entry)
		if err != nil {
			continue
		}

		typeID := entry.NameOrID
		isDirectory := (entry.OffsetToDataOrDirectory & 0x80000000) != 0
		offset := entry.OffsetToDataOrDirectory & 0x7FFFFFFF

		if isDirectory {
			// This is a subdirectory
			newOffset := baseOffset + int64(offset)

			// For root level, track resource types
			if currentOffset == baseOffset {
				switch typeID {
				case RT_VERSION:
					// Parse version info
					_ = parseVersionResource(f, r, baseOffset, newOffset, info)
				case RT_ICON:
					info.HasIcon = true
					info.IconCount++
				case RT_GROUP_ICON:
					info.HasIcon = true
				case RT_STRING:
					info.StringCount++
				}
			}
		}
	}

	return nil
}

func parseVersionResource(f *pe.File, r io.ReaderAt, baseOffset, dirOffset int64, info *ResourceInfo) error {
	// Read the version resource directory (Name level)
	var dir resourceDirectory
	err := binary.Read(io.NewSectionReader(r, dirOffset, 16), binary.LittleEndian, &dir)
	if err != nil {
		return err
	}

	// Get first entry (usually the only one)
	if dir.NumberOfNamedEntries+dir.NumberOfIdEntries == 0 {
		return nil
	}

	var entry resourceDirectoryEntry
	err = binary.Read(io.NewSectionReader(r, dirOffset+16, 8), binary.LittleEndian, &entry)
	if err != nil {
		return err
	}

	isDirectory := (entry.OffsetToDataOrDirectory & 0x80000000) != 0
	if !isDirectory {
		return nil
	}

	langOffset := baseOffset + int64(entry.OffsetToDataOrDirectory&0x7FFFFFFF)

	// Read language level directory
	err = binary.Read(io.NewSectionReader(r, langOffset, 16), binary.LittleEndian, &dir)
	if err != nil {
		return err
	}

	if dir.NumberOfNamedEntries+dir.NumberOfIdEntries == 0 {
		return nil
	}

	// Get first language entry
	err = binary.Read(io.NewSectionReader(r, langOffset+16, 8), binary.LittleEndian, &entry)
	if err != nil {
		return err
	}

	// This should point to data
	if (entry.OffsetToDataOrDirectory & 0x80000000) != 0 {
		return nil
	}

	dataEntryOffset := baseOffset + int64(entry.OffsetToDataOrDirectory)

	// Read data entry
	var dataEntry resourceDataEntry
	err = binary.Read(io.NewSectionReader(r, dataEntryOffset, 16), binary.LittleEndian, &dataEntry)
	if err != nil {
		return err
	}

	// Convert data RVA to offset
	dataOffset, err := rvaToOffset(f, dataEntry.OffsetToData)
	if err != nil {
		return err
	}

	// Read version data
	versionData := make([]byte, dataEntry.Size)
	_, err = r.ReadAt(versionData, int64(dataOffset))
	if err != nil {
		return err
	}

	// Parse VS_VERSIONINFO structure
	info.VersionInfo = parseVersionInfo(versionData)

	return nil
}

// VS_VERSIONINFO header.
type vsVersionInfo struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

func parseVersionInfo(data []byte) *VersionInfo {
	if len(data) < 6 {
		return nil
	}

	info := &VersionInfo{}

	// Simple string extraction from version resource
	// Look for common string keys
	stringData := string(data)

	info.CompanyName = extractVersionString(data, "CompanyName")
	info.FileDescription = extractVersionString(data, "FileDescription")
	info.FileVersion = extractVersionString(data, "FileVersion")
	info.InternalName = extractVersionString(data, "InternalName")
	info.LegalCopyright = extractVersionString(data, "LegalCopyright")
	info.OriginalFilename = extractVersionString(data, "OriginalFilename")
	info.ProductName = extractVersionString(data, "ProductName")
	info.ProductVersion = extractVersionString(data, "ProductVersion")

	// Fallback: extract from fixed file info if strings not found
	if info.FileVersion == "" && len(data) >= 52 {
		// Try to find VS_FIXEDFILEINFO (should be at offset 40-ish)
		for i := 0; i < len(data)-52; i++ {
			if binary.LittleEndian.Uint32(data[i:]) == 0xFEEF04BD { // Signature
				fileVersionMS := binary.LittleEndian.Uint32(data[i+8:])
				fileVersionLS := binary.LittleEndian.Uint32(data[i+12:])
				info.FileVersion = fmt.Sprintf("%d.%d.%d.%d",
					(fileVersionMS>>16)&0xFFFF,
					fileVersionMS&0xFFFF,
					(fileVersionLS>>16)&0xFFFF,
					fileVersionLS&0xFFFF)

				productVersionMS := binary.LittleEndian.Uint32(data[i+16:])
				productVersionLS := binary.LittleEndian.Uint32(data[i+20:])
				info.ProductVersion = fmt.Sprintf("%d.%d.%d.%d",
					(productVersionMS>>16)&0xFFFF,
					productVersionMS&0xFFFF,
					(productVersionLS>>16)&0xFFFF,
					productVersionLS&0xFFFF)
				break
			}
		}
	}

	_ = stringData // Avoid unused variable

	return info
}

func extractVersionString(data []byte, key string) string {
	// Convert key to UTF-16LE for searching
	keyUTF16 := encodeUTF16(key)

	// Search for the key
	keyPos := -1
	for i := 0; i < len(data)-len(keyUTF16); i++ {
		match := true
		for j := 0; j < len(keyUTF16); j++ {
			if data[i+j] != keyUTF16[j] {
				match = false
				break
			}
		}
		if match {
			keyPos = i
			break
		}
	}

	if keyPos == -1 {
		return ""
	}

	// Skip past the key and null terminator
	valueStart := keyPos + len(keyUTF16) + 2 // +2 for null terminator

	// Align to 4-byte boundary
	if valueStart%4 != 0 {
		valueStart += 4 - (valueStart % 4)
	}

	if valueStart >= len(data) {
		return ""
	}

	// Read until null terminator
	valueEnd := valueStart
	for valueEnd < len(data)-1 {
		if data[valueEnd] == 0 && data[valueEnd+1] == 0 {
			break
		}
		valueEnd += 2
	}

	if valueEnd >= len(data) {
		return ""
	}

	// Decode UTF-16LE string
	return decodeUTF16(data[valueStart:valueEnd])
}

func encodeUTF16(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	result := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(result[i*2:], v)
	}
	return result
}

func decodeUTF16(data []byte) string {
	if len(data)%2 != 0 {
		return ""
	}

	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}

	return string(utf16.Decode(u16))
}
