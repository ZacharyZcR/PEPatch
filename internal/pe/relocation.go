package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// RelocationInfo contains base relocation information.
type RelocationInfo struct {
	HasRelocations bool
	BlockCount     int
	TotalEntries   int
}

// IMAGE_BASE_RELOCATION structure
type baseRelocationBlock struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

// Relocation types
const (
	IMAGE_REL_BASED_ABSOLUTE       = 0
	IMAGE_REL_BASED_HIGH           = 1
	IMAGE_REL_BASED_LOW            = 2
	IMAGE_REL_BASED_HIGHLOW        = 3
	IMAGE_REL_BASED_HIGHADJ        = 4
	IMAGE_REL_BASED_MIPS_JMPADDR   = 5
	IMAGE_REL_BASED_ARM_MOV32      = 5
	IMAGE_REL_BASED_THUMB_MOV32    = 7
	IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
	IMAGE_REL_BASED_DIR64          = 10
)

// ParseRelocations extracts relocation table information from PE file.
func ParseRelocations(f *pe.File, r io.ReaderAt) (*RelocationInfo, error) {
	info := &RelocationInfo{
		HasRelocations: false,
	}

	// Get Base Relocation Directory (Data Directory[5])
	var relocDirRVA, relocDirSize uint32

	if oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 5 {
			relocDirRVA = oh32.DataDirectory[5].VirtualAddress
			relocDirSize = oh32.DataDirectory[5].Size
		}
	} else if oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		if len(oh64.DataDirectory) > 5 {
			relocDirRVA = oh64.DataDirectory[5].VirtualAddress
			relocDirSize = oh64.DataDirectory[5].Size
		}
	}

	if relocDirRVA == 0 || relocDirSize == 0 {
		return info, nil // No relocations
	}

	info.HasRelocations = true

	// Convert RVA to file offset
	relocOffset, err := rvaToOffset(f, relocDirRVA)
	if err != nil {
		return info, err
	}

	// Parse relocation blocks
	currentOffset := int64(relocOffset)
	endOffset := currentOffset + int64(relocDirSize)

	for currentOffset < endOffset {
		// Read block header
		var block baseRelocationBlock
		err := binary.Read(io.NewSectionReader(r, currentOffset, 8), binary.LittleEndian, &block)
		if err != nil || block.SizeOfBlock == 0 {
			break
		}

		// Count entries in this block
		// Each entry is 2 bytes, header is 8 bytes
		entryCount := int(block.SizeOfBlock-8) / 2
		info.TotalEntries += entryCount
		info.BlockCount++

		// Move to next block
		currentOffset += int64(block.SizeOfBlock)

		// Safety check
		if block.SizeOfBlock < 8 || block.SizeOfBlock > 0x10000 {
			break
		}
	}

	return info, nil
}

// GetRelocationTypeName returns the name of a relocation type.
func GetRelocationTypeName(relocType uint16) string {
	switch relocType {
	case IMAGE_REL_BASED_ABSOLUTE:
		return "ABSOLUTE"
	case IMAGE_REL_BASED_HIGH:
		return "HIGH"
	case IMAGE_REL_BASED_LOW:
		return "LOW"
	case IMAGE_REL_BASED_HIGHLOW:
		return "HIGHLOW"
	case IMAGE_REL_BASED_HIGHADJ:
		return "HIGHADJ"
	case IMAGE_REL_BASED_MIPS_JMPADDR:
		return "MIPS_JMPADDR/ARM_MOV32"
	case IMAGE_REL_BASED_THUMB_MOV32:
		return "THUMB_MOV32"
	case IMAGE_REL_BASED_MIPS_JMPADDR16:
		return "MIPS_JMPADDR16"
	case IMAGE_REL_BASED_DIR64:
		return "DIR64"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", relocType)
	}
}
