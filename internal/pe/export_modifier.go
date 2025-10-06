package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// ExportModifier handles Export Table modifications.
type ExportModifier struct {
	patcher *Patcher
}

// NewExportModifier creates a new export modifier.
func NewExportModifier(patcher *Patcher) *ExportModifier {
	return &ExportModifier{
		patcher: patcher,
	}
}

// ExportFunction represents a single exported function.
type ExportFunction struct {
	Name    string // Function name (empty for ordinal-only exports)
	Ordinal uint16 // Ordinal number
	RVA     uint32 // Relative Virtual Address of the function
}

// ExportTableData contains the complete export table information.
type ExportTableData struct {
	ModuleName string
	Base       uint32 // Ordinal base
	Functions  []ExportFunction
}

// AddExport adds a new function to the export table.
func (em *ExportModifier) AddExport(name string, rva uint32) error {
	// Read existing exports
	exports, err := em.readExports()
	if err != nil {
		return fmt.Errorf("读取现有导出失败: %w", err)
	}

	// Check if export already exists
	for _, exp := range exports.Functions {
		if exp.Name == name {
			return fmt.Errorf("导出 %s 已存在", name)
		}
	}

	// Find next available ordinal
	maxOrdinal := uint16(0)
	for _, exp := range exports.Functions {
		if exp.Ordinal > maxOrdinal {
			maxOrdinal = exp.Ordinal
		}
	}
	newOrdinal := maxOrdinal + 1

	// Add new export
	exports.Functions = append(exports.Functions, ExportFunction{
		Name:    name,
		Ordinal: newOrdinal,
		RVA:     rva,
	})

	// Rebuild export table
	return em.rebuildExportTable(exports)
}

// ModifyExport changes the RVA of an existing export.
func (em *ExportModifier) ModifyExport(name string, newRVA uint32) error {
	exports, err := em.readExports()
	if err != nil {
		return fmt.Errorf("读取现有导出失败: %w", err)
	}

	found := false
	for i := range exports.Functions {
		if exports.Functions[i].Name == name {
			exports.Functions[i].RVA = newRVA
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("导出 %s 不存在", name)
	}

	return em.rebuildExportTable(exports)
}

// RemoveExport removes a function from the export table.
func (em *ExportModifier) RemoveExport(name string) error {
	exports, err := em.readExports()
	if err != nil {
		return fmt.Errorf("读取现有导出失败: %w", err)
	}

	newFunctions := make([]ExportFunction, 0)
	found := false
	for _, exp := range exports.Functions {
		if exp.Name != name {
			newFunctions = append(newFunctions, exp)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("导出 %s 不存在", name)
	}

	exports.Functions = newFunctions
	return em.rebuildExportTable(exports)
}

// readExports reads the current export table.
func (em *ExportModifier) readExports() (*ExportTableData, error) {
	// Get export directory
	var exportDirRVA, exportDirSize uint32
	oh := em.patcher.File().OptionalHeader

	if oh32, ok := oh.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 0 {
			exportDirRVA = oh32.DataDirectory[0].VirtualAddress
			exportDirSize = oh32.DataDirectory[0].Size
		}
	} else if oh64, ok := oh.(*pe.OptionalHeader64); ok {
		if len(oh64.DataDirectory) > 0 {
			exportDirRVA = oh64.DataDirectory[0].VirtualAddress
			exportDirSize = oh64.DataDirectory[0].Size
		}
	}

	if exportDirRVA == 0 {
		// No exports, create empty table
		return &ExportTableData{
			ModuleName: "module.dll",
			Base:       1,
			Functions:  make([]ExportFunction, 0),
		}, nil
	}

	// Read export directory
	exportData, err := em.patcher.ReadRVA(exportDirRVA, exportDirSize)
	if err != nil {
		return nil, fmt.Errorf("读取导出目录失败: %w", err)
	}

	if len(exportData) < 40 {
		return nil, fmt.Errorf("导出目录大小不足")
	}

	// Parse export directory structure
	nameRVA := binary.LittleEndian.Uint32(exportData[12:16])
	base := binary.LittleEndian.Uint32(exportData[16:20])
	numFunctions := binary.LittleEndian.Uint32(exportData[20:24])
	numNames := binary.LittleEndian.Uint32(exportData[24:28])
	addressTableRVA := binary.LittleEndian.Uint32(exportData[28:32])
	namePointerRVA := binary.LittleEndian.Uint32(exportData[32:36])
	ordinalTableRVA := binary.LittleEndian.Uint32(exportData[36:40])

	// Read module name
	nameData, err := em.patcher.ReadRVA(nameRVA, 256)
	if err != nil {
		return nil, err
	}
	moduleName := readNullTerminatedString(nameData)

	result := &ExportTableData{
		ModuleName: moduleName,
		Base:       base,
		Functions:  make([]ExportFunction, 0),
	}

	// Read address table
	addressTable, err := em.patcher.ReadRVA(addressTableRVA, numFunctions*4)
	if err != nil {
		return nil, err
	}

	// Read name pointers
	namePointers := make([]uint32, numNames)
	if numNames > 0 {
		namePointerData, err := em.patcher.ReadRVA(namePointerRVA, numNames*4)
		if err != nil {
			return nil, err
		}
		for i := uint32(0); i < numNames; i++ {
			namePointers[i] = binary.LittleEndian.Uint32(namePointerData[i*4:])
		}
	}

	// Read ordinals
	ordinals := make([]uint16, numNames)
	if numNames > 0 {
		ordinalData, err := em.patcher.ReadRVA(ordinalTableRVA, numNames*2)
		if err != nil {
			return nil, err
		}
		for i := uint32(0); i < numNames; i++ {
			ordinals[i] = binary.LittleEndian.Uint16(ordinalData[i*2:])
		}
	}

	// Build function list
	for i := uint32(0); i < numFunctions; i++ {
		rva := binary.LittleEndian.Uint32(addressTable[i*4:])
		if rva == 0 {
			continue // Skip empty slots
		}

		ordinal := uint16(base + i)

		// Find name for this ordinal
		name := ""
		for j := uint32(0); j < numNames; j++ {
			if ordinals[j] == uint16(i) {
				// Read name
				nameData, err := em.patcher.ReadRVA(namePointers[j], 256)
				if err == nil {
					name = readNullTerminatedString(nameData)
				}
				break
			}
		}

		result.Functions = append(result.Functions, ExportFunction{
			Name:    name,
			Ordinal: ordinal,
			RVA:     rva,
		})
	}

	return result, nil
}

// rebuildExportTable rebuilds the export table in a new section.
func (em *ExportModifier) rebuildExportTable(exports *ExportTableData) error {
	// Sort functions by name (Windows requirement for binary search)
	sort.Slice(exports.Functions, func(i, j int) bool {
		if exports.Functions[i].Name == "" {
			return false
		}
		if exports.Functions[j].Name == "" {
			return true
		}
		return strings.ToLower(exports.Functions[i].Name) < strings.ToLower(exports.Functions[j].Name)
	})

	// Calculate required size
	size := em.calculateExportDataSize(exports)

	// Create new export section
	sectionData := make([]byte, size)

	// Write export data
	offset := em.writeExportData(sectionData, exports)
	_ = offset

	// Inject section
	err := em.patcher.InjectSection(".edata", sectionData,
		pe.IMAGE_SCN_CNT_INITIALIZED_DATA|pe.IMAGE_SCN_MEM_READ)
	if err != nil {
		return fmt.Errorf("注入导出节区失败: %w", err)
	}

	// Reload PE
	if err := em.patcher.Reload(); err != nil {
		return fmt.Errorf("重新加载PE失败: %w", err)
	}

	// Get new section
	sections := em.patcher.File().Sections
	newSection := sections[len(sections)-1]

	// Now rewrite the export data with correct RVAs
	sectionData = make([]byte, size)
	em.writeExportDataWithRVA(sectionData, exports, newSection.VirtualAddress)

	// Write corrected data to file
	_, err = em.patcher.file.WriteAt(sectionData, int64(newSection.Offset))
	if err != nil {
		return fmt.Errorf("写入导出数据失败: %w", err)
	}

	// Update export directory pointer
	return em.updateExportDirectory(newSection.VirtualAddress, uint32(len(sectionData)))
}

// calculateExportDataSize calculates the size needed for export data.
func (em *ExportModifier) calculateExportDataSize(exports *ExportTableData) uint32 {
	size := uint32(40) // Export directory

	// Count named exports
	namedCount := 0
	for _, exp := range exports.Functions {
		if exp.Name != "" {
			namedCount++
		}
	}

	// Address table (4 bytes per function)
	size += uint32(len(exports.Functions) * 4)

	// Name pointer table
	size += uint32(namedCount * 4)

	// Ordinal table
	size += uint32(namedCount * 2)

	// Module name
	size += uint32(len(exports.ModuleName) + 1)

	// Function names
	for _, exp := range exports.Functions {
		if exp.Name != "" {
			size += uint32(len(exp.Name) + 1)
		}
	}

	// Align to 16 bytes
	size = (size + 15) &^ 15

	return size
}

// writeExportData writes the export data to a buffer (for initial size calculation).
func (em *ExportModifier) writeExportData(data []byte, exports *ExportTableData) uint32 {
	return em.writeExportDataWithRVA(data, exports, 0)
}

// writeExportDataWithRVA writes the export data to a buffer with specified section RVA.
func (em *ExportModifier) writeExportDataWithRVA(data []byte, exports *ExportTableData, sectionRVA uint32) uint32 {
	baseRVA := sectionRVA

	offset := uint32(0)

	// Reserve space for export directory (40 bytes)
	dirOffset := offset
	offset += 40

	// Calculate offsets
	addressTableOffset := offset
	addressTableRVA := baseRVA + addressTableOffset
	offset += uint32(len(exports.Functions) * 4)

	// Count named exports
	namedExports := make([]int, 0)
	for i, exp := range exports.Functions {
		if exp.Name != "" {
			namedExports = append(namedExports, i)
		}
	}

	namePointerOffset := offset
	namePointerRVA := baseRVA + namePointerOffset
	offset += uint32(len(namedExports) * 4)

	ordinalTableOffset := offset
	ordinalTableRVA := baseRVA + ordinalTableOffset
	offset += uint32(len(namedExports) * 2)

	// Write module name
	moduleNameOffset := offset
	moduleNameRVA := baseRVA + moduleNameOffset
	copy(data[offset:], exports.ModuleName)
	offset += uint32(len(exports.ModuleName) + 1)

	// Write function names and collect RVAs
	nameRVAs := make(map[int]uint32)
	for _, idx := range namedExports {
		nameRVAs[idx] = baseRVA + offset
		copy(data[offset:], exports.Functions[idx].Name)
		offset += uint32(len(exports.Functions[idx].Name) + 1)
	}

	// Write export directory
	binary.LittleEndian.PutUint32(data[dirOffset:], 0)           // Characteristics
	binary.LittleEndian.PutUint32(data[dirOffset+4:], 0)         // TimeDateStamp
	binary.LittleEndian.PutUint16(data[dirOffset+8:], 0)         // MajorVersion
	binary.LittleEndian.PutUint16(data[dirOffset+10:], 0)        // MinorVersion
	binary.LittleEndian.PutUint32(data[dirOffset+12:], moduleNameRVA)
	binary.LittleEndian.PutUint32(data[dirOffset+16:], exports.Base)
	binary.LittleEndian.PutUint32(data[dirOffset+20:], uint32(len(exports.Functions)))
	binary.LittleEndian.PutUint32(data[dirOffset+24:], uint32(len(namedExports)))
	binary.LittleEndian.PutUint32(data[dirOffset+28:], addressTableRVA)
	binary.LittleEndian.PutUint32(data[dirOffset+32:], namePointerRVA)
	binary.LittleEndian.PutUint32(data[dirOffset+36:], ordinalTableRVA)

	// Write address table
	for i, exp := range exports.Functions {
		binary.LittleEndian.PutUint32(data[addressTableOffset+uint32(i*4):], exp.RVA)
	}

	// Write name pointer table and ordinal table
	for i, idx := range namedExports {
		binary.LittleEndian.PutUint32(data[namePointerOffset+uint32(i*4):], nameRVAs[idx])

		// Ordinal is index in address table (not the actual ordinal value)
		ordinalIndex := uint16(idx)
		binary.LittleEndian.PutUint16(data[ordinalTableOffset+uint32(i*2):], ordinalIndex)
	}

	return offset
}

// updateExportDirectory updates the export directory pointer in PE header.
func (em *ExportModifier) updateExportDirectory(rva, size uint32) error {
	// Read DOS header to get PE offset
	dosHeader := make([]byte, 64)
	if _, err := em.patcher.file.ReadAt(dosHeader, 0); err != nil {
		return fmt.Errorf("读取DOS头失败: %w", err)
	}

	peOffset := binary.LittleEndian.Uint32(dosHeader[60:64])

	// Calculate data directory offset
	var dataDirOffset int64
	if em.patcher.File().Machine == 0x8664 { // x64
		dataDirOffset = int64(peOffset) + 4 + 20 + 112 // Signature + COFF + OptionalHeader offset
	} else { // x86
		dataDirOffset = int64(peOffset) + 4 + 20 + 96
	}

	// Export directory is index 0
	exportDirOffset := dataDirOffset

	// Prepare data
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data, rva)
	binary.LittleEndian.PutUint32(data[4:], size)

	// Write to file
	_, err := em.patcher.file.WriteAt(data, exportDirOffset)
	return err
}

// readNullTerminatedString reads a null-terminated string from a byte slice.
func readNullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
