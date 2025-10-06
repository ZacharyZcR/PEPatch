package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// ImportModifier handles Import Table modifications.
type ImportModifier struct {
	patcher *Patcher
}

// NewImportModifier creates a new import modifier.
func NewImportModifier(patcher *Patcher) *ImportModifier {
	return &ImportModifier{
		patcher: patcher,
	}
}

// ImportDescriptor represents IMAGE_IMPORT_DESCRIPTOR.
type ImportDescriptor struct {
	OriginalFirstThunk uint32 // RVA to Import Name Table (INT).
	TimeDateStamp      uint32 // Usually 0.
	ForwarderChain     uint32 // Usually 0.
	Name               uint32 // RVA to DLL name.
	FirstThunk         uint32 // RVA to Import Address Table (IAT).
}

// AddImport adds a new DLL import with specified functions.
// This is a complete implementation that preserves all existing imports.
func (im *ImportModifier) AddImport(dllName string, functions []string) error {
	// Find import directory.
	importDir, err := im.getImportDirectory()
	if err != nil {
		return err
	}

	// Read existing import descriptors.
	descriptors, err := im.readImportDescriptors(importDir)
	if err != nil {
		return err
	}

	// Check if DLL already imported.
	for _, desc := range descriptors {
		existingName, err := im.readString(desc.Name)
		if err != nil {
			continue
		}
		if existingName == dllName {
			return fmt.Errorf("DLL %s 已存在于导入表中", dllName)
		}
	}

	// Read all existing import data.
	existingData, err := im.readAllImportData(descriptors)
	if err != nil {
		return fmt.Errorf("读取现有导入数据失败: %w", err)
	}

	// Calculate total size for new import table.
	dataSize := im.calculateCompleteImportDataSize(existingData, dllName, functions)

	// Create new section for complete import data.
	newSectionName := ".idata2"
	err = im.patcher.InjectSection(newSectionName, make([]byte, dataSize),
		pe.IMAGE_SCN_CNT_INITIALIZED_DATA|pe.IMAGE_SCN_MEM_READ|pe.IMAGE_SCN_MEM_WRITE)
	if err != nil {
		return fmt.Errorf("创建导入数据节区失败: %w", err)
	}

	// Reload PE file to reflect the new section.
	if err := im.patcher.Reload(); err != nil {
		return fmt.Errorf("重新加载PE文件失败: %w", err)
	}

	// Get the new section.
	sections := im.patcher.File().Sections
	newSection := sections[len(sections)-1]

	// Build complete import data preserving all existing imports.
	if err := im.buildCompleteImportData(newSection, existingData, dllName, functions); err != nil {
		return err
	}

	// Update Import Directory in Optional Header.
	if err := im.updateImportDirectory(newSection.VirtualAddress, dataSize); err != nil {
		return err
	}

	return nil
}

// getImportDirectory returns the Import Table data directory.
func (im *ImportModifier) getImportDirectory() (pe.DataDirectory, error) {
	var importDir pe.DataDirectory

	if oh32, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 1 {
			importDir = oh32.DataDirectory[1] // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
		}
	} else if oh64, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		if len(oh64.DataDirectory) > 1 {
			importDir = oh64.DataDirectory[1]
		}
	} else {
		return importDir, fmt.Errorf("无法读取可选头")
	}

	if importDir.VirtualAddress == 0 {
		return importDir, fmt.Errorf("PE文件没有导入表")
	}

	return importDir, nil
}

// readImportDescriptors reads existing import descriptors.
func (im *ImportModifier) readImportDescriptors(importDir pe.DataDirectory) ([]ImportDescriptor, error) {
	var descriptors []ImportDescriptor

	// Find section containing import directory.
	offset, err := im.rvaToOffset(importDir.VirtualAddress)
	if err != nil {
		return nil, err
	}

	// Read descriptors until we hit null descriptor.
	for {
		descData := make([]byte, 20) // sizeof(IMAGE_IMPORT_DESCRIPTOR)
		_, err := im.patcher.file.ReadAt(descData, int64(offset))
		if err != nil {
			break
		}

		desc := ImportDescriptor{
			OriginalFirstThunk: binary.LittleEndian.Uint32(descData[0:4]),
			TimeDateStamp:      binary.LittleEndian.Uint32(descData[4:8]),
			ForwarderChain:     binary.LittleEndian.Uint32(descData[8:12]),
			Name:               binary.LittleEndian.Uint32(descData[12:16]),
			FirstThunk:         binary.LittleEndian.Uint32(descData[16:20]),
		}

		// Null descriptor marks end.
		if desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0 {
			break
		}

		descriptors = append(descriptors, desc)
		offset += 20
	}

	return descriptors, nil
}

// rvaToOffset converts RVA to file offset.
func (im *ImportModifier) rvaToOffset(rva uint32) (uint32, error) {
	for _, section := range im.patcher.peFile.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return rva - section.VirtualAddress + section.Offset, nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%X 不在任何节区中", rva)
}

// readString reads a null-terminated string at given RVA.
func (im *ImportModifier) readString(rva uint32) (string, error) {
	offset, err := im.rvaToOffset(rva)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	b := make([]byte, 1)

	for {
		_, err := im.patcher.file.ReadAt(b, int64(offset))
		if err != nil {
			break
		}
		if b[0] == 0 {
			break
		}
		buf.WriteByte(b[0])
		offset++
		if buf.Len() > 256 { // Sanity check.
			break
		}
	}

	return buf.String(), nil
}

// ExistingImportData stores complete data for an existing import.
type ExistingImportData struct {
	Descriptor ImportDescriptor
	DLLName    string
	INT        []uint64 // Import Name Table entries
	IAT        []uint64 // Import Address Table entries
	Functions  []ImportFunction
}

// ImportFunction represents an imported function.
type ImportFunction struct {
	Name    string
	Ordinal uint16
	IsByOrdinal bool
	Hint    uint16
}

// readAllImportData reads all existing import data for preservation.
func (im *ImportModifier) readAllImportData(descriptors []ImportDescriptor) ([]ExistingImportData, error) {
	var allData []ExistingImportData

	is64bit := false
	if _, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		is64bit = true
	}

	for _, desc := range descriptors {
		data := ExistingImportData{
			Descriptor: desc,
		}

		// Read DLL name.
		dllName, err := im.readString(desc.Name)
		if err != nil {
			continue
		}
		data.DLLName = dllName

		// Read INT and IAT.
		intEntries, functions, err := im.readImportThunks(desc.OriginalFirstThunk, is64bit)
		if err != nil {
			continue
		}
		data.INT = intEntries
		data.Functions = functions

		// Read IAT (should mirror INT initially).
		iatEntries, _, err := im.readImportThunks(desc.FirstThunk, is64bit)
		if err != nil {
			continue
		}
		data.IAT = iatEntries

		allData = append(allData, data)
	}

	return allData, nil
}

// readImportThunks reads thunk data (INT or IAT).
func (im *ImportModifier) readImportThunks(rva uint32, is64bit bool) ([]uint64, []ImportFunction, error) {
	if rva == 0 {
		return nil, nil, fmt.Errorf("invalid RVA")
	}

	offset, err := im.rvaToOffset(rva)
	if err != nil {
		return nil, nil, err
	}

	var entries []uint64
	var functions []ImportFunction

	ordinalFlag := uint64(0x80000000)
	if is64bit {
		ordinalFlag = 0x8000000000000000
	}

	for {
		var thunkData uint64
		if is64bit {
			buf := make([]byte, 8)
			_, err := im.patcher.file.ReadAt(buf, int64(offset))
			if err != nil {
				break
			}
			thunkData = binary.LittleEndian.Uint64(buf)
			offset += 8
		} else {
			buf := make([]byte, 4)
			_, err := im.patcher.file.ReadAt(buf, int64(offset))
			if err != nil {
				break
			}
			thunkData = uint64(binary.LittleEndian.Uint32(buf))
			offset += 4
		}

		if thunkData == 0 {
			break
		}

		entries = append(entries, thunkData)

		// Parse function info.
		var fn ImportFunction
		if thunkData&ordinalFlag != 0 {
			// Import by ordinal.
			fn.IsByOrdinal = true
			fn.Ordinal = uint16(thunkData & 0xFFFF)
		} else {
			// Import by name.
			nameRVA := uint32(thunkData)
			nameOffset, err := im.rvaToOffset(nameRVA)
			if err != nil {
				continue
			}

			// Read hint.
			hintBuf := make([]byte, 2)
			_, err = im.patcher.file.ReadAt(hintBuf, int64(nameOffset))
			if err == nil {
				fn.Hint = binary.LittleEndian.Uint16(hintBuf)
			}

			// Read name.
			name, err := im.readStringAtOffset(nameOffset + 2)
			if err != nil {
				continue
			}
			fn.Name = name
		}

		functions = append(functions, fn)

		if len(entries) > 10000 {
			break
		}
	}

	return entries, functions, nil
}

// calculateCompleteImportDataSize calculates total size including existing imports.
func (im *ImportModifier) calculateCompleteImportDataSize(existing []ExistingImportData, newDLL string, newFunctions []string) uint32 {
	is64bit := false
	if _, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		is64bit = true
	}

	ptrSize := uint32(4)
	if is64bit {
		ptrSize = 8
	}

	size := uint32(0)

	// Import descriptors: existing + new + null terminator.
	numDescriptors := len(existing) + 1
	size += uint32((numDescriptors + 1) * 20)

	// INT and IAT for all imports.
	for _, imp := range existing {
		size += uint32(len(imp.INT)+1) * ptrSize  // INT
		size += uint32(len(imp.IAT)+1) * ptrSize  // IAT
	}
	size += (uint32(len(newFunctions)) + 1) * ptrSize * 2 // New INT + IAT

	// DLL names.
	for _, imp := range existing {
		size += uint32(len(imp.DLLName)) + 1
	}
	size += uint32(len(newDLL)) + 1

	// Function names (only for new import - existing function names remain in original location).
	for _, fn := range newFunctions {
		size += 2 + uint32(len(fn)) + 1
	}

	// Align to 16 bytes.
	size = alignUp(size, 16)

	return size
}

// calculateImportDataSize calculates size needed for new import data.
func (im *ImportModifier) calculateImportDataSize(dllName string, functions []string, numDescriptors int) uint32 {
	size := uint32(0)

	// Import descriptors (including null terminator).
	size += uint32((numDescriptors + 1) * 20)

	// DLL name.
	size += uint32(len(dllName) + 1)

	// Function names (IMAGE_IMPORT_BY_NAME: 2 bytes hint + name + null).
	for _, fn := range functions {
		size += 2 + uint32(len(fn)) + 1
	}

	// INT and IAT (each function + null terminator).
	// For PE32+: 8 bytes per entry, PE32: 4 bytes per entry.
	is64bit := false
	if _, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		is64bit = true
	}

	entrySize := uint32(4)
	if is64bit {
		entrySize = 8
	}

	size += (uint32(len(functions)) + 1) * entrySize * 2 // INT + IAT

	// Align to 16 bytes.
	size = alignUp(size, 16)

	return size
}

// buildCompleteImportData builds the complete import table preserving all existing imports.
func (im *ImportModifier) buildCompleteImportData(section *pe.Section, existing []ExistingImportData, newDLL string, newFunctions []string) error {
	baseRVA := section.VirtualAddress

	is64bit := false
	if _, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		is64bit = true
	}

	ptrSize := uint32(4)
	if is64bit {
		ptrSize = 8
	}

	// Calculate total data size.
	dataSize := im.calculateCompleteImportDataSize(existing, newDLL, newFunctions)
	data := make([]byte, dataSize)

	// Phase 1: Layout calculation.
	offset := uint32(0)

	// Descriptors area.
	descriptorsOffset := offset
	numDescriptors := len(existing) + 1
	offset += uint32((numDescriptors + 1) * 20)

	// INT/IAT area for existing imports.
	intOffsets := make([]uint32, len(existing))
	iatOffsets := make([]uint32, len(existing))
	for i, imp := range existing {
		intOffsets[i] = offset
		offset += uint32(len(imp.INT)+1) * ptrSize

		iatOffsets[i] = offset
		offset += uint32(len(imp.IAT)+1) * ptrSize
	}

	// INT/IAT for new import.
	newINTOffset := offset
	offset += (uint32(len(newFunctions)) + 1) * ptrSize
	newIATOffset := offset
	offset += (uint32(len(newFunctions)) + 1) * ptrSize

	// Strings area: DLL names.
	dllNameOffsets := make([]uint32, len(existing))
	for i, imp := range existing {
		dllNameOffsets[i] = offset
		offset += uint32(len(imp.DLLName)) + 1
	}
	newDLLNameOffset := offset
	offset += uint32(len(newDLL)) + 1

	// Function names (only for new import - existing function names remain in original location).
	newFuncNameOffsets := make([]uint32, len(newFunctions))
	for i, fn := range newFunctions {
		newFuncNameOffsets[i] = offset
		offset += 2 + uint32(len(fn)) + 1
	}

	// Phase 2: Write descriptors.
	for i := range existing {
		desc := ImportDescriptor{
			OriginalFirstThunk: baseRVA + intOffsets[i],
			TimeDateStamp:      0,
			ForwarderChain:     0,
			Name:               baseRVA + dllNameOffsets[i],
			FirstThunk:         baseRVA + iatOffsets[i],
		}
		encodeDescriptor(data[descriptorsOffset+uint32(i*20):], desc)
	}

	// New import descriptor.
	newDesc := ImportDescriptor{
		OriginalFirstThunk: baseRVA + newINTOffset,
		TimeDateStamp:      0,
		ForwarderChain:     0,
		Name:               baseRVA + newDLLNameOffset,
		FirstThunk:         baseRVA + newIATOffset,
	}
	encodeDescriptor(data[descriptorsOffset+uint32(len(existing)*20):], newDesc)

	// Null descriptor already zero-initialized.

	// Phase 3: Write INT/IAT for existing imports (preserve original values).
	for i, imp := range existing {
		// Write INT - use original thunk values.
		for j := range imp.INT {
			pos := intOffsets[i] + uint32(j)*ptrSize
			if is64bit {
				binary.LittleEndian.PutUint64(data[pos:], imp.INT[j])
			} else {
				binary.LittleEndian.PutUint32(data[pos:], uint32(imp.INT[j]))
			}
		}
		// Null terminator already zero-initialized.

		// Write IAT - use original thunk values.
		for j := range imp.IAT {
			pos := iatOffsets[i] + uint32(j)*ptrSize
			if is64bit {
				binary.LittleEndian.PutUint64(data[pos:], imp.IAT[j])
			} else {
				binary.LittleEndian.PutUint32(data[pos:], uint32(imp.IAT[j]))
			}
		}
	}

	// Phase 4: Write INT/IAT for new import.
	for i := range newFunctions {
		nameRVA := baseRVA + newFuncNameOffsets[i]

		intPos := newINTOffset + uint32(i)*ptrSize
		iatPos := newIATOffset + uint32(i)*ptrSize

		if is64bit {
			binary.LittleEndian.PutUint64(data[intPos:], uint64(nameRVA))
			binary.LittleEndian.PutUint64(data[iatPos:], uint64(nameRVA))
		} else {
			binary.LittleEndian.PutUint32(data[intPos:], nameRVA)
			binary.LittleEndian.PutUint32(data[iatPos:], nameRVA)
		}
	}

	// Phase 5: Write DLL names.
	for i, imp := range existing {
		pos := dllNameOffsets[i]
		copy(data[pos:], imp.DLLName)
		data[pos+uint32(len(imp.DLLName))] = 0
	}
	copy(data[newDLLNameOffset:], newDLL)
	data[newDLLNameOffset+uint32(len(newDLL))] = 0

	// Phase 6: Write function names (only for new import).
	// Existing import function names remain in their original locations.
	for i, fn := range newFunctions {
		pos := newFuncNameOffsets[i]
		binary.LittleEndian.PutUint16(data[pos:], 0) // Hint = 0
		copy(data[pos+2:], fn)
		data[pos+2+uint32(len(fn))] = 0
	}

	// Write data to section.
	fileOffset := int64(section.Offset)
	_, err := im.patcher.file.WriteAt(data, fileOffset)
	if err != nil {
		return fmt.Errorf("写入完整导入数据失败: %w", err)
	}

	return nil
}

// buildImportData builds the complete import data structure (deprecated).
func (im *ImportModifier) buildImportData(section *pe.Section, dllName string, functions []string, existingDescriptors []ImportDescriptor) error {
	baseRVA := section.VirtualAddress

	is64bit := false
	if _, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		is64bit = true
	}

	ptrSize := uint32(4)
	if is64bit {
		ptrSize = 8
	}

	// Layout offsets.
	numDescriptors := len(existingDescriptors) + 1 // +1 for new DLL
	descriptorsSize := uint32((numDescriptors + 1) * 20) // +1 for null terminator

	intOffset := descriptorsSize
	iatOffset := intOffset + (uint32(len(functions)) + 1) * ptrSize

	dllNameOffset := iatOffset + (uint32(len(functions)) + 1) * ptrSize
	funcNamesOffset := dllNameOffset + uint32(len(dllName)) + 1

	// Allocate data buffer.
	dataSize := im.calculateImportDataSize(dllName, functions, numDescriptors)
	data := make([]byte, dataSize)

	// 1. Copy existing descriptors.
	for i, desc := range existingDescriptors {
		encodeDescriptor(data[i*20:(i+1)*20], desc)
	}

	// 2. Create new descriptor for our DLL.
	newDesc := ImportDescriptor{
		OriginalFirstThunk: baseRVA + intOffset,
		TimeDateStamp:      0,
		ForwarderChain:     0,
		Name:               baseRVA + dllNameOffset,
		FirstThunk:         baseRVA + iatOffset,
	}
	encodeDescriptor(data[len(existingDescriptors)*20:(len(existingDescriptors)+1)*20], newDesc)

	// 3. Null descriptor already initialized (data is zero-filled).

	// 4. Build INT and IAT.
	currentFuncNameOffset := funcNamesOffset
	for i, fn := range functions {
		// RVA to IMAGE_IMPORT_BY_NAME.
		nameRVA := baseRVA + currentFuncNameOffset

		// Write to INT.
		intPos := intOffset + uint32(i)*ptrSize
		iatPos := iatOffset + uint32(i)*ptrSize

		if is64bit {
			binary.LittleEndian.PutUint64(data[intPos:intPos+8], uint64(nameRVA))
			binary.LittleEndian.PutUint64(data[iatPos:iatPos+8], uint64(nameRVA))
		} else {
			binary.LittleEndian.PutUint32(data[intPos:intPos+4], nameRVA)
			binary.LittleEndian.PutUint32(data[iatPos:iatPos+4], nameRVA)
		}

		// Write IMAGE_IMPORT_BY_NAME (hint + name + null).
		binary.LittleEndian.PutUint16(data[currentFuncNameOffset:currentFuncNameOffset+2], 0) // Hint = 0
		copy(data[currentFuncNameOffset+2:], fn)
		data[currentFuncNameOffset+2+uint32(len(fn))] = 0 // Null terminator

		currentFuncNameOffset += 2 + uint32(len(fn)) + 1
	}

	// Null terminators for INT and IAT already initialized.

	// 5. Write DLL name.
	copy(data[dllNameOffset:], dllName)
	data[dllNameOffset+uint32(len(dllName))] = 0

	// Write data to section.
	fileOffset := int64(section.Offset)
	_, err := im.patcher.file.WriteAt(data, fileOffset)
	if err != nil {
		return fmt.Errorf("写入导入数据失败: %w", err)
	}

	return nil
}

// encodeDescriptor encodes an ImportDescriptor to bytes.
func encodeDescriptor(buf []byte, desc ImportDescriptor) {
	binary.LittleEndian.PutUint32(buf[0:4], desc.OriginalFirstThunk)
	binary.LittleEndian.PutUint32(buf[4:8], desc.TimeDateStamp)
	binary.LittleEndian.PutUint32(buf[8:12], desc.ForwarderChain)
	binary.LittleEndian.PutUint32(buf[12:16], desc.Name)
	binary.LittleEndian.PutUint32(buf[16:20], desc.FirstThunk)
}

// updateImportDirectory updates the Import Directory in Optional Header.
func (im *ImportModifier) updateImportDirectory(rva, size uint32) error {
	// Calculate offset to Import Directory entry in Optional Header.
	dosHeader := make([]byte, 64)
	_, err := im.patcher.file.ReadAt(dosHeader, 0)
	if err != nil {
		return err
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[60:64]))

	// Determine if PE32 or PE32+.
	optHeaderStart := peHeaderOffset + 4 + 20
	magicBuf := make([]byte, 2)
	_, err = im.patcher.file.ReadAt(magicBuf, optHeaderStart)
	if err != nil {
		return err
	}
	magic := binary.LittleEndian.Uint16(magicBuf)

	// Data Directory starts at different offsets:
	// PE32 (0x10b): offset 96
	// PE32+ (0x20b): offset 112
	var dataDirOffset int64
	if magic == 0x10b { // PE32
		dataDirOffset = optHeaderStart + 96
	} else if magic == 0x20b { // PE32+
		dataDirOffset = optHeaderStart + 112
	} else {
		return fmt.Errorf("unknown PE magic: 0x%X", magic)
	}

	// Import Directory is at index 1 in Data Directory array.
	importDirOffset := dataDirOffset + (1 * 8)

	// Write VirtualAddress and Size.
	dirData := make([]byte, 8)
	binary.LittleEndian.PutUint32(dirData[0:4], rva)
	binary.LittleEndian.PutUint32(dirData[4:8], size)

	_, err = im.patcher.file.WriteAt(dirData, importDirOffset)
	if err != nil {
		return fmt.Errorf("更新导入目录失败: %w", err)
	}

	return nil
}

// AddImport is a convenience method on Patcher.
func (p *Patcher) AddImport(dllName string, functions []string) error {
	modifier := NewImportModifier(p)
	return modifier.AddImport(dllName, functions)
}

// ListImports returns detailed import information.
func (p *Patcher) ListImports() ([]ImportInfo, error) {
	modifier := NewImportModifier(p)
	importDir, err := modifier.getImportDirectory()
	if err != nil {
		return nil, err
	}

	descriptors, err := modifier.readImportDescriptors(importDir)
	if err != nil {
		return nil, err
	}

	var imports []ImportInfo
	for _, desc := range descriptors {
		dllName, err := modifier.readString(desc.Name)
		if err != nil {
			continue
		}

		functions, err := modifier.readImportFunctions(desc)
		if err != nil {
			functions = []string{"(error reading functions)"}
		}

		imports = append(imports, ImportInfo{
			DLL:       dllName,
			Functions: functions,
		})
	}

	return imports, nil
}

// ListImportsFromReader returns detailed import information from a Reader.
func ListImportsFromReader(reader *Reader) ([]ImportInfo, error) {
	// Create a temporary patcher-like structure for reading.
	modifier := &ImportModifier{
		patcher: &Patcher{
			file:   reader.RawFile(),
			peFile: reader.File(),
		},
	}

	importDir, err := modifier.getImportDirectory()
	if err != nil {
		return nil, err
	}

	descriptors, err := modifier.readImportDescriptors(importDir)
	if err != nil {
		return nil, err
	}

	var imports []ImportInfo
	for _, desc := range descriptors {
		dllName, err := modifier.readString(desc.Name)
		if err != nil {
			continue
		}

		functions, err := modifier.readImportFunctions(desc)
		if err != nil {
			functions = []string{"(error reading functions)"}
		}

		imports = append(imports, ImportInfo{
			DLL:       dllName,
			Functions: functions,
		})
	}

	return imports, nil
}

// readImportFunctions reads function names from INT.
func (im *ImportModifier) readImportFunctions(desc ImportDescriptor) ([]string, error) {
	if desc.OriginalFirstThunk == 0 {
		return nil, fmt.Errorf("no INT")
	}

	offset, err := im.rvaToOffset(desc.OriginalFirstThunk)
	if err != nil {
		return nil, err
	}

	is64bit := false
	if _, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		is64bit = true
	}

	var functions []string
	for {
		var thunkData uint64
		if is64bit {
			buf := make([]byte, 8)
			_, err := im.patcher.file.ReadAt(buf, int64(offset))
			if err != nil && err != io.EOF {
				break
			}
			thunkData = binary.LittleEndian.Uint64(buf)
			offset += 8
		} else {
			buf := make([]byte, 4)
			_, err := im.patcher.file.ReadAt(buf, int64(offset))
			if err != nil && err != io.EOF {
				break
			}
			thunkData = uint64(binary.LittleEndian.Uint32(buf))
			offset += 4
		}

		if thunkData == 0 {
			break
		}

		// Check if import by ordinal.
		ordinalFlag := uint64(0x80000000)
		if is64bit {
			ordinalFlag = 0x8000000000000000
		}

		if thunkData&ordinalFlag != 0 {
			ordinal := thunkData & 0xFFFF
			functions = append(functions, fmt.Sprintf("Ordinal_%d", ordinal))
		} else {
			// Import by name - thunkData is RVA to IMAGE_IMPORT_BY_NAME.
			nameRVA := uint32(thunkData)
			nameOffset, err := im.rvaToOffset(nameRVA)
			if err != nil {
				continue
			}

			// Skip hint (2 bytes).
			nameOffset += 2

			name, err := im.readStringAtOffset(nameOffset)
			if err != nil {
				continue
			}
			functions = append(functions, name)
		}

		if len(functions) > 1000 { // Sanity check.
			break
		}
	}

	return functions, nil
}

// readStringAtOffset reads a null-terminated string at file offset.
func (im *ImportModifier) readStringAtOffset(offset uint32) (string, error) {
	var buf bytes.Buffer
	b := make([]byte, 1)

	for {
		_, err := im.patcher.file.ReadAt(b, int64(offset))
		if err != nil {
			break
		}
		if b[0] == 0 {
			break
		}
		buf.WriteByte(b[0])
		offset++
		if buf.Len() > 256 {
			break
		}
	}

	return buf.String(), nil
}
