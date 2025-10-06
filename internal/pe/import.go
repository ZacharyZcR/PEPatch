package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
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
	iatInfo, err := im.buildCompleteImportData(newSection, existingData, dllName, functions)
	if err != nil {
		return err
	}

	// Update Import Directory and IAT Directory in Optional Header.
	if err := im.updateImportDirectory(newSection.VirtualAddress, dataSize, iatInfo); err != nil {
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
	Name        string
	Ordinal     uint16
	IsByOrdinal bool
	Hint        uint16
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
	ptrSize := im.getPtrSize(is64bit)
	ordinalFlag := im.getOrdinalFlag(is64bit)

	for len(entries) < 10000 {
		thunkData, err := im.readThunkValue(offset, is64bit)
		if err != nil || thunkData == 0 {
			break
		}

		entries = append(entries, thunkData)
		fn := im.parseImportFunction(thunkData, ordinalFlag)
		functions = append(functions, fn)

		offset += ptrSize
	}

	return entries, functions, nil
}

// readThunkValue reads a single thunk value from file.
func (im *ImportModifier) readThunkValue(offset uint32, is64bit bool) (uint64, error) {
	size := 4
	if is64bit {
		size = 8
	}

	buf := make([]byte, size)
	_, err := im.patcher.file.ReadAt(buf, int64(offset))
	if err != nil {
		return 0, err
	}

	if is64bit {
		return binary.LittleEndian.Uint64(buf), nil
	}
	return uint64(binary.LittleEndian.Uint32(buf)), nil
}

// parseImportFunction parses function information from thunk data.
func (im *ImportModifier) parseImportFunction(thunkData, ordinalFlag uint64) ImportFunction {
	var fn ImportFunction

	if thunkData&ordinalFlag != 0 {
		fn.IsByOrdinal = true
		fn.Ordinal = uint16(thunkData & 0xFFFF)
	} else {
		nameRVA := uint32(thunkData)
		nameOffset, err := im.rvaToOffset(nameRVA)
		if err != nil {
			return fn
		}

		hintBuf := make([]byte, 2)
		if _, err := im.patcher.file.ReadAt(hintBuf, int64(nameOffset)); err == nil {
			fn.Hint = binary.LittleEndian.Uint16(hintBuf)
		}

		if name, err := im.readStringAtOffset(nameOffset + 2); err == nil {
			fn.Name = name
		}
	}

	return fn
}

// getOrdinalFlag returns the ordinal flag based on architecture.
func (im *ImportModifier) getOrdinalFlag(is64bit bool) uint64 {
	if is64bit {
		return 0x8000000000000000
	}
	return 0x80000000
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
		size += uint32(len(imp.INT)+1) * ptrSize // INT
		size += uint32(len(imp.IAT)+1) * ptrSize // IAT
	}
	size += (uint32(len(newFunctions)) + 1) * ptrSize * 2 // New INT + IAT

	// DLL names.
	for _, imp := range existing {
		size += uint32(len(imp.DLLName)) + 1
	}
	size += uint32(len(newDLL)) + 1

	// Function names for existing imports.
	for _, imp := range existing {
		for _, fn := range imp.Functions {
			if !fn.IsByOrdinal {
				size += 2 + uint32(len(fn.Name)) + 1 // hint + name + null
			}
		}
	}

	// Function names for new import.
	for _, fn := range newFunctions {
		size += 2 + uint32(len(fn)) + 1
	}

	// Align to 16 bytes.
	size = alignUp(size, 16)

	return size
}

// importDataLayout holds offset information for import table layout.
type importDataLayout struct {
	descriptorsOffset   uint32
	intOffsets          []uint32
	iatOffsets          []uint32
	dllNameOffsets      []uint32
	funcNameOffsets     [][]uint32 // [dllIndex][funcIndex]
	newINTOffset        uint32
	newIATOffset        uint32
	newDLLNameOffset    uint32
	newFuncNameOffsets  []uint32
}

// IATInfo holds IAT directory information.
type IATInfo struct {
	RVA  uint32
	Size uint32
}

// buildCompleteImportData builds the complete import table preserving all existing imports.
func (im *ImportModifier) buildCompleteImportData(section *pe.Section, existing []ExistingImportData, newDLL string, newFunctions []string) (IATInfo, error) {
	is64bit := im.is64Bit()
	ptrSize := im.getPtrSize(is64bit)

	// Calculate layout and allocate buffer.
	dataSize := im.calculateCompleteImportDataSize(existing, newDLL, newFunctions)
	data := make([]byte, dataSize)
	layout := im.calculateLayout(existing, newDLL, newFunctions, ptrSize)

	baseRVA := section.VirtualAddress

	// Write all components.
	im.writeDescriptors(data, &layout, existing, baseRVA, newDLL)
	im.writeThunks(data, &layout, existing, newFunctions, baseRVA, is64bit, ptrSize)
	im.writeStrings(data, &layout, existing, newDLL, newFunctions)

	// Write to file.
	_, err := im.patcher.file.WriteAt(data, int64(section.Offset))
	if err != nil {
		return IATInfo{}, fmt.Errorf("写入完整导入数据失败: %w", err)
	}

	// Calculate IAT info for Data Directory.
	iatInfo := im.calculateIATInfo(baseRVA, &layout, existing, newFunctions, ptrSize)
	return iatInfo, nil
}

// calculateIATInfo computes IAT directory information.
func (im *ImportModifier) calculateIATInfo(baseRVA uint32, layout *importDataLayout, existing []ExistingImportData, newFunctions []string, ptrSize uint32) IATInfo {
	// IAT starts at the first IAT table.
	var iatStartRVA uint32
	if len(existing) > 0 {
		iatStartRVA = baseRVA + layout.iatOffsets[0]
	} else {
		iatStartRVA = baseRVA + layout.newIATOffset
	}

	// Calculate total IAT size.
	var iatTotalSize uint32
	for _, imp := range existing {
		iatTotalSize += uint32(len(imp.IAT)+1) * ptrSize
	}
	iatTotalSize += (uint32(len(newFunctions)) + 1) * ptrSize

	return IATInfo{
		RVA:  iatStartRVA,
		Size: iatTotalSize,
	}
}

// calculateLayout computes offset layout for all import data components.
func (im *ImportModifier) calculateLayout(existing []ExistingImportData, newDLL string, newFunctions []string, ptrSize uint32) importDataLayout {
	layout := importDataLayout{
		intOffsets:         make([]uint32, len(existing)),
		iatOffsets:         make([]uint32, len(existing)),
		dllNameOffsets:     make([]uint32, len(existing)),
		funcNameOffsets:    make([][]uint32, len(existing)),
		newFuncNameOffsets: make([]uint32, len(newFunctions)),
	}

	offset := uint32(0)

	// Descriptors.
	layout.descriptorsOffset = offset
	numDescriptors := len(existing) + 1
	offset += uint32((numDescriptors + 1) * 20)

	// INT/IAT for existing + new.
	for i, imp := range existing {
		layout.intOffsets[i] = offset
		offset += uint32(len(imp.INT)+1) * ptrSize
		layout.iatOffsets[i] = offset
		offset += uint32(len(imp.IAT)+1) * ptrSize
	}
	layout.newINTOffset = offset
	offset += (uint32(len(newFunctions)) + 1) * ptrSize
	layout.newIATOffset = offset
	offset += (uint32(len(newFunctions)) + 1) * ptrSize

	// DLL names.
	for i, imp := range existing {
		layout.dllNameOffsets[i] = offset
		offset += uint32(len(imp.DLLName)) + 1
	}
	layout.newDLLNameOffset = offset
	offset += uint32(len(newDLL)) + 1

	// Function names for existing imports.
	for i, imp := range existing {
		layout.funcNameOffsets[i] = make([]uint32, len(imp.Functions))
		for j, fn := range imp.Functions {
			if !fn.IsByOrdinal {
				layout.funcNameOffsets[i][j] = offset
				offset += 2 + uint32(len(fn.Name)) + 1 // hint + name + null
			}
		}
	}

	// Function names for new import.
	for i, fn := range newFunctions {
		layout.newFuncNameOffsets[i] = offset
		offset += 2 + uint32(len(fn)) + 1
	}

	return layout
}

// writeDescriptors writes import descriptors to data buffer.
func (im *ImportModifier) writeDescriptors(data []byte, layout *importDataLayout, existing []ExistingImportData, baseRVA uint32, newDLL string) {
	for i := range existing {
		desc := ImportDescriptor{
			OriginalFirstThunk: baseRVA + layout.intOffsets[i],
			TimeDateStamp:      0,
			ForwarderChain:     0,
			Name:               baseRVA + layout.dllNameOffsets[i],
			FirstThunk:         baseRVA + layout.iatOffsets[i],
		}
		encodeDescriptor(data[layout.descriptorsOffset+uint32(i*20):], desc)
	}

	newDesc := ImportDescriptor{
		OriginalFirstThunk: baseRVA + layout.newINTOffset,
		TimeDateStamp:      0,
		ForwarderChain:     0,
		Name:               baseRVA + layout.newDLLNameOffset,
		FirstThunk:         baseRVA + layout.newIATOffset,
	}
	encodeDescriptor(data[layout.descriptorsOffset+uint32(len(existing)*20):], newDesc)
}

// writeThunks writes INT and IAT thunks to data buffer.
func (im *ImportModifier) writeThunks(data []byte, layout *importDataLayout, existing []ExistingImportData, newFunctions []string, baseRVA uint32, is64bit bool, ptrSize uint32) {
	ordinalFlag := im.getOrdinalFlag(is64bit)

	// Write existing imports with updated RVAs.
	for i, imp := range existing {
		for j, fn := range imp.Functions {
			var thunkValue uint64
			if fn.IsByOrdinal {
				thunkValue = ordinalFlag | uint64(fn.Ordinal)
			} else {
				// Point to new function name location.
				thunkValue = uint64(baseRVA + layout.funcNameOffsets[i][j])
			}

			intPos := layout.intOffsets[i] + uint32(j)*ptrSize
			iatPos := layout.iatOffsets[i] + uint32(j)*ptrSize
			im.writeThunkEntry(data, intPos, thunkValue, is64bit)
			im.writeThunkEntry(data, iatPos, thunkValue, is64bit)
		}
	}

	// Write new import.
	for i := range newFunctions {
		nameRVA := baseRVA + layout.newFuncNameOffsets[i]
		im.writeThunkEntry(data, layout.newINTOffset+uint32(i)*ptrSize, uint64(nameRVA), is64bit)
		im.writeThunkEntry(data, layout.newIATOffset+uint32(i)*ptrSize, uint64(nameRVA), is64bit)
	}
}

// writeStrings writes DLL and function names to data buffer.
func (im *ImportModifier) writeStrings(data []byte, layout *importDataLayout, existing []ExistingImportData, newDLL string, newFunctions []string) {
	// Write DLL names.
	for i, imp := range existing {
		pos := layout.dllNameOffsets[i]
		copy(data[pos:], imp.DLLName)
		data[pos+uint32(len(imp.DLLName))] = 0
	}
	copy(data[layout.newDLLNameOffset:], newDLL)
	data[layout.newDLLNameOffset+uint32(len(newDLL))] = 0

	// Write function names for existing imports.
	for i, imp := range existing {
		for j, fn := range imp.Functions {
			if !fn.IsByOrdinal {
				pos := layout.funcNameOffsets[i][j]
				binary.LittleEndian.PutUint16(data[pos:], fn.Hint)
				copy(data[pos+2:], fn.Name)
				data[pos+2+uint32(len(fn.Name))] = 0
			}
		}
	}

	// Write function names for new import.
	for i := range newFunctions {
		pos := layout.newFuncNameOffsets[i]
		fn := newFunctions[i]
		binary.LittleEndian.PutUint16(data[pos:], 0)
		copy(data[pos+2:], fn)
		data[pos+2+uint32(len(fn))] = 0
	}
}

// Helper functions.
func (im *ImportModifier) is64Bit() bool {
	_, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64)
	return ok
}

func (im *ImportModifier) getPtrSize(is64bit bool) uint32 {
	if is64bit {
		return 8
	}
	return 4
}

func (im *ImportModifier) writeThunkArray(data []byte, baseOffset uint32, thunks []uint64, is64bit bool, ptrSize uint32) {
	for j, thunk := range thunks {
		pos := baseOffset + uint32(j)*ptrSize
		im.writeThunkEntry(data, pos, thunk, is64bit)
	}
}

func (im *ImportModifier) writeThunkEntry(data []byte, pos uint32, value uint64, is64bit bool) {
	if is64bit {
		binary.LittleEndian.PutUint64(data[pos:], value)
	} else {
		binary.LittleEndian.PutUint32(data[pos:], uint32(value))
	}
}

// encodeDescriptor encodes an ImportDescriptor to bytes.
func encodeDescriptor(buf []byte, desc ImportDescriptor) {
	binary.LittleEndian.PutUint32(buf[0:4], desc.OriginalFirstThunk)
	binary.LittleEndian.PutUint32(buf[4:8], desc.TimeDateStamp)
	binary.LittleEndian.PutUint32(buf[8:12], desc.ForwarderChain)
	binary.LittleEndian.PutUint32(buf[12:16], desc.Name)
	binary.LittleEndian.PutUint32(buf[16:20], desc.FirstThunk)
}

// updateImportDirectory updates the Import Directory and IAT Directory in Optional Header.
func (im *ImportModifier) updateImportDirectory(rva, size uint32, iatInfo IATInfo) error {
	// Calculate offset to Data Directory in Optional Header.
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

	// Update Import Directory (index 1).
	importDirOffset := dataDirOffset + (1 * 8)
	dirData := make([]byte, 8)
	binary.LittleEndian.PutUint32(dirData[0:4], rva)
	binary.LittleEndian.PutUint32(dirData[4:8], size)
	_, err = im.patcher.file.WriteAt(dirData, importDirOffset)
	if err != nil {
		return fmt.Errorf("更新导入目录失败: %w", err)
	}

	// Update IAT Directory (index 12).
	iatDirOffset := dataDirOffset + (12 * 8)
	binary.LittleEndian.PutUint32(dirData[0:4], iatInfo.RVA)
	binary.LittleEndian.PutUint32(dirData[4:8], iatInfo.Size)
	_, err = im.patcher.file.WriteAt(dirData, iatDirOffset)
	if err != nil {
		return fmt.Errorf("更新IAT目录失败: %w", err)
	}

	// Clear Bound Import Directory (index 11) if present.
	// Bound imports cache function addresses, which are now invalid.
	boundDirOffset := dataDirOffset + (11 * 8)
	binary.LittleEndian.PutUint32(dirData[0:4], 0)
	binary.LittleEndian.PutUint32(dirData[4:8], 0)
	_, err = im.patcher.file.WriteAt(dirData, boundDirOffset)
	if err != nil {
		return fmt.Errorf("清除Bound Import目录失败: %w", err)
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

	is64bit := im.is64Bit()
	_, importFuncs, err := im.readImportThunks(desc.OriginalFirstThunk, is64bit)
	if err != nil {
		return nil, err
	}

	return im.formatFunctionList(importFuncs), nil
}

// formatFunctionList converts ImportFunction slice to string slice.
func (im *ImportModifier) formatFunctionList(funcs []ImportFunction) []string {
	result := make([]string, len(funcs))
	for i, fn := range funcs {
		if fn.IsByOrdinal {
			result[i] = fmt.Sprintf("Ordinal_%d", fn.Ordinal)
		} else {
			result[i] = fn.Name
		}
	}
	return result
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
