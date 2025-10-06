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
// Universal compatible solution: Rebuilds descriptor table + INT in new section,
// but preserves ALL original IAT RVAs (critical for Go and other languages).
func (im *ImportModifier) AddImport(dllName string, functions []string) error {
	// Read existing import data.
	importDir, err := im.getImportDirectory()
	if err != nil {
		return err
	}

	descriptors, err := im.readImportDescriptors(importDir)
	if err != nil {
		return err
	}

	// Check if DLL already exists.
	for _, desc := range descriptors {
		existingName, _ := im.readString(desc.Name)
		if existingName == dllName {
			return fmt.Errorf("DLL %s 已存在于导入表中", dllName)
		}
	}

	// Read all existing import data (we need INT data for rebuilding).
	existingImports, err := im.readAllImportData(descriptors)
	if err != nil {
		return fmt.Errorf("读取现有导入数据失败: %w", err)
	}

	// Get original IAT Directory.
	var origIATDir pe.DataDirectory
	if oh32, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 12 {
			origIATDir = oh32.DataDirectory[12]
		}
	} else if oh64, ok := im.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		if len(oh64.DataDirectory) > 12 {
			origIATDir = oh64.DataDirectory[12]
		}
	}

	// Calculate size for new import section (descriptors + INT + strings).
	// Note: We don't include IAT here, we'll preserve original IATs.
	dataSize := im.calculateCompatibleImportDataSize(existingImports, dllName, functions)

	// Create new section.
	newSectionName := ".idata2"
	err = im.patcher.InjectSection(newSectionName, make([]byte, dataSize),
		pe.IMAGE_SCN_CNT_INITIALIZED_DATA|pe.IMAGE_SCN_MEM_READ|pe.IMAGE_SCN_MEM_WRITE)
	if err != nil {
		return fmt.Errorf("创建导入数据节区失败: %w", err)
	}

	if err := im.patcher.Reload(); err != nil {
		return fmt.Errorf("重新加载PE文件失败: %w", err)
	}

	sections := im.patcher.File().Sections
	newSection := sections[len(sections)-1]

	// Build import data in new section, preserving original IAT RVAs.
	newIATInfo, err := im.buildCompatibleImportData(newSection, existingImports, dllName, functions)
	if err != nil {
		return err
	}

	// Calculate new IAT Directory info.
	var iatInfo IATInfo
	if origIATDir.VirtualAddress != 0 {
		// Preserve original IAT RVA, extend size to include new IAT.
		iatInfo.RVA = origIATDir.VirtualAddress
		iatInfo.Size = origIATDir.Size + newIATInfo.Size
	} else {
		// No original IAT Directory, use new IAT.
		iatInfo = newIATInfo
	}

	// Update Import Directory to point to new section.
	descriptorTableSize := uint32((len(existingImports) + 2) * 20) // existing + new + null
	if err := im.updateImportDirectoryInPlace(newSection.VirtualAddress, descriptorTableSize, iatInfo); err != nil {
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

// calculateCompatibleImportDataSize calculates size for compatible mode.
// Includes: descriptors + INT (for all imports) + IAT (for new import only) + strings.
func (im *ImportModifier) calculateCompatibleImportDataSize(existing []ExistingImportData, newDLL string, newFunctions []string) uint32 {
	is64bit := im.is64Bit()
	ptrSize := uint32(4)
	if is64bit {
		ptrSize = 8
	}

	size := uint32(0)

	// Descriptors: existing + new + null.
	size += uint32((len(existing) + 2) * 20)

	// INT for all imports (existing + new).
	for _, imp := range existing {
		size += uint32(len(imp.Functions)+1) * ptrSize
	}
	size += (uint32(len(newFunctions)) + 1) * ptrSize

	// IAT only for new import (existing IATs stay at original locations).
	size += (uint32(len(newFunctions)) + 1) * ptrSize

	// DLL names.
	for _, imp := range existing {
		size += uint32(len(imp.DLLName)) + 1
	}
	size += uint32(len(newDLL)) + 1

	// Function names.
	for _, imp := range existing {
		for _, fn := range imp.Functions {
			if !fn.IsByOrdinal {
				size += 2 + uint32(len(fn.Name)) + 1
			}
		}
	}
	for _, fn := range newFunctions {
		size += 2 + uint32(len(fn)) + 1
	}

	size = alignUp(size, 16)
	return size
}

// importDataOffsets holds calculated offsets for import data layout.
type importDataOffsets struct {
	intOffsets         []uint32
	newINTOffset       uint32
	newIATOffset       uint32
	dllNameOffsets     []uint32
	newDLLNameOffset   uint32
	funcNameOffsets    [][]uint32
	newFuncNameOffsets []uint32
}

// calculateImportOffsets calculates all offsets for import data layout.
func (im *ImportModifier) calculateImportOffsets(existing []ExistingImportData, newDLL string, newFunctions []string, ptrSize uint32) *importDataOffsets {
	offsets := &importDataOffsets{}
	currentOffset := uint32((len(existing) + 2) * 20) // after descriptor table

	// INT offsets.
	offsets.intOffsets = make([]uint32, len(existing))
	for i, imp := range existing {
		offsets.intOffsets[i] = currentOffset
		currentOffset += uint32(len(imp.Functions)+1) * ptrSize
	}
	offsets.newINTOffset = currentOffset
	currentOffset += uint32(len(newFunctions)+1) * ptrSize

	// IAT offset (only for new import).
	offsets.newIATOffset = currentOffset
	currentOffset += uint32(len(newFunctions)+1) * ptrSize

	// DLL name offsets.
	offsets.dllNameOffsets = make([]uint32, len(existing))
	for i, imp := range existing {
		offsets.dllNameOffsets[i] = currentOffset
		currentOffset += uint32(len(imp.DLLName)) + 1
	}
	offsets.newDLLNameOffset = currentOffset
	currentOffset += uint32(len(newDLL)) + 1

	// Function name offsets.
	offsets.funcNameOffsets = make([][]uint32, len(existing))
	for i, imp := range existing {
		offsets.funcNameOffsets[i] = make([]uint32, len(imp.Functions))
		for j, fn := range imp.Functions {
			if !fn.IsByOrdinal {
				offsets.funcNameOffsets[i][j] = currentOffset
				currentOffset += 2 + uint32(len(fn.Name)) + 1
			}
		}
	}
	offsets.newFuncNameOffsets = make([]uint32, len(newFunctions))
	for i, fn := range newFunctions {
		offsets.newFuncNameOffsets[i] = currentOffset
		currentOffset += 2 + uint32(len(fn)) + 1
	}

	return offsets
}

// writeImportDescriptors writes all import descriptors to data buffer.
func (im *ImportModifier) writeImportDescriptors(data []byte, baseRVA uint32, existing []ExistingImportData, offsets *importDataOffsets) {
	// Write existing descriptors (with updated INT RVAs, but original IAT RVAs).
	for i, imp := range existing {
		desc := ImportDescriptor{
			OriginalFirstThunk: baseRVA + offsets.intOffsets[i],
			TimeDateStamp:      0,
			ForwarderChain:     0,
			Name:               baseRVA + offsets.dllNameOffsets[i],
			FirstThunk:         imp.Descriptor.FirstThunk, // PRESERVE ORIGINAL IAT RVA!
		}
		encodeDescriptor(data[uint32(i*20):], desc)
	}

	// Write new descriptor.
	newDesc := ImportDescriptor{
		OriginalFirstThunk: baseRVA + offsets.newINTOffset,
		TimeDateStamp:      0,
		ForwarderChain:     0,
		Name:               baseRVA + offsets.newDLLNameOffset,
		FirstThunk:         baseRVA + offsets.newIATOffset,
	}
	encodeDescriptor(data[uint32(len(existing)*20):], newDesc)
}

// writeImportThunks writes INT entries for existing and new imports.
func (im *ImportModifier) writeImportThunks(data []byte, baseRVA uint32, existing []ExistingImportData, newFunctions []string, offsets *importDataOffsets, is64bit bool, ptrSize uint32) {
	// Write INT data for existing imports.
	for i, imp := range existing {
		for j, fn := range imp.Functions {
			var thunkValue uint64
			if fn.IsByOrdinal {
				thunkValue = im.getOrdinalFlag(is64bit) | uint64(fn.Ordinal)
			} else {
				thunkValue = uint64(baseRVA + offsets.funcNameOffsets[i][j])
			}
			im.writeThunkEntry(data, offsets.intOffsets[i]+uint32(j)*ptrSize, thunkValue, is64bit)
		}
	}

	// Write INT and IAT for new import.
	for i := range newFunctions {
		nameRVA := baseRVA + offsets.newFuncNameOffsets[i]
		im.writeThunkEntry(data, offsets.newINTOffset+uint32(i)*ptrSize, uint64(nameRVA), is64bit)
		im.writeThunkEntry(data, offsets.newIATOffset+uint32(i)*ptrSize, uint64(nameRVA), is64bit)
	}
}

// writeImportNames writes DLL and function names to data buffer.
func (im *ImportModifier) writeImportNames(data []byte, existing []ExistingImportData, newDLL string, newFunctions []string, offsets *importDataOffsets) {
	// Write DLL names.
	for i, imp := range existing {
		copy(data[offsets.dllNameOffsets[i]:], imp.DLLName)
		data[offsets.dllNameOffsets[i]+uint32(len(imp.DLLName))] = 0
	}
	copy(data[offsets.newDLLNameOffset:], newDLL)
	data[offsets.newDLLNameOffset+uint32(len(newDLL))] = 0

	// Write function names.
	for i, imp := range existing {
		for j, fn := range imp.Functions {
			if !fn.IsByOrdinal {
				offset := offsets.funcNameOffsets[i][j]
				binary.LittleEndian.PutUint16(data[offset:], fn.Hint)
				copy(data[offset+2:], fn.Name)
				data[offset+2+uint32(len(fn.Name))] = 0
			}
		}
	}
	for i, fn := range newFunctions {
		offset := offsets.newFuncNameOffsets[i]
		binary.LittleEndian.PutUint16(data[offset:], 0)
		copy(data[offset+2:], fn)
		data[offset+2+uint32(len(fn))] = 0
	}
}

// buildCompatibleImportData builds import data preserving original IAT RVAs.
// Returns IATInfo for the new import only.
func (im *ImportModifier) buildCompatibleImportData(section *pe.Section, existing []ExistingImportData, newDLL string, newFunctions []string) (IATInfo, error) {
	is64bit := im.is64Bit()
	ptrSize := im.getPtrSize(is64bit)

	dataSize := im.calculateCompatibleImportDataSize(existing, newDLL, newFunctions)
	data := make([]byte, dataSize)
	baseRVA := section.VirtualAddress

	offsets := im.calculateImportOffsets(existing, newDLL, newFunctions, ptrSize)
	im.writeImportDescriptors(data, baseRVA, existing, offsets)
	im.writeImportThunks(data, baseRVA, existing, newFunctions, offsets, is64bit, ptrSize)
	im.writeImportNames(data, existing, newDLL, newFunctions, offsets)

	if _, err := im.patcher.file.WriteAt(data, int64(section.Offset)); err != nil {
		return IATInfo{}, fmt.Errorf("写入导入数据失败: %w", err)
	}

	return IATInfo{
		RVA:  baseRVA + offsets.newIATOffset,
		Size: (uint32(len(newFunctions)) + 1) * ptrSize,
	}, nil
}

// updateImportDirectoryInPlace updates data directories keeping Import Directory RVA unchanged.
func (im *ImportModifier) updateImportDirectoryInPlace(importRVA, importSize uint32, iatInfo IATInfo) error {
	// Calculate offset to Data Directory.
	dosHeader := make([]byte, 64)
	_, err := im.patcher.file.ReadAt(dosHeader, 0)
	if err != nil {
		return err
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[60:64]))
	optHeaderStart := peHeaderOffset + 4 + 20
	magicBuf := make([]byte, 2)
	_, err = im.patcher.file.ReadAt(magicBuf, optHeaderStart)
	if err != nil {
		return err
	}
	magic := binary.LittleEndian.Uint16(magicBuf)

	var dataDirOffset int64
	if magic == 0x10b { // PE32
		dataDirOffset = optHeaderStart + 96
	} else if magic == 0x20b { // PE32+
		dataDirOffset = optHeaderStart + 112
	} else {
		return fmt.Errorf("unknown PE magic: 0x%X", magic)
	}

	// Update Import Directory (index 1) - keep RVA, update Size.
	importDirOffset := dataDirOffset + (1 * 8)
	dirData := make([]byte, 8)
	binary.LittleEndian.PutUint32(dirData[0:4], importRVA)
	binary.LittleEndian.PutUint32(dirData[4:8], importSize)
	_, err = im.patcher.file.WriteAt(dirData, importDirOffset)
	if err != nil {
		return fmt.Errorf("更新导入目录失败: %w", err)
	}

	// Update IAT Directory (index 12) - keep RVA, update Size.
	iatDirOffset := dataDirOffset + (12 * 8)
	binary.LittleEndian.PutUint32(dirData[0:4], iatInfo.RVA)
	binary.LittleEndian.PutUint32(dirData[4:8], iatInfo.Size)
	_, err = im.patcher.file.WriteAt(dirData, iatDirOffset)
	if err != nil {
		return fmt.Errorf("更新IAT目录失败: %w", err)
	}

	// Don't clear other directories - keep them as-is.

	return nil
}

// IATInfo holds IAT directory information.
type IATInfo struct {
	RVA  uint32
	Size uint32
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
