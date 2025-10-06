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

	// Find or create space for new import data.
	// For simplicity, we'll use a new section.
	newSectionName := ".idata2"
	dataSize := im.calculateImportDataSize(dllName, functions, len(descriptors)+1)

	// Create new section for import data.
	err = im.patcher.InjectSection(newSectionName, make([]byte, dataSize),
		pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE)
	if err != nil {
		return fmt.Errorf("创建导入数据节区失败: %w", err)
	}

	// Get the new section.
	sections := im.patcher.File().Sections
	newSection := sections[len(sections)-1]

	// Build new import data in the section.
	if err := im.buildImportData(newSection, dllName, functions, descriptors); err != nil {
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

// buildImportData builds the complete import data structure.
func (im *ImportModifier) buildImportData(section *pe.Section, dllName string, functions []string, existingDescriptors []ImportDescriptor) error {
	// This is a simplified implementation.
	// A full implementation would need to:
	// 1. Copy existing import descriptors
	// 2. Add new descriptor
	// 3. Build INT and IAT
	// 4. Write all strings
	// 5. Update all RVAs

	// For now, return not implemented.
	return fmt.Errorf("Import Table修改功能正在开发中")
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

	// Import Directory is at offset 96 in Optional Header (for both PE32 and PE32+).
	importDirOffset := peHeaderOffset + 4 + 20 + 96

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
