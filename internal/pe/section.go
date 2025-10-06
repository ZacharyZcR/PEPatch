package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// SectionInjector handles adding new sections to PE files.
type SectionInjector struct {
	patcher *Patcher
}

// NewSectionInjector creates a new section injector.
func NewSectionInjector(patcher *Patcher) *SectionInjector {
	return &SectionInjector{
		patcher: patcher,
	}
}

// InjectSection adds a new section to the PE file.
func (s *SectionInjector) InjectSection(name string, data []byte, characteristics uint32) error {
	// Get alignment values.
	fileAlignment, sectionAlignment, err := s.getAlignments()
	if err != nil {
		return err
	}

	// Check if there's space for a new section header.
	if err := s.checkHeaderSpace(); err != nil {
		return err
	}

	// Calculate new section offsets and sizes.
	lastSection := s.patcher.peFile.Sections[len(s.patcher.peFile.Sections)-1]

	// File offset: align after last section's raw data.
	newFileOffset := alignUp(lastSection.Offset+lastSection.Size, fileAlignment)

	// Virtual address: align after last section's virtual memory.
	newVirtualAddress := alignUp(lastSection.VirtualAddress+lastSection.VirtualSize, sectionAlignment)

	// Sizes.
	rawSize := alignUp(uint32(len(data)), fileAlignment)
	virtualSize := uint32(len(data))

	// Validate section name (max 8 bytes).
	if len(name) > 8 {
		return fmt.Errorf("节区名称过长: %d 字节 (最大8字节)", len(name))
	}
	var sectionName [8]byte
	copy(sectionName[:], name)

	// Read DOS header to get PE header offset.
	dosHeader := make([]byte, 64)
	_, err = s.patcher.file.ReadAt(dosHeader, 0)
	if err != nil {
		return fmt.Errorf("读取DOS头失败: %w", err)
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[60:64]))

	// Read COFF header to get section count and optional header size.
	coffHeader := make([]byte, 20)
	_, err = s.patcher.file.ReadAt(coffHeader, peHeaderOffset+4)
	if err != nil {
		return fmt.Errorf("读取COFF头失败: %w", err)
	}

	numberOfSections := binary.LittleEndian.Uint16(coffHeader[2:4])
	optionalHeaderSize := binary.LittleEndian.Uint16(coffHeader[16:18])

	// Calculate new section header offset.
	sectionTableOffset := peHeaderOffset + 4 + 20 + int64(optionalHeaderSize)
	newSectionHeaderOffset := sectionTableOffset + int64(numberOfSections*40)

	// Create section header (40 bytes).
	sectionHeader := make([]byte, 40)
	copy(sectionHeader[0:8], sectionName[:])                              // Name.
	binary.LittleEndian.PutUint32(sectionHeader[8:12], virtualSize)       // VirtualSize.
	binary.LittleEndian.PutUint32(sectionHeader[12:16], newVirtualAddress) // VirtualAddress.
	binary.LittleEndian.PutUint32(sectionHeader[16:20], rawSize)          // SizeOfRawData.
	binary.LittleEndian.PutUint32(sectionHeader[20:24], newFileOffset)    // PointerToRawData.
	binary.LittleEndian.PutUint32(sectionHeader[24:28], 0)                // PointerToRelocations.
	binary.LittleEndian.PutUint32(sectionHeader[28:32], 0)                // PointerToLinenumbers.
	binary.LittleEndian.PutUint16(sectionHeader[32:34], 0)                // NumberOfRelocations.
	binary.LittleEndian.PutUint16(sectionHeader[34:36], 0)                // NumberOfLinenumbers.
	binary.LittleEndian.PutUint32(sectionHeader[36:40], characteristics)  // Characteristics.

	// Write section header.
	_, err = s.patcher.file.WriteAt(sectionHeader, newSectionHeaderOffset)
	if err != nil {
		return fmt.Errorf("写入节区头失败: %w", err)
	}

	// Prepare section data (aligned).
	alignedData := make([]byte, rawSize)
	copy(alignedData, data)

	// Write section data.
	_, err = s.patcher.file.WriteAt(alignedData, int64(newFileOffset))
	if err != nil {
		return fmt.Errorf("写入节区数据失败: %w", err)
	}

	// Update NumberOfSections in COFF header.
	newNumberOfSections := numberOfSections + 1
	binary.LittleEndian.PutUint16(coffHeader[2:4], newNumberOfSections)
	_, err = s.patcher.file.WriteAt(coffHeader[2:4], peHeaderOffset+4+2)
	if err != nil {
		return fmt.Errorf("更新节区数量失败: %w", err)
	}

	// Update SizeOfImage in Optional Header.
	newSizeOfImage := newVirtualAddress + alignUp(virtualSize, sectionAlignment)
	if err := s.updateSizeOfImage(peHeaderOffset, newSizeOfImage); err != nil {
		return err
	}

	return nil
}

// getAlignments returns FileAlignment and SectionAlignment from Optional Header.
func (s *SectionInjector) getAlignments() (uint32, uint32, error) {
	if oh32, ok := s.patcher.peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
		return oh32.FileAlignment, oh32.SectionAlignment, nil
	} else if oh64, ok := s.patcher.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		return oh64.FileAlignment, oh64.SectionAlignment, nil
	}
	return 0, 0, fmt.Errorf("无法读取对齐值")
}

// checkHeaderSpace verifies there's space for a new section header.
func (s *SectionInjector) checkHeaderSpace() error {
	// Read DOS header.
	dosHeader := make([]byte, 64)
	_, err := s.patcher.file.ReadAt(dosHeader, 0)
	if err != nil {
		return fmt.Errorf("读取DOS头失败: %w", err)
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[60:64]))

	// Read COFF header.
	coffHeader := make([]byte, 20)
	_, err = s.patcher.file.ReadAt(coffHeader, peHeaderOffset+4)
	if err != nil {
		return fmt.Errorf("读取COFF头失败: %w", err)
	}

	numberOfSections := binary.LittleEndian.Uint16(coffHeader[2:4])
	optionalHeaderSize := binary.LittleEndian.Uint16(coffHeader[16:18])

	// Calculate where new section header would be.
	sectionTableOffset := peHeaderOffset + 4 + 20 + int64(optionalHeaderSize)
	newSectionHeaderEnd := sectionTableOffset + int64((numberOfSections+1)*40)

	// Check against first section's file offset.
	firstSection := s.patcher.peFile.Sections[0]
	if newSectionHeaderEnd > int64(firstSection.Offset) {
		return fmt.Errorf("节区头表空间不足，无法添加新节区")
	}

	return nil
}

// updateSizeOfImage updates the SizeOfImage field in Optional Header.
func (s *SectionInjector) updateSizeOfImage(peHeaderOffset int64, newSize uint32) error {
	// SizeOfImage offset in Optional Header.
	// PE32: offset 56, PE32+: offset 56.
	sizeOfImageOffset := peHeaderOffset + 4 + 20 + 56

	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, newSize)

	_, err := s.patcher.file.WriteAt(sizeBytes, sizeOfImageOffset)
	if err != nil {
		return fmt.Errorf("更新SizeOfImage失败: %w", err)
	}

	return nil
}

// alignUp aligns a value up to the nearest multiple of alignment.
func alignUp(value, alignment uint32) uint32 {
	if alignment == 0 {
		return value
	}
	return ((value + alignment - 1) / alignment) * alignment
}

// InjectSection is a convenience method on Patcher.
func (p *Patcher) InjectSection(name string, data []byte, characteristics uint32) error {
	injector := NewSectionInjector(p)
	return injector.InjectSection(name, data, characteristics)
}

// GetSectionCharacteristics returns common section characteristics.
type SectionCharacteristics struct {
	Code             uint32 // Executable code section.
	InitializedData  uint32 // Initialized data section.
	UninitializedData uint32 // Uninitialized data section.
	ReadOnly         uint32 // Read-only section.
	ReadWrite        uint32 // Read-write section.
	ReadExecute      uint32 // Read-execute section.
	ReadWriteExecute uint32 // Read-write-execute section.
}

// CommonCharacteristics provides commonly used section characteristics.
var CommonCharacteristics = SectionCharacteristics{
	Code:             pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE,
	InitializedData:  pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ,
	ReadOnly:         pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ,
	ReadWrite:        pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE,
	ReadExecute:      pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_EXECUTE,
	ReadWriteExecute: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE | pe.IMAGE_SCN_MEM_EXECUTE,
}

// ExtendFileSize extends the file to accommodate new sections.
func (p *Patcher) ExtendFileSize(newSize int64) error {
	// Seek to new size - 1.
	_, err := p.file.Seek(newSize-1, io.SeekStart)
	if err != nil {
		return fmt.Errorf("扩展文件失败: %w", err)
	}

	// Write a single byte to extend file.
	_, err = p.file.Write([]byte{0})
	if err != nil {
		return fmt.Errorf("扩展文件失败: %w", err)
	}

	return nil
}
