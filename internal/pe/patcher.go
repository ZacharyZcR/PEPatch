package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

// Patcher handles PE file modifications.
type Patcher struct {
	filepath string
	file     *os.File
	peFile   *pe.File
	filesize int64
}

// NewPatcher creates a new PE patcher for the given file.
func NewPatcher(filepath string) (*Patcher, error) {
	file, err := os.OpenFile(filepath, os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}

	peFile, err := pe.NewFile(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("解析PE文件失败: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("获取文件信息失败: %w", err)
	}

	return &Patcher{
		filepath: filepath,
		file:     file,
		peFile:   peFile,
		filesize: stat.Size(),
	}, nil
}

// Close closes the patcher and releases resources.
func (p *Patcher) Close() error {
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

// PatchSectionPermissions modifies section characteristics (permissions).
func (p *Patcher) PatchSectionPermissions(sectionName string, newPerms uint32) error {
	// Find section
	var section *pe.Section
	for _, s := range p.peFile.Sections {
		if s.Name == sectionName {
			section = s
			break
		}
	}

	if section == nil {
		return fmt.Errorf("未找到节区: %s", sectionName)
	}

	// Read DOS header to get e_lfanew
	dosHeader := make([]byte, 64)
	_, err := p.file.ReadAt(dosHeader, 0)
	if err != nil {
		return fmt.Errorf("读取DOS头失败: %w", err)
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[60:64]))

	// Calculate section table offset
	// PE Header = Signature(4) + COFF Header(20) + Optional Header
	// Read actual optional header size from COFF header
	coffHeader := make([]byte, 20)
	_, err = p.file.ReadAt(coffHeader, peHeaderOffset+4)
	if err != nil {
		return fmt.Errorf("读取COFF头失败: %w", err)
	}
	optionalHeaderSize := binary.LittleEndian.Uint16(coffHeader[16:18])

	sectionTableOffset := peHeaderOffset + 4 + 20 + int64(optionalHeaderSize)

	// Find section index
	sectionIndex := -1
	for i, s := range p.peFile.Sections {
		if s.Name == sectionName {
			sectionIndex = i
			break
		}
	}

	// Section header is 40 bytes
	sectionHeaderOffset := sectionTableOffset + int64(sectionIndex*40)

	// Characteristics field is at offset 36 in section header
	characteristicsOffset := sectionHeaderOffset + 36

	// Write new characteristics
	newChars := make([]byte, 4)
	binary.LittleEndian.PutUint32(newChars, newPerms)

	_, err = p.file.WriteAt(newChars, characteristicsOffset)
	if err != nil {
		return fmt.Errorf("写入节区特征失败: %w", err)
	}

	return nil
}

// UpdateChecksum recalculates and updates the PE checksum.
func (p *Patcher) UpdateChecksum() error {
	// Read DOS header to get e_lfanew
	dosHeader := make([]byte, 64)
	_, err := p.file.ReadAt(dosHeader, 0)
	if err != nil {
		return fmt.Errorf("读取DOS头失败: %w", err)
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[60:64]))

	// Checksum offset: e_lfanew + Signature(4) + COFF(20) + CheckSum field(64)
	checksumOffset := peHeaderOffset + 4 + 20 + 64

	// Calculate new checksum
	newChecksum, err := CalculatePEChecksum(p.file, p.filesize, checksumOffset)
	if err != nil {
		return fmt.Errorf("计算校验和失败: %w", err)
	}

	// Write new checksum
	checksumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksumBytes, newChecksum)

	_, err = p.file.WriteAt(checksumBytes, checksumOffset)
	if err != nil {
		return fmt.Errorf("写入校验和失败: %w", err)
	}

	return nil
}

// RemoveSectionWritePermission removes WRITE permission from a section (security hardening).
func (p *Patcher) RemoveSectionWritePermission(sectionName string) error {
	// Find current section
	var section *pe.Section
	for _, s := range p.peFile.Sections {
		if s.Name == sectionName {
			section = s
			break
		}
	}

	if section == nil {
		return fmt.Errorf("未找到节区: %s", sectionName)
	}

	// Remove WRITE flag
	newPerms := section.Characteristics &^ pe.IMAGE_SCN_MEM_WRITE

	return p.PatchSectionPermissions(sectionName, newPerms)
}

// SetSectionPermissions sets exact permissions for a section.
func (p *Patcher) SetSectionPermissions(sectionName string, read, write, execute bool) error {
	var perms uint32

	if read {
		perms |= pe.IMAGE_SCN_MEM_READ
	}
	if write {
		perms |= pe.IMAGE_SCN_MEM_WRITE
	}
	if execute {
		perms |= pe.IMAGE_SCN_MEM_EXECUTE
	}

	// Also set CNT_CODE or CNT_INITIALIZED_DATA based on execute flag
	if execute {
		perms |= pe.IMAGE_SCN_CNT_CODE
	} else {
		perms |= pe.IMAGE_SCN_CNT_INITIALIZED_DATA
	}

	return p.PatchSectionPermissions(sectionName, perms)
}

// PatchEntryPoint modifies the PE entry point address.
func (p *Patcher) PatchEntryPoint(newEntryPoint uint32) error {
	// Read DOS header to get e_lfanew
	dosHeader := make([]byte, 64)
	_, err := p.file.ReadAt(dosHeader, 0)
	if err != nil {
		return fmt.Errorf("读取DOS头失败: %w", err)
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[60:64]))

	// AddressOfEntryPoint is at offset 16 in Optional Header
	// e_lfanew + PE Signature(4) + COFF Header(20) + AddressOfEntryPoint offset(16)
	entryPointOffset := peHeaderOffset + 4 + 20 + 16

	// Validate the new entry point is within reasonable bounds
	if newEntryPoint == 0 {
		return fmt.Errorf("入口点地址不能为0")
	}

	// Write new entry point
	entryPointBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(entryPointBytes, newEntryPoint)

	_, err = p.file.WriteAt(entryPointBytes, entryPointOffset)
	if err != nil {
		return fmt.Errorf("写入入口点失败: %w", err)
	}

	return nil
}

// GetEntryPoint returns the current entry point address.
func (p *Patcher) GetEntryPoint() (uint32, error) {
	if oh32, ok := p.peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
		return oh32.AddressOfEntryPoint, nil
	} else if oh64, ok := p.peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		return uint32(oh64.AddressOfEntryPoint), nil
	}
	return 0, fmt.Errorf("无法读取入口点")
}

// File returns the underlying PE file structure.
func (p *Patcher) File() *pe.File {
	return p.peFile
}

// Reload re-parses the PE file to reflect changes made to disk.
func (p *Patcher) Reload() error {
	// Sync file to ensure all writes are flushed
	if err := p.file.Sync(); err != nil {
		return fmt.Errorf("同步文件失败: %w", err)
	}

	// Close existing PE file (but not the file handle)
	if p.peFile != nil {
		_ = p.peFile.Close()
	}

	// Re-parse PE file from current file handle
	peFile, err := pe.NewFile(p.file)
	if err != nil {
		return fmt.Errorf("重新解析PE文件失败: %w", err)
	}

	p.peFile = peFile

	// Update file size
	stat, err := p.file.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}
	p.filesize = stat.Size()

	return nil
}

// ReadRVA reads data from a Relative Virtual Address.
func (p *Patcher) ReadRVA(rva, size uint32) ([]byte, error) {
	// Convert RVA to file offset
	var offset uint32
	found := false

	for _, section := range p.peFile.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			offset = rva - section.VirtualAddress + section.Offset
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("RVA 0x%X 不在任何节区内", rva)
	}

	// Read data
	data := make([]byte, size)
	_, err := p.file.ReadAt(data, int64(offset))
	if err != nil {
		return nil, fmt.Errorf("读取RVA 0x%X 失败: %w", rva, err)
	}

	return data, nil
}
