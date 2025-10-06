package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// CodeCave represents a usable code cave in a PE file.
type CodeCave struct {
	Section  string // Section name.
	Offset   uint32 // File offset.
	RVA      uint32 // Relative Virtual Address.
	Size     uint32 // Available size in bytes.
	FillByte byte   // Fill pattern (0x00 or 0xCC).
}

// CodeCaveDetector finds code caves in PE files.
type CodeCaveDetector struct {
	file   io.ReaderAt
	peFile *pe.File
}

// NewCodeCaveDetector creates a new code cave detector.
func NewCodeCaveDetector(file io.ReaderAt, peFile *pe.File) *CodeCaveDetector {
	return &CodeCaveDetector{
		file:   file,
		peFile: peFile,
	}
}

// FindCodeCaves searches for code caves in all sections.
// minSize specifies the minimum cave size in bytes.
func (d *CodeCaveDetector) FindCodeCaves(minSize uint32) ([]CodeCave, error) {
	var caves []CodeCave

	for _, section := range d.peFile.Sections {
		sectionCaves, err := d.findInSection(section, minSize)
		if err != nil {
			return nil, fmt.Errorf("扫描节区 %s 失败: %w", section.Name, err)
		}
		caves = append(caves, sectionCaves...)
	}

	return caves, nil
}

// findInSection searches for code caves in a specific section.
func (d *CodeCaveDetector) findInSection(section *pe.Section, minSize uint32) ([]CodeCave, error) {
	// Read section data.
	data := make([]byte, section.Size)
	_, err := section.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}

	var caves []CodeCave
	var caveStart int = -1
	var fillByte byte

	// Scan for consecutive fill bytes (0x00 or 0xCC).
	for i := 0; i < len(data); i++ {
		b := data[i]

		// Check if this is a potential fill byte.
		if b == 0x00 || b == 0xCC {
			if caveStart == -1 {
				// Start of new potential cave.
				caveStart = i
				fillByte = b
			} else if b != fillByte {
				// Different fill byte, end previous cave and start new one.
				if uint32(i-caveStart) >= minSize {
					caves = append(caves, d.createCodeCave(section, caveStart, i, fillByte))
				}
				caveStart = i
				fillByte = b
			}
			// Continue expanding current cave.
		} else {
			// Non-fill byte, end current cave if exists.
			if caveStart != -1 && uint32(i-caveStart) >= minSize {
				caves = append(caves, d.createCodeCave(section, caveStart, i, fillByte))
			}
			caveStart = -1
		}
	}

	// Handle cave extending to end of section.
	if caveStart != -1 && uint32(len(data)-caveStart) >= minSize {
		caves = append(caves, d.createCodeCave(section, caveStart, len(data), fillByte))
	}

	return caves, nil
}

// createCodeCave constructs a CodeCave struct.
func (d *CodeCaveDetector) createCodeCave(section *pe.Section, start, end int, fillByte byte) CodeCave {
	offset := section.Offset + uint32(start)
	rva := section.VirtualAddress + uint32(start)
	size := uint32(end - start)

	return CodeCave{
		Section:  section.Name,
		Offset:   offset,
		RVA:      rva,
		Size:     size,
		FillByte: fillByte,
	}
}

// InjectCodeCave writes code to a specific file offset.
func (p *Patcher) InjectCodeCave(offset uint32, code []byte) error {
	if len(code) == 0 {
		return fmt.Errorf("代码不能为空")
	}

	// Write code to file.
	_, err := p.file.WriteAt(code, int64(offset))
	if err != nil {
		return fmt.Errorf("写入代码失败: %w", err)
	}

	return nil
}

// InjectCodeCaveWithJump injects code and redirects entry point to it.
// Returns the original entry point for restoration.
func (p *Patcher) InjectCodeCaveWithJump(cave CodeCave, code []byte, updateChecksum bool) (uint32, error) {
	if uint32(len(code)) > cave.Size-5 {
		return 0, fmt.Errorf("代码大小 %d 字节超过 code cave 容量 %d 字节 (需要保留5字节用于返回跳转)", len(code), cave.Size)
	}

	// Get original entry point.
	originalEntry, err := p.GetEntryPoint()
	if err != nil {
		return 0, err
	}

	// Prepare full code with jump back.
	// JMP instruction: E9 [relative offset]
	fullCode := make([]byte, len(code)+5)
	copy(fullCode, code)

	// Calculate relative jump back to original entry point.
	// Jump target = original entry point
	// Jump source = cave RVA + code length + 5
	jumpSource := cave.RVA + uint32(len(code)) + 5
	relativeOffset := int32(originalEntry) - int32(jumpSource)
	fullCode[len(code)] = 0xE9 // JMP opcode.
	binary.LittleEndian.PutUint32(fullCode[len(code)+1:], uint32(relativeOffset))

	// Inject code to cave.
	if err := p.InjectCodeCave(cave.Offset, fullCode); err != nil {
		return 0, err
	}

	// Update entry point to cave.
	if err := p.PatchEntryPoint(cave.RVA); err != nil {
		return 0, err
	}

	// Update checksum if requested.
	if updateChecksum {
		if err := p.UpdateChecksum(); err != nil {
			return 0, err
		}
	}

	return originalEntry, nil
}

// DetectCodeCaves is a convenience function for detecting code caves.
func (p *Patcher) DetectCodeCaves(minSize uint32) ([]CodeCave, error) {
	detector := NewCodeCaveDetector(p.file, p.peFile)
	return detector.FindCodeCaves(minSize)
}
