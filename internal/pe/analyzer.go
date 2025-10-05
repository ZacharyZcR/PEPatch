package pe

import (
	"debug/pe"
	"fmt"
	"strings"
)

// Info contains analyzed PE file information.
type Info struct {
	FilePath     string
	FileSize     int64
	Architecture string
	Subsystem    string
	EntryPoint   uint64
	ImageBase    uint64
	Checksum     *ChecksumInfo
	Signature    *SignatureInfo
	Sections     []SectionInfo
	Imports      []ImportInfo
	Exports      []string
}

// SectionInfo contains information about a PE section.
type SectionInfo struct {
	Name            string
	VirtualAddress  uint32
	VirtualSize     uint32
	Size            uint32
	Characteristics uint32
	Permissions     string
	Entropy         float64
}

// ImportInfo contains information about imported DLL and functions.
type ImportInfo struct {
	DLL       string
	Functions []string
}

// Analyzer extracts information from PE files.
type Analyzer struct {
	reader *Reader
}

// NewAnalyzer creates a new analyzer for the given reader.
func NewAnalyzer(r *Reader) *Analyzer {
	return &Analyzer{reader: r}
}

// Analyze extracts all information from the PE file.
func (a *Analyzer) Analyze() (*Info, error) {
	f := a.reader.File()

	info := &Info{
		FilePath: a.reader.FilePath(),
		FileSize: a.reader.FileSize(),
	}

	if err := a.extractBasicInfo(f, info); err != nil {
		return nil, err
	}

	a.extractSections(f, info)
	a.extractImports(f, info)
	a.extractExports(f, info)
	a.verifyChecksum(f, info)
	a.verifySignature(f, info)

	return info, nil
}

func (a *Analyzer) extractBasicInfo(f *pe.File, info *Info) error {
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		info.Architecture = "x86 (32位)"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		info.Architecture = "x64 (64位)"
	case pe.IMAGE_FILE_MACHINE_ARM:
		info.Architecture = "ARM"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		info.Architecture = "ARM64"
	default:
		info.Architecture = fmt.Sprintf("未知 (0x%X)", f.Machine)
	}

	if opt, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		info.EntryPoint = uint64(opt.AddressOfEntryPoint)
		info.ImageBase = uint64(opt.ImageBase)
		info.Subsystem = getSubsystem(opt.Subsystem)
	} else if opt, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		info.EntryPoint = uint64(opt.AddressOfEntryPoint)
		info.ImageBase = opt.ImageBase
		info.Subsystem = getSubsystem(opt.Subsystem)
	}

	return nil
}

func (a *Analyzer) extractSections(f *pe.File, info *Info) {
	for _, section := range f.Sections {
		// Calculate entropy for this section
		entropy, err := CalculateSectionEntropy(a.reader.RawFile(), int64(section.Offset), section.Size)
		if err != nil {
			entropy = 0.0 // Default to 0 on error
		}

		info.Sections = append(info.Sections, SectionInfo{
			Name:            section.Name,
			VirtualAddress:  section.VirtualAddress,
			VirtualSize:     section.VirtualSize,
			Size:            section.Size,
			Characteristics: section.Characteristics,
			Permissions:     getSectionPermissions(section.Characteristics),
			Entropy:         entropy,
		})
	}
}

func (a *Analyzer) extractImports(f *pe.File, info *Info) {
	symbols, err := f.ImportedSymbols()
	if err != nil {
		return
	}

	// Parse "FunctionName:DLL.dll" format and group by DLL
	dllMap := make(map[string][]string)
	for _, symbol := range symbols {
		// Split "FunctionName:DLL.dll" -> ["FunctionName", "DLL.dll"]
		parts := strings.Split(symbol, ":")
		if len(parts) != 2 {
			continue
		}
		funcName := parts[0]
		dllName := parts[1]
		dllMap[dllName] = append(dllMap[dllName], funcName)
	}

	// Convert map to slice
	for dll, funcs := range dllMap {
		info.Imports = append(info.Imports, ImportInfo{
			DLL:       dll,
			Functions: funcs,
		})
	}
}

func (a *Analyzer) extractExports(f *pe.File, info *Info) {
	exports, err := parseExports(f, a.reader.RawFile())
	if err != nil {
		// Silently ignore export parsing errors
		return
	}
	info.Exports = exports
}

func (a *Analyzer) verifyChecksum(f *pe.File, info *Info) {
	checksum, err := VerifyChecksum(f, a.reader.RawFile(), a.reader.FileSize())
	if err != nil {
		// Silently ignore checksum verification errors
		return
	}
	info.Checksum = checksum
}

func (a *Analyzer) verifySignature(f *pe.File, info *Info) {
	signature, err := VerifySignature(f, a.reader.RawFile())
	if err != nil {
		// Silently ignore signature verification errors
		return
	}
	info.Signature = signature
}

func getSubsystem(subsystem uint16) string {
	switch subsystem {
	case pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		return "Windows GUI"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CUI:
		return "Windows 控制台"
	case pe.IMAGE_SUBSYSTEM_NATIVE:
		return "Native"
	default:
		return fmt.Sprintf("未知 (0x%X)", subsystem)
	}
}

func getSectionPermissions(c uint32) string {
	var perms [3]rune
	perms[0] = '-'
	perms[1] = '-'
	perms[2] = '-'

	if c&pe.IMAGE_SCN_MEM_READ != 0 {
		perms[0] = 'R'
	}
	if c&pe.IMAGE_SCN_MEM_WRITE != 0 {
		perms[1] = 'W'
	}
	if c&pe.IMAGE_SCN_MEM_EXECUTE != 0 {
		perms[2] = 'X'
	}

	return string(perms[:])
}
