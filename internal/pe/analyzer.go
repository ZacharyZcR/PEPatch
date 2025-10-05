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
	Sections     []SectionInfo
	Imports      []ImportInfo
}

// SectionInfo contains information about a PE section.
type SectionInfo struct {
	Name            string
	VirtualAddress  uint32
	VirtualSize     uint32
	Size            uint32
	Characteristics uint32
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
		info.Sections = append(info.Sections, SectionInfo{
			Name:            section.Name,
			VirtualAddress:  section.VirtualAddress,
			VirtualSize:     section.VirtualSize,
			Size:            section.Size,
			Characteristics: section.Characteristics,
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
