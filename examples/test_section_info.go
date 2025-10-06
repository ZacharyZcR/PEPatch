//go:build ignore
package main

import (
	"debug/pe"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test_section_info <file>")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer f.Close()

	pef, err := pe.NewFile(f)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	// Get import directory
	var importDir pe.DataDirectory
	if oh64, ok := pef.OptionalHeader.(*pe.OptionalHeader64); ok {
		importDir = oh64.DataDirectory[1]
	} else if oh32, ok := pef.OptionalHeader.(*pe.OptionalHeader32); ok {
		importDir = oh32.DataDirectory[1]
	}

	// Find .idata section
	for _, section := range pef.Sections {
		if section.VirtualAddress == importDir.VirtualAddress {
			fmt.Printf("Section: %s\n", section.Name)
			fmt.Printf("  VirtualAddress: 0x%08X\n", section.VirtualAddress)
			fmt.Printf("  VirtualSize:    0x%08X (%d bytes)\n", section.VirtualSize, section.VirtualSize)
			fmt.Printf("  Size:           0x%08X (%d bytes)\n", section.Size, section.Size)
			fmt.Printf("  Offset:         0x%08X\n", section.Offset)
			fmt.Printf("\nImport Directory:\n")
			fmt.Printf("  RVA:  0x%08X\n", importDir.VirtualAddress)
			fmt.Printf("  Size: 0x%08X (%d bytes)\n", importDir.Size, importDir.Size)
			fmt.Printf("\nSpace after Import Directory:\n")
			endRVA := importDir.VirtualAddress + importDir.Size
			sectionEndRVA := section.VirtualAddress + section.VirtualSize
			space := sectionEndRVA - endRVA
			fmt.Printf("  Import Dir End: 0x%08X\n", endRVA)
			fmt.Printf("  Section End:    0x%08X\n", sectionEndRVA)
			fmt.Printf("  Available:      0x%08X (%d bytes)\n", space, space)
			break
		}
	}
}
