package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test_check_import <file>")
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

	// Get Import Directory
	var importDir pe.DataDirectory
	if oh64, ok := pef.OptionalHeader.(*pe.OptionalHeader64); ok {
		importDir = oh64.DataDirectory[1]
		fmt.Printf("Architecture: x64\n")
	} else if oh32, ok := pef.OptionalHeader.(*pe.OptionalHeader32); ok {
		importDir = oh32.DataDirectory[1]
		fmt.Printf("Architecture: x86\n")
	}

	fmt.Printf("Import Directory RVA:  0x%08X\n", importDir.VirtualAddress)
	fmt.Printf("Import Directory Size: 0x%08X (%d bytes)\n", importDir.Size, importDir.Size)

	// Get IAT Directory
	var iatDir pe.DataDirectory
	if oh64, ok := pef.OptionalHeader.(*pe.OptionalHeader64); ok {
		iatDir = oh64.DataDirectory[12]
	} else if oh32, ok := pef.OptionalHeader.(*pe.OptionalHeader32); ok {
		iatDir = oh32.DataDirectory[12]
	}

	fmt.Printf("IAT Directory RVA:     0x%08X\n", iatDir.VirtualAddress)
	fmt.Printf("IAT Directory Size:    0x%08X (%d bytes)\n", iatDir.Size, iatDir.Size)

	// Count descriptors
	for _, section := range pef.Sections {
		if importDir.VirtualAddress >= section.VirtualAddress &&
			importDir.VirtualAddress < section.VirtualAddress+section.VirtualSize {
			offset := importDir.VirtualAddress - section.VirtualAddress + section.Offset

			f.Seek(int64(offset), 0)
			count := 0
			for {
				descData := make([]byte, 20)
				n, _ := f.Read(descData)
				if n != 20 {
					break
				}

				OriginalFirstThunk := binary.LittleEndian.Uint32(descData[0:4])
				Name := binary.LittleEndian.Uint32(descData[12:16])
				FirstThunk := binary.LittleEndian.Uint32(descData[16:20])

				if OriginalFirstThunk == 0 && Name == 0 && FirstThunk == 0 {
					count++ // null descriptor
					break
				}
				count++
			}
			fmt.Printf("Descriptor count:      %d (including null)\n", count)
			fmt.Printf("Descriptor size:       %d bytes\n", count*20)
			break
		}
	}
}
