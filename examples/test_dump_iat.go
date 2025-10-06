//go:build ignore
package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test_dump_iat <file>")
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
	is64bit := false
	if oh64, ok := pef.OptionalHeader.(*pe.OptionalHeader64); ok {
		importDir = oh64.DataDirectory[1]
		is64bit = true
	} else if oh32, ok := pef.OptionalHeader.(*pe.OptionalHeader32); ok {
		importDir = oh32.DataDirectory[1]
	}

	// Find section containing import directory
	var importSection *pe.Section
	var importOffset uint32
	for _, section := range pef.Sections {
		if importDir.VirtualAddress >= section.VirtualAddress &&
			importDir.VirtualAddress < section.VirtualAddress+section.VirtualSize {
			importSection = section
			importOffset = importDir.VirtualAddress - section.VirtualAddress + section.Offset
			break
		}
	}

	if importSection == nil {
		fmt.Println("Import section not found")
		os.Exit(1)
	}

	fmt.Printf("Import Directory at file offset: 0x%08X\n\n", importOffset)

	// Read descriptors
	f.Seek(int64(importOffset), 0)
	descriptorIndex := 0

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
			fmt.Printf("Descriptor %d: NULL (end marker)\n\n", descriptorIndex)
			break
		}

		// Read DLL name
		dllName := ""
		if nameOffset := rvaToOffset(pef, Name); nameOffset != 0 {
			f.Seek(int64(nameOffset), 0)
			nameBuf := make([]byte, 256)
			f.Read(nameBuf)
			for i, b := range nameBuf {
				if b == 0 {
					dllName = string(nameBuf[:i])
					break
				}
			}
		}

		fmt.Printf("Descriptor %d: %s\n", descriptorIndex, dllName)
		fmt.Printf("  OriginalFirstThunk (INT): 0x%08X\n", OriginalFirstThunk)
		fmt.Printf("  FirstThunk (IAT):         0x%08X\n", FirstThunk)

		// Read INT to count functions
		if intOffset := rvaToOffset(pef, OriginalFirstThunk); intOffset != 0 {
			f.Seek(int64(intOffset), 0)
			funcCount := 0
			ptrSize := 4
			if is64bit {
				ptrSize = 8
			}

			for {
				thunkBuf := make([]byte, ptrSize)
				f.Read(thunkBuf)
				var thunkValue uint64
				if is64bit {
					thunkValue = binary.LittleEndian.Uint64(thunkBuf)
				} else {
					thunkValue = uint64(binary.LittleEndian.Uint32(thunkBuf))
				}

				if thunkValue == 0 {
					break
				}
				funcCount++
			}
			fmt.Printf("  Function count:           %d\n", funcCount)
			fmt.Printf("  INT range:                0x%08X - 0x%08X\n", OriginalFirstThunk, OriginalFirstThunk+uint32((funcCount+1)*ptrSize))
			fmt.Printf("  IAT range:                0x%08X - 0x%08X\n", FirstThunk, FirstThunk+uint32((funcCount+1)*ptrSize))
		}

		fmt.Println()
		descriptorIndex++
	}
}

func rvaToOffset(pef *pe.File, rva uint32) uint32 {
	for _, section := range pef.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return rva - section.VirtualAddress + section.Offset
		}
	}
	return 0
}
