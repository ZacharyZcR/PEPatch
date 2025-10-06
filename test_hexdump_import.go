package main

import (
	"debug/pe"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test_hexdump_import <file>")
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
	} else if oh32, ok := pef.OptionalHeader.(*pe.OptionalHeader32); ok {
		importDir = oh32.DataDirectory[1]
	}

	// Find section and offset
	var importOffset uint32
	for _, section := range pef.Sections {
		if importDir.VirtualAddress >= section.VirtualAddress &&
			importDir.VirtualAddress < section.VirtualAddress+section.VirtualSize {
			importOffset = importDir.VirtualAddress - section.VirtualAddress + section.Offset
			break
		}
	}

	// Read first 512 bytes of import data
	f.Seek(int64(importOffset), 0)
	data := make([]byte, 512)
	n, _ := f.Read(data)

	fmt.Printf("Import data hex dump (first %d bytes):\n\n", n)
	fmt.Println(hex.Dump(data[:n]))
}
