//go:build ignore
package main

import (
	"debug/pe"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: test_hexdump <file> <section_name>")
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
	defer pef.Close()

	sectionName := os.Args[2]
	var section *pe.Section
	for _, s := range pef.Sections {
		if s.Name == sectionName {
			section = s
			break
		}
	}

	if section == nil {
		fmt.Printf("Section %s not found\n", sectionName)
		os.Exit(1)
	}

	fmt.Printf("Section: %s\n", section.Name)
	fmt.Printf("File Offset: 0x%X\n", section.Offset)
	fmt.Printf("Virtual Address: 0x%X\n", section.VirtualAddress)
	fmt.Printf("Size: 0x%X (%d bytes)\n\n", section.Size, section.Size)

	// Read up to 512 bytes
	size := section.Size
	if size > 512 {
		size = 512
	}

	data := make([]byte, size)
	n, err := f.ReadAt(data, int64(section.Offset))
	if err != nil && n == 0 {
		fmt.Println("Error reading:", err)
		os.Exit(1)
	}

	fmt.Println("Hex dump (first", n, "bytes):")
	fmt.Println(hex.Dump(data[:n]))
}
