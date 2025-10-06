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
		fmt.Println("Usage: test_imports <file>")
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

	// Get import directory
	var importDir pe.DataDirectory
	if oh64, ok := pef.OptionalHeader.(*pe.OptionalHeader64); ok {
		importDir = oh64.DataDirectory[1]
	} else if oh32, ok := pef.OptionalHeader.(*pe.OptionalHeader32); ok {
		importDir = oh32.DataDirectory[1]
	}

	fmt.Printf("Import Directory: RVA=0x%08X Size=0x%08X\n", importDir.VirtualAddress, importDir.Size)

	// Find section containing import directory
	var importSection *pe.Section
	for _, s := range pef.Sections {
		if importDir.VirtualAddress >= s.VirtualAddress &&
		   importDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			importSection = s
			break
		}
	}

	if importSection == nil {
		fmt.Println("Import directory not in any section!")
		return
	}

	fmt.Printf("Import table in section: %s (RVA=0x%08X)\n", importSection.Name, importSection.VirtualAddress)

	// Read first 3 import descriptors
	offset := importDir.VirtualAddress - importSection.VirtualAddress + importSection.Offset
	buf := make([]byte, 20*3)
	_, err = f.ReadAt(buf, int64(offset))
	if err != nil {
		fmt.Println("Error reading descriptors:", err)
		return
	}

	fmt.Println("\nFirst 3 import descriptors:")
	for i := 0; i < 3; i++ {
		desc := buf[i*20 : (i+1)*20]
		int_ := binary.LittleEndian.Uint32(desc[0:4])
		timestamp := binary.LittleEndian.Uint32(desc[4:8])
		chain := binary.LittleEndian.Uint32(desc[8:12])
		name := binary.LittleEndian.Uint32(desc[12:16])
		iat := binary.LittleEndian.Uint32(desc[16:20])

		fmt.Printf("  [%d] INT=0x%08X Timestamp=0x%08X Chain=0x%08X Name=0x%08X IAT=0x%08X\n",
			i, int_, timestamp, chain, name, iat)

		if int_ == 0 && name == 0 && iat == 0 {
			fmt.Println("  (null descriptor - end of table)")
			break
		}
	}
}
