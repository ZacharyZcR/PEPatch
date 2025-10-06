package main

import (
	"debug/pe"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test_datadirs <file>")
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

	fmt.Println("Data Directories:")
	dirNames := []string{
		"Export", "Import", "Resource", "Exception", "Certificate",
		"Base Relocation", "Debug", "Architecture", "Global Ptr", "TLS",
		"Load Config", "Bound Import", "IAT", "Delay Import", "CLR", "Reserved",
	}

	if oh32, ok := pef.OptionalHeader.(*pe.OptionalHeader32); ok {
		for i, dir := range oh32.DataDirectory {
			if dir.VirtualAddress != 0 || dir.Size != 0 {
				name := "Unknown"
				if i < len(dirNames) {
					name = dirNames[i]
				}
				fmt.Printf("  [%2d] %-20s RVA: 0x%08X  Size: 0x%08X\n", i, name, dir.VirtualAddress, dir.Size)
			}
		}
	} else if oh64, ok := pef.OptionalHeader.(*pe.OptionalHeader64); ok {
		for i, dir := range oh64.DataDirectory {
			if dir.VirtualAddress != 0 || dir.Size != 0 {
				name := "Unknown"
				if i < len(dirNames) {
					name = dirNames[i]
				}
				fmt.Printf("  [%2d] %-20s RVA: 0x%08X  Size: 0x%08X\n", i, name, dir.VirtualAddress, dir.Size)
			}
		}
	}
}
