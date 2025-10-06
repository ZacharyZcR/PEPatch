package main

import (
	"debug/pe"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: test_find_section <file> <rva_hex>")
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

	var rva uint32
	fmt.Sscanf(os.Args[2], "%x", &rva)

	fmt.Printf("Looking for RVA 0x%08X\n\n", rva)

	found := false
	for _, s := range pef.Sections {
		start := s.VirtualAddress
		end := s.VirtualAddress + s.VirtualSize

		fmt.Printf("Section: %-10s VirtAddr=0x%08X-0x%08X Size=0x%X\n",
			s.Name, start, end, s.VirtualSize)

		if rva >= start && rva < end {
			fmt.Printf("  ✓ RVA 0x%08X is in this section (offset from section start: 0x%X)\n",
				rva, rva-start)
			found = true
		}
	}

	if !found {
		fmt.Printf("\n⚠ RVA 0x%08X not found in any section!\n", rva)
	}
}
