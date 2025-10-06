package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: test_compare_imports <original> <modified>")
		os.Exit(1)
	}

	fmt.Println("=== ORIGINAL FILE ===")
	dumpImportStructure(os.Args[1])

	fmt.Println("\n=== MODIFIED FILE ===")
	dumpImportStructure(os.Args[2])
}

func dumpImportStructure(filepath string) {
	f, err := os.Open(filepath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer f.Close()

	pef, err := pe.NewFile(f)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer pef.Close()

	// Get import directory
	var importDir pe.DataDirectory
	if oh64, ok := pef.OptionalHeader.(*pe.OptionalHeader64); ok {
		importDir = oh64.DataDirectory[1]
	} else if oh32, ok := pef.OptionalHeader.(*pe.OptionalHeader32); ok {
		importDir = oh32.DataDirectory[1]
	}

	fmt.Printf("Import Dir: RVA=0x%08X Size=0x%08X (%d bytes)\n",
		importDir.VirtualAddress, importDir.Size, importDir.Size)

	// Find section
	var importSection *pe.Section
	for _, s := range pef.Sections {
		if importDir.VirtualAddress >= s.VirtualAddress &&
		   importDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			importSection = s
			break
		}
	}

	if importSection == nil {
		fmt.Println("ERROR: Import directory not in any section!")
		return
	}

	fmt.Printf("Section: %s (Offset=0x%X VirtAddr=0x%X VirtSize=0x%X)\n",
		importSection.Name, importSection.Offset,
		importSection.VirtualAddress, importSection.VirtualSize)

	// Read and dump first 5 descriptors
	offset := importDir.VirtualAddress - importSection.VirtualAddress + importSection.Offset

	fmt.Println("\nImport Descriptors:")
	for i := 0; i < 5; i++ {
		buf := make([]byte, 20)
		_, err := f.ReadAt(buf, int64(offset)+int64(i*20))
		if err != nil {
			fmt.Printf("  [%d] Error reading: %v\n", i, err)
			break
		}

		int_ := binary.LittleEndian.Uint32(buf[0:4])
		timestamp := binary.LittleEndian.Uint32(buf[4:8])
		chain := binary.LittleEndian.Uint32(buf[8:12])
		name := binary.LittleEndian.Uint32(buf[12:16])
		iat := binary.LittleEndian.Uint32(buf[16:20])

		if int_ == 0 && name == 0 && iat == 0 {
			fmt.Printf("  [%d] NULL DESCRIPTOR (end of table)\n", i)
			break
		}

		fmt.Printf("  [%d] INT=0x%08X Time=0x%08X Chain=0x%08X Name=0x%08X IAT=0x%08X\n",
			i, int_, timestamp, chain, name, iat)

		// Try to read DLL name
		if name > 0 {
			dllName := readString(f, pef, name)
			fmt.Printf("       DLL: %s\n", dllName)
		}

		// Read first 3 INT entries
		if int_ > 0 {
			fmt.Printf("       INT entries: ")
			intEntries := readThunks(f, pef, int_, 3, true)
			fmt.Println(intEntries)

			// Read function names from INT
			readFunctionNames(f, pef, int_, 3, true)
		}

		// Read first 3 IAT entries
		if iat > 0 {
			fmt.Printf("       IAT entries: ")
			iatEntries := readThunks(f, pef, iat, 3, true)
			fmt.Println(iatEntries)
		}

		fmt.Println()
	}

	// Check for data after the null descriptor
	expectedDescSize := importDir.Size
	actualDescUsed := uint32(0)
	for i := 0; i < 100; i++ {
		buf := make([]byte, 20)
		_, err := f.ReadAt(buf, int64(offset)+int64(i*20))
		if err != nil {
			break
		}

		int_ := binary.LittleEndian.Uint32(buf[0:4])
		name := binary.LittleEndian.Uint32(buf[12:16])
		iat := binary.LittleEndian.Uint32(buf[16:20])

		if int_ == 0 && name == 0 && iat == 0 {
			actualDescUsed = uint32((i + 1) * 20)
			break
		}
	}

	fmt.Printf("Expected descriptor size: %d bytes\n", expectedDescSize)
	fmt.Printf("Actual descriptor size: %d bytes\n", actualDescUsed)
	if expectedDescSize != actualDescUsed {
		fmt.Printf("⚠ SIZE MISMATCH! Difference: %d bytes\n", int(expectedDescSize)-int(actualDescUsed))
	}
}

func readString(f *os.File, pef *pe.File, rva uint32) string {
	offset := rvaToOffset(pef, rva)
	if offset == 0 {
		return "<invalid RVA>"
	}

	buf := make([]byte, 256)
	n, err := f.ReadAt(buf, int64(offset))
	if err != nil && n == 0 {
		return "<read error>"
	}

	// Find null terminator
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return string(buf[:i])
		}
	}
	return string(buf[:n])
}

func readThunks(f *os.File, pef *pe.File, rva uint32, maxCount int, is64bit bool) string {
	offset := rvaToOffset(pef, rva)
	if offset == 0 {
		return "<invalid RVA>"
	}

	size := 4
	if is64bit {
		size = 8
	}

	var result string
	for i := 0; i < maxCount; i++ {
		buf := make([]byte, size)
		_, err := f.ReadAt(buf, int64(offset)+int64(i*size))
		if err != nil {
			break
		}

		var value uint64
		if is64bit {
			value = binary.LittleEndian.Uint64(buf)
		} else {
			value = uint64(binary.LittleEndian.Uint32(buf))
		}

		if value == 0 {
			result += "NULL"
			break
		}

		if i > 0 {
			result += ", "
		}

		// Check if ordinal
		ordinalFlag := uint64(0x80000000)
		if is64bit {
			ordinalFlag = 0x8000000000000000
		}

		if value&ordinalFlag != 0 {
			result += fmt.Sprintf("ORD:%d", value&0xFFFF)
		} else {
			result += fmt.Sprintf("0x%X", value)
		}
	}

	return result
}

func rvaToOffset(pef *pe.File, rva uint32) uint32 {
	for _, section := range pef.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return rva - section.VirtualAddress + section.Offset
		}
	}
	return 0
}

func readFunctionNames(f *os.File, pef *pe.File, intRVA uint32, maxCount int, is64bit bool) {
	offset := rvaToOffset(pef, intRVA)
	if offset == 0 {
		return
	}

	size := 4
	if is64bit {
		size = 8
	}

	ordinalFlag := uint64(0x80000000)
	if is64bit {
		ordinalFlag = 0x8000000000000000
	}

	for i := 0; i < maxCount; i++ {
		buf := make([]byte, size)
		_, err := f.ReadAt(buf, int64(offset)+int64(i*size))
		if err != nil {
			break
		}

		var value uint64
		if is64bit {
			value = binary.LittleEndian.Uint64(buf)
		} else {
			value = uint64(binary.LittleEndian.Uint32(buf))
		}

		if value == 0 {
			break
		}

		// Skip ordinals
		if value&ordinalFlag != 0 {
			continue
		}

		// Read IMAGE_IMPORT_BY_NAME (hint + name)
		nameRVA := uint32(value)
		nameOffset := rvaToOffset(pef, nameRVA)
		if nameOffset == 0 {
			fmt.Printf("         [%d] <invalid name RVA 0x%X>\n", i, nameRVA)
			continue
		}

		// Read hint (2 bytes)
		hintBuf := make([]byte, 2)
		f.ReadAt(hintBuf, int64(nameOffset))
		hint := binary.LittleEndian.Uint16(hintBuf)

		// Read name
		funcName := readString(f, pef, nameRVA+2)
		fmt.Printf("         [%d] Hint=%d Name=%s\n", i, hint, funcName)
	}
}
