//go:build ignore
package main

import (
	"fmt"
	"os"

	"github.com/ZacharyZcR/PEPatch/internal/pe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test_inject_import <file>")
		os.Exit(1)
	}

	filePath := os.Args[1]

	// Create patcher
	patcher, err := pe.NewPatcher(filePath)
	if err != nil {
		fmt.Printf("Error creating patcher: %v\n", err)
		os.Exit(1)
	}
	defer patcher.Close()

	// Add import
	im := pe.NewImportModifier(patcher)
	err = im.AddImport("user32.dll", []string{"MessageBoxA"})
	if err != nil {
		fmt.Printf("Error adding import: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Successfully added user32.dll:MessageBoxA")
}
