// Package main provides the PEPatch CLI tool.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: pepatch <pe-file>")
		os.Exit(1)
	}

	fmt.Printf("PEPatch: analyzing %s\n", os.Args[1])
}
