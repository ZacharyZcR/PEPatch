package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// ChecksumInfo contains PE checksum verification results.
type ChecksumInfo struct {
	Stored   uint32
	Computed uint32
	Valid    bool
}

// VerifyChecksum calculates and verifies PE file checksum.
func VerifyChecksum(f *pe.File, r io.ReaderAt, filesize int64) (*ChecksumInfo, error) {
	// Read DOS header to get e_lfanew (PE header offset)
	dosHeader := make([]byte, 64)
	_, err := r.ReadAt(dosHeader, 0)
	if err != nil {
		return nil, fmt.Errorf("读取DOS头失败: %w", err)
	}

	// e_lfanew is at offset 0x3C (60) in DOS header
	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[60:64]))

	// Get stored checksum from optional header
	var storedChecksum uint32
	var checksumOffset int64

	if oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		storedChecksum = oh32.CheckSum
		// CheckSum is at offset 64 in Optional Header
		// e_lfanew + PE Signature(4) + COFF Header(20) + OptionalHeader offset(64)
		checksumOffset = peHeaderOffset + 4 + 20 + 64
	} else if oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		storedChecksum = oh64.CheckSum
		// Same offset for PE32+
		checksumOffset = peHeaderOffset + 4 + 20 + 64
	}

	// If checksum is 0, file is not checksummed (common for non-system files)
	if storedChecksum == 0 {
		return &ChecksumInfo{
			Stored:   0,
			Computed: 0,
			Valid:    true,
		}, nil
	}

	// Calculate actual checksum
	computed, err := CalculatePEChecksum(r, filesize, checksumOffset)
	if err != nil {
		return nil, fmt.Errorf("计算校验和失败: %w", err)
	}

	return &ChecksumInfo{
		Stored:   storedChecksum,
		Computed: computed,
		Valid:    storedChecksum == computed,
	}, nil
}

// CalculatePEChecksum computes the PE checksum using Windows algorithm.
func CalculatePEChecksum(r io.ReaderAt, filesize int64, checksumOffset int64) (uint32, error) {
	// Read entire file
	data := make([]byte, filesize)
	_, err := r.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		return 0, err
	}

	var checksum uint64

	// Process file as array of DWORDs (32-bit words)
	for i := int64(0); i < filesize; i += 4 {
		// Skip the checksum field itself (4 bytes)
		if i == checksumOffset {
			continue
		}

		// Read DWORD, handle partial last DWORD
		var dword uint32
		remaining := filesize - i
		if remaining >= 4 {
			dword = binary.LittleEndian.Uint32(data[i : i+4])
		} else {
			// Last partial DWORD - pad with zeros
			temp := make([]byte, 4)
			copy(temp, data[i:])
			dword = binary.LittleEndian.Uint32(temp)
		}

		// Add to checksum
		checksum += uint64(dword)

		// Handle overflow: add high DWORD to low DWORD
		checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
	}

	// Final carry
	checksum = (checksum & 0xFFFF) + (checksum >> 16)
	checksum = checksum + (checksum >> 16)
	checksum = checksum & 0xFFFF

	// Add file size
	checksum += uint64(filesize)

	return uint32(checksum), nil
}
