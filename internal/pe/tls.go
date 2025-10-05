package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

// TLSInfo contains TLS (Thread Local Storage) information.
type TLSInfo struct {
	HasTLS                bool
	Callbacks             []uint64
	StartAddressOfRawData uint64
	EndAddressOfRawData   uint64
	AddressOfIndex        uint64
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

// IMAGE_TLS_DIRECTORY32 structure.
type tlsDirectory32 struct {
	StartAddressOfRawData uint32
	EndAddressOfRawData   uint32
	AddressOfIndex        uint32
	AddressOfCallBacks    uint32
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

// IMAGE_TLS_DIRECTORY64 structure.
type tlsDirectory64 struct {
	StartAddressOfRawData uint64
	EndAddressOfRawData   uint64
	AddressOfIndex        uint64
	AddressOfCallBacks    uint64
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

// ParseTLS extracts TLS directory information from PE file.
func ParseTLS(f *pe.File, r io.ReaderAt) (*TLSInfo, error) {
	info := &TLSInfo{
		HasTLS: false,
	}

	// Get TLS Directory (Data Directory[9])
	var tlsDirRVA, tlsDirSize uint32
	is64Bit := false

	if oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 9 {
			tlsDirRVA = oh32.DataDirectory[9].VirtualAddress
			tlsDirSize = oh32.DataDirectory[9].Size
		}
	} else if oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		is64Bit = true
		if len(oh64.DataDirectory) > 9 {
			tlsDirRVA = oh64.DataDirectory[9].VirtualAddress
			tlsDirSize = oh64.DataDirectory[9].Size
		}
	}

	if tlsDirRVA == 0 || tlsDirSize == 0 {
		return info, nil // No TLS directory
	}

	info.HasTLS = true

	// Convert RVA to file offset
	tlsOffset, err := rvaToOffset(f, tlsDirRVA)
	if err != nil {
		return info, err
	}

	// Parse TLS directory based on architecture
	if is64Bit {
		return parseTLS64(f, r, int64(tlsOffset), info)
	}
	return parseTLS32(f, r, int64(tlsOffset), info)
}

func parseTLS32(f *pe.File, r io.ReaderAt, offset int64, info *TLSInfo) (*TLSInfo, error) {
	var tls tlsDirectory32
	err := binary.Read(io.NewSectionReader(r, offset, 24), binary.LittleEndian, &tls)
	if err != nil {
		return info, fmt.Errorf("读取TLS目录失败: %w", err)
	}

	info.StartAddressOfRawData = uint64(tls.StartAddressOfRawData)
	info.EndAddressOfRawData = uint64(tls.EndAddressOfRawData)
	info.AddressOfIndex = uint64(tls.AddressOfIndex)
	info.SizeOfZeroFill = tls.SizeOfZeroFill
	info.Characteristics = tls.Characteristics

	// Parse callbacks if present
	if tls.AddressOfCallBacks != 0 {
		info.Callbacks = parseTLSCallbacks32(f, r, tls.AddressOfCallBacks)
	}

	return info, nil
}

func parseTLS64(f *pe.File, r io.ReaderAt, offset int64, info *TLSInfo) (*TLSInfo, error) {
	var tls tlsDirectory64
	err := binary.Read(io.NewSectionReader(r, offset, 40), binary.LittleEndian, &tls)
	if err != nil {
		return info, fmt.Errorf("读取TLS目录失败: %w", err)
	}

	info.StartAddressOfRawData = tls.StartAddressOfRawData
	info.EndAddressOfRawData = tls.EndAddressOfRawData
	info.AddressOfIndex = tls.AddressOfIndex
	info.SizeOfZeroFill = tls.SizeOfZeroFill
	info.Characteristics = tls.Characteristics

	// Parse callbacks if present
	if tls.AddressOfCallBacks != 0 {
		info.Callbacks = parseTLSCallbacks64(f, r, tls.AddressOfCallBacks)
	}

	return info, nil
}

func parseTLSCallbacks32(f *pe.File, r io.ReaderAt, callbacksVA uint32) []uint64 {
	var callbacks []uint64

	// Get image base
	var imageBase uint32
	if oh, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		imageBase = oh.ImageBase
	} else {
		return callbacks
	}

	// Convert VA to RVA
	callbacksRVA := callbacksVA - imageBase

	// Convert RVA to file offset
	callbacksOffset, err := rvaToOffset(f, callbacksRVA)
	if err != nil {
		return callbacks
	}

	// Read callbacks (array terminated by NULL)
	for i := 0; i < 100; i++ { // Max 100 callbacks to prevent infinite loop
		var callback uint32
		err := binary.Read(io.NewSectionReader(r, int64(callbacksOffset)+int64(i*4), 4), binary.LittleEndian, &callback)
		if err != nil || callback == 0 {
			break
		}
		callbacks = append(callbacks, uint64(callback))
	}

	return callbacks
}

func parseTLSCallbacks64(f *pe.File, r io.ReaderAt, callbacksVA uint64) []uint64 {
	var callbacks []uint64

	// Get image base
	var imageBase uint64
	if oh, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		imageBase = oh.ImageBase
	} else {
		return callbacks
	}

	// Convert VA to RVA
	callbacksRVA := uint32(callbacksVA - imageBase)

	// Convert RVA to file offset
	callbacksOffset, err := rvaToOffset(f, callbacksRVA)
	if err != nil {
		return callbacks
	}

	// Read callbacks (array terminated by NULL)
	for i := 0; i < 100; i++ { // Max 100 callbacks to prevent infinite loop
		var callback uint64
		err := binary.Read(io.NewSectionReader(r, int64(callbacksOffset)+int64(i*8), 8), binary.LittleEndian, &callback)
		if err != nil || callback == 0 {
			break
		}
		callbacks = append(callbacks, callback)
	}

	return callbacks
}
