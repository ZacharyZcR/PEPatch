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

// TLSModifier handles TLS callback modifications.
type TLSModifier struct {
	patcher *Patcher
}

// NewTLSModifier creates a new TLS modifier.
func NewTLSModifier(patcher *Patcher) *TLSModifier {
	return &TLSModifier{
		patcher: patcher,
	}
}

// HasTLS checks if the PE file has a TLS directory.
func (tm *TLSModifier) HasTLS() (bool, uint32, uint32) {
	oh := tm.patcher.File().OptionalHeader

	var tlsRVA, tlsSize uint32

	if oh32, ok := oh.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 9 {
			tlsRVA = oh32.DataDirectory[9].VirtualAddress
			tlsSize = oh32.DataDirectory[9].Size
		}
	} else if oh64, ok := oh.(*pe.OptionalHeader64); ok {
		if len(oh64.DataDirectory) > 9 {
			tlsRVA = oh64.DataDirectory[9].VirtualAddress
			tlsSize = oh64.DataDirectory[9].Size
		}
	}

	return tlsRVA != 0 && tlsSize != 0, tlsRVA, tlsSize
}

// AddTLSCallback adds a new TLS callback function.
func (tm *TLSModifier) AddTLSCallback(callbackRVA uint32) error {
	hasTLS, tlsRVA, _ := tm.HasTLS()

	if !hasTLS {
		return fmt.Errorf("文件没有TLS目录，无法添加TLS回调")
	}

	// Check if 32-bit or 64-bit
	is64Bit := false
	var imageBase uint64
	if oh32, ok := tm.patcher.File().OptionalHeader.(*pe.OptionalHeader32); ok {
		imageBase = uint64(oh32.ImageBase)
	} else if oh64, ok := tm.patcher.File().OptionalHeader.(*pe.OptionalHeader64); ok {
		is64Bit = true
		imageBase = oh64.ImageBase
	}

	// Read existing TLS directory
	tlsData, err := tm.patcher.ReadRVA(tlsRVA, 64)
	if err != nil {
		return fmt.Errorf("读取TLS目录失败: %w", err)
	}

	// Parse existing callbacks
	var existingCallbacksVA uint64
	if is64Bit {
		existingCallbacksVA = binary.LittleEndian.Uint64(tlsData[24:32])
	} else {
		existingCallbacksVA = uint64(binary.LittleEndian.Uint32(tlsData[12:16]))
	}

	// Read existing callbacks
	var existingCallbacks []uint64
	if existingCallbacksVA != 0 {
		callbacksRVA := uint32(existingCallbacksVA - imageBase)
		existingCallbacks, err = tm.readCallbacksArray(callbacksRVA, is64Bit)
		if err != nil {
			return fmt.Errorf("读取现有回调失败: %w", err)
		}
	}

	// Create new callbacks array with the new callback prepended
	newCallbackVA := imageBase + uint64(callbackRVA)
	newCallbacks := append([]uint64{newCallbackVA}, existingCallbacks...)

	// Write new callbacks array to a new section
	callbacksData := tm.buildCallbacksArray(newCallbacks, is64Bit)

	// Inject section for callbacks
	err = tm.patcher.InjectSection(".tlscb", callbacksData, pe.IMAGE_SCN_CNT_INITIALIZED_DATA|pe.IMAGE_SCN_MEM_READ)
	if err != nil {
		return fmt.Errorf("注入回调节区失败: %w", err)
	}

	// Reload PE
	if err := tm.patcher.Reload(); err != nil {
		return fmt.Errorf("重新加载PE失败: %w", err)
	}

	// Get new section
	sections := tm.patcher.File().Sections
	newSection := sections[len(sections)-1]

	// Calculate new callbacks VA
	newCallbacksVA := imageBase + uint64(newSection.VirtualAddress)

	// Update TLS directory to point to new callbacks array
	return tm.updateTLSCallbacksPointer(tlsRVA, newCallbacksVA, is64Bit)
}

// readCallbacksArray reads the existing callbacks array.
func (tm *TLSModifier) readCallbacksArray(callbacksRVA uint32, is64Bit bool) ([]uint64, error) {
	var callbacks []uint64

	pointerSize := 4
	if is64Bit {
		pointerSize = 8
	}

	// Read up to 100 callbacks
	for i := 0; i < 100; i++ {
		offset := callbacksRVA + uint32(i*pointerSize)
		data, err := tm.patcher.ReadRVA(offset, uint32(pointerSize))
		if err != nil {
			break
		}

		var callback uint64
		if is64Bit {
			callback = binary.LittleEndian.Uint64(data)
		} else {
			callback = uint64(binary.LittleEndian.Uint32(data))
		}

		if callback == 0 {
			break
		}

		callbacks = append(callbacks, callback)
	}

	return callbacks, nil
}

// buildCallbacksArray builds the callbacks array data (NULL-terminated).
func (tm *TLSModifier) buildCallbacksArray(callbacks []uint64, is64Bit bool) []byte {
	pointerSize := 4
	if is64Bit {
		pointerSize = 8
	}

	// Allocate buffer: callbacks + 1 NULL terminator
	size := (len(callbacks) + 1) * pointerSize
	data := make([]byte, size)

	// Write callbacks
	for i, callback := range callbacks {
		offset := i * pointerSize
		if is64Bit {
			binary.LittleEndian.PutUint64(data[offset:], callback)
		} else {
			binary.LittleEndian.PutUint32(data[offset:], uint32(callback))
		}
	}

	// NULL terminator is already zero

	return data
}

// updateTLSCallbacksPointer updates the AddressOfCallBacks field in TLS directory.
func (tm *TLSModifier) updateTLSCallbacksPointer(tlsRVA uint32, newCallbacksVA uint64, is64Bit bool) error {
	// Convert TLS RVA to file offset
	tlsOffset, err := rvaToOffset(tm.patcher.File(), tlsRVA)
	if err != nil {
		return fmt.Errorf("转换TLS RVA失败: %w", err)
	}

	// AddressOfCallBacks is at offset 12 (32-bit) or 24 (64-bit)
	var callbacksOffset int64
	if is64Bit {
		callbacksOffset = int64(tlsOffset) + 24
	} else {
		callbacksOffset = int64(tlsOffset) + 12
	}

	// Write new VA
	data := make([]byte, 8)
	if is64Bit {
		binary.LittleEndian.PutUint64(data, newCallbacksVA)
		_, err = tm.patcher.file.WriteAt(data, callbacksOffset)
	} else {
		binary.LittleEndian.PutUint32(data, uint32(newCallbacksVA))
		_, err = tm.patcher.file.WriteAt(data[:4], callbacksOffset)
	}

	return err
}
