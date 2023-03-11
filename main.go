package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	INVALID_HANDLE_VALUE = windows.Handle(0xFFFFFFFF)
)

//winnt.h
type ImageDOSHeader struct {
	Magic                    uint16
	BytesOnLastPageOfFile    uint16
	PagesInFile              uint16
	Relocations              uint16
	SizeOfHeader             uint16
	MinExtraParagraphsNeeded uint16
	MaxExtraParagraphsNeeded uint16
	InitialSS                uint16
	InitialSP                uint16
	Checksum                 uint16
	InitialIP                uint16
	InitialCS                uint16
	AddressOfRelocationTable uint16
	OverlayNumber            uint16
	ReservedWords1           [4]uint16
	OEMIdentifier            uint16
	OEMInformation           uint16
	ReservedWords2           [10]uint16
	AddressOfNewEXEHeader    uint32
}

type ImageNtHeader struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader *ImageOptionalHeader
}

type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

//x64
type ImageOptionalHeader struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]ImageDataDirectory
}

type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type ImageSectionHeader struct {
	Name                 [8]uint8
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

type ImageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type ImageDebugDirectoryType uint32

type ImageDebugDirectory struct {
	Characteristics  uint32
	TimeDateStamp    uint32
	MajorVersion     uint16
	MinorVersion     uint16
	Type             ImageDebugDirectoryType
	SizeOfData       uint32
	AddressOfRawData uint32
	PointerToRawData uint32
}

type PERelocation struct {
	RVA  uint32
	Type uint16
}

type PECodeDebugInfo struct {
	Signature uint32
	Guid      windows.GUID
	Age       uint32
	PdbName   [1]uint8
}

type PE struct {
	IsMemoryMapped          bool
	IsInAnotherAddressSpace bool
	HProcess                windows.Handle
	BaseAddress             uint64
	DosHeader               *ImageDOSHeader
	NtHeader                *ImageNtHeader
	OptHeader               *ImageOptionalHeader
	DataDir                 *ImageDataDirectory
	SectionHeaders          *ImageSectionHeader
	ExportDirectory         *ImageExportDirectory
	ExportedNames           *uint32
	ExportedNamesLength     uint32
	ExportedFunctions       *uint32
	ExportedOrdinals        *uint16
	NbRelocations           uint32
	Relocations             *PERelocation
	DebugDirectory          *ImageDebugDirectory
	CodeviewDebugInfo       *PECodeDebugInfo
}

func readFullFile(filePath string) []byte {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	return bytes
}

func loadSymbolsFromImageFile(imageFilePath string) {
	image := readFullFile(imageFilePath)
	fmt.Println(image)

}

func parseDosHeader(imageBytes []byte) *ImageDOSHeader {
	var imageDosHeader ImageDOSHeader
	offset := uint32(0)
	size := uint32(unsafe.Sizeof(imageDosHeader))
	totalSize := offset + size
	buf := bytes.NewReader(imageBytes[offset:totalSize])
	err := binary.Read(buf, binary.LittleEndian, &imageDosHeader)
	if err != nil {
		panic(err)
	}
	return &imageDosHeader
}

func parseNTHeader(imageBytes []byte, ntHeaderOffset uint32) *ImageNtHeader {
	var imageNtHeader ImageNtHeader
	sig := binary.LittleEndian.Uint32(imageBytes[ntHeaderOffset:])
	imageNtHeader.Signature = sig
	fileHeaderSize := uint32(binary.Size(imageNtHeader.FileHeader))
	fileHeaderOffset := ntHeaderOffset + 4
	totalSize := fileHeaderOffset + fileHeaderSize
	buf := bytes.NewReader(imageBytes[fileHeaderOffset:totalSize])
	err := binary.Read(buf, binary.LittleEndian, &imageNtHeader.FileHeader)
	if err != nil {
		panic(err)
	}
	optHeader := ImageOptionalHeader{}
	optHeaderOffset := ntHeaderOffset + (fileHeaderSize + 4)
	magic := binary.LittleEndian.Uint16(imageBytes[optHeaderOffset:])
	if magic != 0x20b {
		panic("Only x64")
	}
	size := uint32(binary.Size(optHeader))
	buf = bytes.NewReader(imageBytes[optHeaderOffset : optHeaderOffset+size])
	err = binary.Read(buf, binary.LittleEndian, &optHeader)
	if err != nil {
		panic(err)
	}
	imageNtHeader.OptionalHeader = &optHeader

	return &imageNtHeader
}

func peCreate(imageBytes []byte, isMemoryMapped bool) {
	var pe *PE
	pe.IsMemoryMapped = isMemoryMapped
	pe.IsInAnotherAddressSpace = false
	pe.HProcess = INVALID_HANDLE_VALUE
	pe.DosHeader = parseDosHeader(imageBytes)
	pe.NtHeader = parseNTHeader(imageBytes, pe.DosHeader.AddressOfNewEXEHeader)
	pe.OptHeader = pe.NtHeader.OptionalHeader
	if isMemoryMapped {
		pe.BaseAddress = uint64(uintptr(unsafe.Pointer(&imageBytes[0])))
	} else {
		pe.BaseAddress = pe.NtHeader.OptionalHeader.ImageBase
	}
	pe.DataDir = &pe.OptHeader.DataDirectory[0]
	// pe.SectionHeaders =
	// a := unsafe.Pointer(&pe)
	// fmt.Println(a)
}
func main() {
	_, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		panic(err)
	}

}

// func init_pdb7_root_stream(fName string, root_page_list []uint32, numRootPages uint32, rootSize uint32, pageSize uint32) {

// }

// func pdb7Parse(fn string) {
// 	// _PDB2_SIGNATURE = b"Microsoft C/C++ program database 2.00\r\n\032JG\0\0"
// 	// _PDB2_SIGNATURE_LEN = len(_PDB2_SIGNATURE)
// 	// _PDB2_FMT = "<%dsIHHII" % _PDB2_SIGNATURE_LEN
// 	_PDB7_SIGNATURE := "Microsoft C/C++ MSF 7.00\r\n\x1ADS\x00\x00\x00"
// 	_PDB7_SIGNATURE_LEN := len(_PDB7_SIGNATURE)
// 	readLen := _PDB7_SIGNATURE_LEN + 4 + 4 + 4 + 4 + 4
// 	f, _ := os.Open(fn)
// 	b := make([]byte, readLen)
// 	_, err := f.Read(b)
// 	if err != nil {
// 		panic(err)
// 	}
// 	signatureSize := _PDB7_SIGNATURE_LEN
// 	page_size_size := _PDB7_SIGNATURE_LEN + 4
// 	startPageSize := _PDB7_SIGNATURE_LEN + 4 + 4
// 	num_file_pages_size := _PDB7_SIGNATURE_LEN + 4 + 4 + 4
// 	root_size_size := _PDB7_SIGNATURE_LEN + 4 + 4 + 4 + 4
// 	reserved_size := _PDB7_SIGNATURE_LEN + 4 + 4 + 4 + 4 + 4
// 	signature := string(b[:signatureSize])
// 	pageSize := binary.LittleEndian.Uint32(b[signatureSize:page_size_size])          //00 04 00 00 uint32
// 	startPage := binary.LittleEndian.Uint32(b[page_size_size:startPageSize])         // 03 00 uint32
// 	numFilePages := binary.LittleEndian.Uint32(b[startPageSize:num_file_pages_size]) // 00 00 uint32
// 	rootSize := binary.LittleEndian.Uint32(b[num_file_pages_size:root_size_size])    // A3 20 00 00 uint32
// 	reserved := binary.LittleEndian.Uint32(b[root_size_size:reserved_size])          //B0 92 00 00 uint32
// 	if signature != _PDB7_SIGNATURE {
// 		panic("Unsupported file type")
// 	}
// 	fmt.Printf("pageSize: %d\n", pageSize)
// 	fmt.Printf("startPage: %d\n", startPage)
// 	fmt.Printf("numFilePages: %d\n", numFilePages)
// 	fmt.Printf("rootSize: %d\n", rootSize)
// 	fmt.Printf("reserved: %d\n", reserved)

// 	numRootPages := rootSize / pageSize
// 	if rootSize%pageSize != 0 {
// 		numRootPages += 1
// 	}
// 	fmt.Printf("numRootPages: %d\n", numRootPages)

// 	numRootIndexPages := (numRootPages * 4) / pageSize
// 	if (numRootPages*4)%pageSize != 0 {
// 		numRootIndexPages += 1
// 	}
// 	fmt.Printf("numRootIndexPages: %d\n", numRootIndexPages)

// 	b = make([]byte, numRootIndexPages*4)
// 	_, err = f.Read(b)
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Println(b)
// 	root_index_pages := make([]uint32, numRootIndexPages*4)
// 	for i := uint32(0); i < numRootIndexPages; i++ {
// 		root_index_pages[i] = binary.LittleEndian.Uint32(b[i*4 : (i+1)*4])
// 	}
// 	fmt.Println(root_index_pages)
// 	fmt.Printf("root_index_pages: %d\n", root_index_pages)

// 	root_page_data := make([]byte, 0)
// 	for _, v := range root_index_pages {
// 		if v == 0 {
// 			continue
// 		}
// 		f.Seek(int64(v*pageSize), 0)
// 		tmpbyte := make([]byte, pageSize)
// 		_, err = f.Read(tmpbyte)
// 		//fmt.Println(tmpbyte)
// 		if err != nil {
// 			panic(err)
// 		}
// 		root_page_data = append(root_page_data, tmpbyte...)
// 	}
// 	//fmt.Println(root_page_data)
// 	root_page_list := make([]uint32, numRootPages)
// 	for i := uint32(0); i < numRootPages; i++ {
// 		root_page_list[i] = binary.LittleEndian.Uint32(root_page_data[i*4 : (i+1)*4])
// 	}
// 	fmt.Print("root_page_list: ")
// 	fmt.Println(root_page_list)
// 	init_pdb7_root_stream(fn, root_page_list, numRootPages, rootSize, pageSize)
// 	// def _pages(length, pagesize):
// 	// num_pages = length // pagesize
// 	// if (length % pagesize):
// 	//     num_pages += 1
// 	// return num_pages
// }

// func main2() {
// 	fn := "C:\\Users\\ZZUF\\github\\pdbdump\\ntkrnlmp.pdb"
// 	f, _ := os.Open(fn)
// 	_PDB7_SIGNATURE := "Microsoft C/C++ MSF 7.00\r\n\x1ADS\x00\x00\x00"
// 	_PDB7_SIGNATURE_LEN := len(_PDB7_SIGNATURE)
// 	_PDB2_SIGNATURE := "Microsoft C/C++ program database 2.00\r\n\x0032JG\x00\x00"
// 	_PDB2_SIGNATURE_LEN := len(_PDB2_SIGNATURE)
// 	b := make([]byte, _PDB7_SIGNATURE_LEN)
// 	n, _ := f.Read(b)
// 	if string(b[:n]) == _PDB7_SIGNATURE {
// 		fmt.Println("TRUE _PDB7_SIGNATURE")
// 		pdb7Parse(fn)
// 	} else {
// 		b = make([]byte, _PDB2_SIGNATURE_LEN)
// 		f.Seek(0, 0)
// 		n, _ = f.Read(b)
// 		if string(b[:n]) == _PDB2_SIGNATURE {
// 			fmt.Println("TRUE _PDB2_SIGNATURE")
// 		} else {
// 			panic("Unsupported file type")
// 		}
// 	}
// }
