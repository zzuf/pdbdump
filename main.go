package main

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output syscallwin.go main.go

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/bits"
	"net/http"
	"os"
	"syscall"
	"unsafe"

	"github.com/saferwall/pe"
	"golang.org/x/sys/windows"
)

//sys SymInitialize(hProcess windows.Handle, UserSearchPath unsafe.Pointer, fInvadeProcess bool) (ret bool) = Dbghelp.SymInitialize
//sys SymLoadModuleExW(hProcess unsafe.Pointer, hFile unsafe.Pointer, ImageName *uint16, ModuleName *uint16, BaseOfDll uint64, DllSize uint32, Data *MODLOAD_DATA, Flags uint32) (ret uint64) = Dbghelp.SymLoadModuleExW
//sys SymUnloadModule64(hProcess unsafe.Pointer, BaseOfDll uint64) (ret bool) = Dbghelp.SymUnloadModule64
//sys SymCleanup(hProcess windows.Handle) (ret bool) = Dbghelp.SymCleanup
//sys SymGetTypeFromNameW(hProcess unsafe.Pointer, BaseOfDll uint64, Name *uint16, Symbol *SYMBOL_INFO) (ret bool) = Dbghelp.SymGetTypeFromNameW

const (
	INVALID_HANDLE_VALUE         = windows.Handle(0xFFFFFFFF)
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0
	IMAGE_DIRECTORY_ENTRY_DEBUG  = 6
	IMAGE_DEBUG_TYPE_CODEVIEW    = 2
	CP_UTF8                      = uint32(65001)
	MAXDWORD                     = uint32(0xffffffff)
	MAX_SYM_NAME                 = 2000
)

type MODLOAD_DATA struct {
	ssize uint32
	ssig  uint32
	data  unsafe.Pointer
	size  uint32
	flags uint32
}

type SYMBOL_INFO_PACKAGE struct {
	si   SYMBOL_INFO
	name [MAX_SYM_NAME + 1]int8
}

type SYMBOL_INFO struct {
	SizeOfStruct uint32
	TypeIndex    uint32
	Reserved     [2]uint64
	Index        uint32
	Size         uint32
	ModBase      uint64
	Flags        uint32
	Value        uint64
	Address      uint64
	Register     uint32
	Scope        uint32
	Tag          uint32
	NameLen      uint32
	MaxNameLen   uint32
	Name         [1]uint16
}

type PERelocation struct {
	RVA  uint32
	Type uint16
}

type PECodeDebugInfo struct {
	Signature uint32
	Guid      windows.GUID
	Age       uint32
	PdbName   [1]int8
}

type PE struct {
	IsMemoryMapped          bool
	IsInAnotherAddressSpace bool
	HProcess                windows.Handle
	BaseAddress             uint64
	DosHeader               *pe.ImageDOSHeader
	NtHeader                *pe.ImageNtHeader
	OptHeader               interface{}
	DataDir                 [16]pe.DataDirectory
	SectionHeaders          []pe.Section
	ExportDirectory         *pe.ImageExportDirectory
	ExportedNames           *uint32
	ExportedNamesLength     uint32
	ExportedFunctions       *uint32
	ExportedOrdinals        *uint16
	NbRelocations           uint32
	Relocations             *PERelocation
	DebugDirectory          *pe.ImageDebugDirectory
	CodeviewDebugInfo       *PECodeDebugInfo
}

type PDBSymbol struct {
	PDBName        string
	PDBBaseAddress uint64
	SymHandle      windows.Handle
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func downloadFullFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func downloadPDB(guid windows.GUID, age uint32, fileName string) bool {
	var guid4 [8]byte
	for i := 0; i < 8; i++ {
		guid4[i] = bits.RotateLeft8(guid.Data4[8-i], 4)
	}
	pdbURI := fmt.Sprintf("/download/symbols/%s/%08X%04X%04X%016X%X/%s", fileName, guid.Data1, guid.Data2, guid.Data3, guid4, age, fileName)
	err := downloadFullFile(fileName, "https://msdl.microsoft.com"+pdbURI)
	if err != nil {
		return true
	} else {
		return false
	}
}

func downloadPDBFromPE(tmppe *PE, fileName string) bool {
	guid := tmppe.CodeviewDebugInfo.Guid
	age := tmppe.CodeviewDebugInfo.Age
	return downloadPDB(guid, age, fileName)
}

func loadSymbolsFromPE(tmppe *PE) *PDBSymbol {
	psbSymbol := &PDBSymbol{}
	pdbName := byte(tmppe.CodeviewDebugInfo.PdbName[0])
	sizeNeeded, err := windows.MultiByteToWideChar(CP_UTF8, 0, &pdbName, -1, nil, 0)
	if err != nil {
		panic(err)
	}
	pdbNameTmp := make([]uint16, sizeNeeded)
	_, err = windows.MultiByteToWideChar(CP_UTF8, 0, &pdbName, -1, &pdbNameTmp[0], sizeNeeded)
	if err != nil {
		panic(err)
	}
	psbSymbol.PDBName = syscall.UTF16ToString(pdbNameTmp)
	pdbName16ptr := syscall.StringToUTF16Ptr(psbSymbol.PDBName)
	if !fileExists(psbSymbol.PDBName) {
		downloadPDBFromPE(tmppe, psbSymbol.PDBName)
	}
	askedPdbBaseAddr := uint64(0x1337000)
	pdbImageSize := MAXDWORD
	cp, err := windows.GetCurrentProcess()
	if err != nil {
		panic(err)
	}
	pdbBaseAddr := SymLoadModuleExW(unsafe.Pointer(cp), nil, pdbName16ptr, nil, askedPdbBaseAddr, pdbImageSize, nil, 0)
	for pdbBaseAddr == 0 {
		lastErr := windows.GetLastError()
		if lastErr == windows.ERROR_SUCCESS {
			break
		}
		if lastErr == windows.ERROR_FILE_NOT_FOUND {
			fmt.Println("PDB file not found!")
			SymUnloadModule64(unsafe.Pointer(cp), askedPdbBaseAddr)
			SymCleanup(cp)
		}
		fmt.Printf("SymLoadModuleExW error : %d(%s)\n", windows.GetLastError(), windows.GetLastError().Error())
		askedPdbBaseAddr += 0x1000000
		pdbBaseAddr = SymLoadModuleExW(unsafe.Pointer(cp), nil, pdbName16ptr, nil, askedPdbBaseAddr, pdbImageSize, nil, 0)
	}
	psbSymbol.PDBBaseAddress = pdbBaseAddr
	return psbSymbol
}

func loadSymbolsFromImageFile(imageFilePath string) *PDBSymbol {
	pe, err := pe.New(imageFilePath, &pe.Options{})
	if err != nil {
		log.Fatalf("Error while opening file: %s, reason: %v", imageFilePath, err)
	}

	err = pe.Parse()
	if err != nil {
		log.Fatalf("Error while parsing file: %s, reason: %v", imageFilePath, err)
	}
	tmppe := peCreate(pe, false)
	pdbSymbols := loadSymbolsFromPE(tmppe)
	return pdbSymbols
}

func peSectionHeaderfromRVA(tmppe *PE, rva uint32) *pe.Section {
	sectionHeaders := tmppe.SectionHeaders
	for _, sectionHeader := range sectionHeaders {
		currSectionVA := sectionHeader.Header.VirtualAddress
		currSectionVSize := sectionHeader.Header.VirtualSize
		if currSectionVA <= rva && rva < (currSectionVA+currSectionVSize) {
			return &sectionHeader
		}
	}
	return nil
}

func peRVAtoAddr(tmppe *PE, rva uint32) uintptr {
	peBase := tmppe.DosHeader
	if tmppe.IsMemoryMapped {
		return uintptr(unsafe.Pointer(peBase)) + uintptr(rva)
	}
	rvaSectionHeader := peSectionHeaderfromRVA(tmppe, rva)
	if rvaSectionHeader != nil {
		return uintptr(unsafe.Pointer(peBase)) + uintptr(rvaSectionHeader.Header.PointerToRawData) + uintptr(rva-rvaSectionHeader.Header.VirtualAddress)
	} else {
		panic("return 0")
	}
}

func peCreate(pefile *pe.File, isMemoryMapped bool) *PE {
	tmppe := &PE{}
	tmppe.IsMemoryMapped = isMemoryMapped
	tmppe.IsInAnotherAddressSpace = false
	tmppe.HProcess = INVALID_HANDLE_VALUE
	tmppe.DosHeader = &pefile.DOSHeader
	tmppe.NtHeader = &pefile.NtHeader
	tmppe.OptHeader = &pefile.NtHeader.OptionalHeader
	switch tmppe.OptHeader.(type) {
	case pe.ImageOptionalHeader32:
		tmppe.BaseAddress = uint64(pefile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader32).ImageBase)
		tmppe.DataDir = pefile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader32).DataDirectory //(*pe.ImageDataDirectory)(unsafe.Pointer(pefile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader32).DataDirectory))
	case pe.ImageOptionalHeader64:
		tmppe.BaseAddress = uint64(pefile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader64).ImageBase)
		tmppe.DataDir = pefile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader64).DataDirectory
	}
	tmppe.SectionHeaders = pefile.Sections
	exportRVA := tmppe.DataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	if exportRVA == 0 {
		tmppe.ExportDirectory = nil
		tmppe.ExportedNames = nil
		tmppe.ExportedFunctions = nil
		tmppe.ExportedOrdinals = nil
	} else {
		tmppe.ExportDirectory = (*pe.ImageExportDirectory)(unsafe.Pointer(peRVAtoAddr(tmppe, exportRVA)))
		tmppe.ExportedNames = (*uint32)(unsafe.Pointer(peRVAtoAddr(tmppe, tmppe.ExportDirectory.AddressOfNames)))
		tmppe.ExportedFunctions = (*uint32)(unsafe.Pointer(peRVAtoAddr(tmppe, tmppe.ExportDirectory.AddressOfFunctions)))
		tmppe.ExportedOrdinals = (*uint16)(unsafe.Pointer(peRVAtoAddr(tmppe, tmppe.ExportDirectory.AddressOfNames)))
		tmppe.ExportedNamesLength = tmppe.ExportDirectory.NumberOfNames
	}
	tmppe.Relocations = nil
	debugRVA := tmppe.DataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
	if debugRVA == 0 {
		tmppe.DebugDirectory = nil
	} else {
		tmppe.DebugDirectory = (*pe.ImageDebugDirectory)(unsafe.Pointer(peRVAtoAddr(tmppe, debugRVA)))
		if tmppe.DebugDirectory.Type != IMAGE_DEBUG_TYPE_CODEVIEW {
			tmppe.DebugDirectory = nil
		} else {
			tmppe.CodeviewDebugInfo = (*PECodeDebugInfo)(unsafe.Pointer(peRVAtoAddr(tmppe, tmppe.DebugDirectory.AddressOfRawData)))
			if tmppe.CodeviewDebugInfo.Signature != 1111 {
				tmppe.DebugDirectory = nil
				tmppe.CodeviewDebugInfo = nil
			}
		}
	}
	return tmppe
}

func getSymbolOffset(symbol *PDBSymbol, symbolName string) uint64 {
	si := &SYMBOL_INFO_PACKAGE{}
	si.si.SizeOfStruct = uint32(binary.Size(SYMBOL_INFO{}))
	si.si.MaxNameLen = uint32(binary.Size(si.name))
	symbolName16ptr := syscall.StringToUTF16Ptr(symbolName)
	res := SymGetTypeFromNameW(unsafe.Pointer(symbol.SymHandle), symbol.PDBBaseAddress, symbolName16ptr, &si.si)
	if res {
		return si.si.Address - symbol.PDBBaseAddress
	} else {
		return 0
	}
}

func test() {
	symbol := loadSymbolsFromImageFile("C:\\windows\\system32\\ntoskrnl.exe")
	if symbol == nil {
		panic("test err")
	}
	fmt.Println(getSymbolOffset(symbol, "PspCreateProcessNotifyRoutine"))
}

func main() {
	// _, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	// if err != nil {
	// 	panic(err)
	// }
	test()
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
