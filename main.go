package main

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output syscallwin.go main.go

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
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
//sys SymGetTypeInfo(hProcess unsafe.Pointer, ModBase uint64, TypeId uint32, GetType int32, pInfo unsafe.Pointer) (ret bool) = Dbghelp.SymGetTypeInfo

const (
	INVALID_HANDLE_VALUE         = windows.Handle(0xFFFFFFFF)
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0
	IMAGE_DIRECTORY_ENTRY_DEBUG  = 6
	IMAGE_DEBUG_TYPE_CODEVIEW    = 2
	CP_UTF8                      = uint32(65001)
	MAXDWORD                     = uint32(0xffffffff)
	MAX_SYM_NAME                 = 2000
)

type TI_FINDCHILDREN_PARAMS struct {
	Count   uint32
	Start   uint32
	ChildId [1]uint32
}

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
	fmt.Println(url)
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
	//var guid4 [8]byte
	// for i := 0; i < 8; i++ {
	// 	guid4[i] = guid.Data4[7-i] //bits.RotateLeft8(guid.Data4[7-i], 4)
	// }
	//byte rotate
	guid4 := binary.BigEndian.Uint64(guid.Data4[:])
	pdbURI := fmt.Sprintf("/download/symbols/%s/%08X%04X%04X%016X%X/%s", fileName, guid.Data1, guid.Data2, guid.Data3, guid4, age, fileName)
	err := downloadFullFile(fileName, "https://msdl.microsoft.com"+pdbURI)
	if err != nil {
		return true
	} else {
		return false
	}
}

func loadSymbolsFromPE(pefile *pe.File) *PDBSymbol {
	psbSymbol := &PDBSymbol{}
	var pdbName string
	var age uint32
	var guid pe.GUID
	switch pefile.Debugs[0].Info.(type) {
	case pe.CVInfoPDB70:
		pdb := pefile.Debugs[0].Info.(pe.CVInfoPDB70)
		pdbName = pdb.PDBFileName
		age = pdb.Age
		guid = pdb.Signature
	case pe.CVInfoPDB20:
		break
	}
	psbSymbol.PDBName = pdbName
	pdbName16ptr := syscall.StringToUTF16Ptr(pdbName)
	if !fileExists(pdbName) {
		downloadPDB(windows.GUID(guid), age, pdbName)
	}
	askedPdbBaseAddr := uint64(0x1337000)
	pdbImageSize := MAXDWORD
	cp, err := windows.GetCurrentProcess()
	if err != nil {
		panic(err)
	}
	psbSymbol.SymHandle = cp
	if !SymInitialize(cp, nil, false) {
		return nil
	}
	pdbBaseAddr := SymLoadModuleExW(unsafe.Pointer(cp), nil, pdbName16ptr, nil, askedPdbBaseAddr, pdbImageSize, nil, 0)
	for pdbBaseAddr == 0 {
		lastErr := windows.GetLastError()
		if lastErr == nil {
			fmt.Println("erro nil")
		}
		if lastErr == windows.ERROR_SUCCESS {
			break
		}
		if lastErr == windows.ERROR_FILE_NOT_FOUND {
			fmt.Println("PDB file not found!")
			SymUnloadModule64(unsafe.Pointer(cp), askedPdbBaseAddr)
			SymCleanup(cp)
		}
		fmt.Printf("SymLoadModuleExW error : %d(%s)\n", lastErr, lastErr.Error())
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
	pdbSymbols := loadSymbolsFromPE(pe)
	return pdbSymbols
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

func GetFieldOffset(symbol *PDBSymbol, structName string, fieldName string) uint32 {
	si := &SYMBOL_INFO_PACKAGE{}
	si.si.SizeOfStruct = uint32(binary.Size(SYMBOL_INFO{}))
	si.si.MaxNameLen = uint32(binary.Size(si.name))
	structName16ptr := syscall.StringToUTF16Ptr(structName)
	res := SymGetTypeFromNameW(unsafe.Pointer(symbol.SymHandle), symbol.PDBBaseAddress, structName16ptr, &si.si)
	if !res {
		return 0
	}
	childrenParam := &TI_FINDCHILDREN_PARAMS{}
	TI_GET_CHILDRENCOUNT := int32(13)
	TI_FINDCHILDREN := int32(7)
	TI_GET_SYMNAME := int32(1)
	TI_GET_OFFSET := int32(10)
	res = SymGetTypeInfo(unsafe.Pointer(symbol.SymHandle), symbol.PDBBaseAddress, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, unsafe.Pointer(&childrenParam.Count))
	if !res {
		return 0
	}
	cnt := int(childrenParam.Count)
	allocSize := binary.Size(TI_FINDCHILDREN_PARAMS{}) + (cnt-1)*4
	// fmt.Printf("TI_FINDCHILDREN_PARAMS_Size: %d, allocSize: %d\n", binary.Size(TI_FINDCHILDREN_PARAMS{}), allocSize)
	ptr := make([]byte, allocSize)
	childrenParam = (*TI_FINDCHILDREN_PARAMS)(unsafe.Pointer(&ptr[0]))
	childrenParam.Count = uint32(cnt)
	res = SymGetTypeInfo(unsafe.Pointer(symbol.SymHandle), symbol.PDBBaseAddress, si.si.TypeIndex, TI_FINDCHILDREN, unsafe.Pointer(childrenParam))
	offset := uint32(0)
	var childIds []uint32
	for i := 0; i < cnt; i++ {
		childIds = append(childIds, *(*uint32)(unsafe.Add(unsafe.Pointer(&ptr[0]), 8+i*4)))
	}
	for _, chidID := range childIds {
		var name *uint16
		SymGetTypeInfo(unsafe.Pointer(symbol.SymHandle), symbol.PDBBaseAddress, chidID, TI_GET_SYMNAME, unsafe.Pointer(&name))
		tmpName := windows.UTF16PtrToString(name)
		if !(tmpName == fieldName) {
			continue
		}
		SymGetTypeInfo(unsafe.Pointer(symbol.SymHandle), symbol.PDBBaseAddress, chidID, TI_GET_OFFSET, unsafe.Pointer(&offset))
		break
	}
	return offset
}

func test() {
	symbol := loadSymbolsFromImageFile("C:\\windows\\system32\\ntoskrnl.exe")
	if symbol == nil {
		panic("symbol err")
	}
	fmt.Println(getSymbolOffset(symbol, "PspCreateProcessNotifyRoutine"))
	fmt.Println(getSymbolOffset(symbol, "PspLoadImageNotifyRoutine"))
	fmt.Println(getSymbolOffset(symbol, "EtwThreatIntProvRegHandle"))
	fmt.Println(GetFieldOffset(symbol, "_EPROCESS", "Protection"))
	fmt.Println(GetFieldOffset(symbol, "_ETW_REG_ENTRY", "GuidEntry"))
	fmt.Println(GetFieldOffset(symbol, "_ETW_GUID_ENTRY", "ProviderEnableInfo"))
	fmt.Println(getSymbolOffset(symbol, "PsProcessType"))
	fmt.Println(getSymbolOffset(symbol, "PsThreadType"))
	fmt.Println(GetFieldOffset(symbol, "_OBJECT_TYPE", "CallbackList"))
}

func main() {
	test()
}
