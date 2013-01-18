#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include "global.h"

#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))
#define VATORVA(base, addr) ((INT)(addr) - (INT)(base))
#define NTHEADER(hModule)   ((PIMAGE_NT_HEADERS)RVATOVA((hModule), ((PIMAGE_DOS_HEADER)(hModule))->e_lfanew))
#define DATADIRECTORY(pNtHeader, nIndex) &(pNtHeader)->OptionalHeader.DataDirectory[(nIndex)]
#define VALIDRANGE(value, base, size) (((DWORD)(value) >= (DWORD)(base)) && ((DWORD)(value)<((DWORD)(base)+(DWORD)(size))))
#define DLLENTRY(hModule) ((DllEntryProc)RVATOVA ((DWORD)(hModule), NTHEADER(hModule)->OptionalHeader.AddressOfEntryPoint))
#define ENTRYRVA(hModule) (NTHEADER(hModule)->OptionalHeader.AddressOfEntryPoint)
#define SIZEOFIMAGE(hModule) (NTHEADER(hModule)->OptionalHeader.SizeOfImage)
#define IMAGEBASE(hModule) (NTHEADER(hModule)->OptionalHeader.ImageBase) 

__inline__ void* readMyAddr()
{
        void* value;
    __asm__(
		    ".byte 0xe8		\n\t"
		    ".long 0x00000000	\n\t"
		    "popl %0\n\t" 
		    :"=m" (value):);
        return value;
}

HMODULE get_module_base()
{
	DWORD pebase = (DWORD)readMyAddr();
	pebase = pebase & 0xFFFFF000;
	while (*((LPWORD)pebase) != IMAGE_DOS_SIGNATURE)
		pebase -= 0x1000;
	return (HMODULE)pebase;
}

long round_align(long val, long alignment)
{
	if( val % alignment )
		return (val + (alignment - (val % alignment)));
	return val;
}

PIMAGE_SECTION_HEADER get_spectial_section_byname(void* pe_base, const char *section_name)
{
        PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER(pe_base);
        PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(pNtHeader_File);

        int i;
        for (i=0; i<pNtHeader_File->FileHeader.NumberOfSections; i++)
        {
                if (stricmp(Sections[i].Name, section_name) == 0)
                {
                        return (PIMAGE_SECTION_HEADER)&Sections[i];
                }
        }

        return NULL;
}

int is_section_exists(void* pe_base, const char* section_name)
{
	if (*(short*)pe_base != 0x5a4d)
	{
		return (0);
	}
	return (get_spectial_section_byname(pe_base, section_name))? 1 : 0;
}

int is_section_exists_main(const char* section_name)
{
	void* pe_base = (void*)GetModuleHandle(NULL);
	return (is_section_exists(pe_base, section_name));
}

int is_section_exists_me(const char* section_name)
{
	void* pe_base = (void*)get_module_base();
	return (is_section_exists(pe_base, section_name));
}

void* get_section(void* pe_base, const char* section_name)
{
	if (pe_base)
	{
		PIMAGE_SECTION_HEADER aim_section = get_spectial_section_byname(pe_base, section_name);
		if (aim_section)
		{
			if (aim_section->VirtualAddress)
			{
				return (void*)RVATOVA(pe_base, aim_section->VirtualAddress);
			}
		}
	}
	return (NULL);
}

void* get_section_raw(void* file_base, const char* section_name)
{
	if (file_base)
	{
		PIMAGE_SECTION_HEADER aim_section = get_spectial_section_byname(file_base, section_name);
		if (aim_section)
		{
			if (aim_section->PointerToRawData)
			{
				return (void*)RVATOVA(file_base, aim_section->PointerToRawData);
			}
		}
	}
	return (NULL);
}

void* get_section_me(const char* section_name)
{
	void* pe_base = (void*)get_module_base();
	return (get_section(pe_base, section_name));
}

STARTUP* get_startup_section_me()
{
	return (STARTUP*)get_section_me(STUB_START_SECTION_NAME);
}

PACKAGE* get_package_section_me()
{
	return (PACKAGE*)get_section_me(PACKAGE_SECTION_NAME);
}

void* get_section_main(const char* section_name)
{
	void* pe_base = (void*)GetModuleHandleA(NULL);
	return (get_section(pe_base, section_name));
}

STARTUP* get_startup_section_main()
{
	return (STARTUP*)get_section_main(STUB_START_SECTION_NAME);
}

PACKAGE* get_package_section_main()
{
	return (PACKAGE*)get_section_main(PACKAGE_SECTION_NAME);
}

char* whoiam_realy_name(PACKAGE* package)
{
	if (package)
	{
		if (package->repack_whoami_index >= 0)
		{
			STORE_ITEM* repack_item = (STORE_ITEM*)PACKAGE(package->repack_app_dir);
			char* repack_name = (char*)PACKAGE(repack_item[package->repack_whoami_index]);
			return strdup(repack_name);
		}
		else if (package->repack_whoami_index == -1)
		{
			char* launch_name = (char*)PACKAGE(package->launch_exe);
			return strdup(launch_name);
		}
	}
	return (NULL);
}

char* whoiam_realy_name_me()
{
	PACKAGE* package = get_package_section_me();
	return whoiam_realy_name(package);
}

void* get_storepe_section_me()
{
	return get_section_me(ORIGIN_APP_SECTION_NAME);
}

int imemcpy_me(char *dest,char *src,int len)
{
        while(--len)
                dest[len] = src[len];
        return 0;
}

void* move_highbit(void* mem_base, long mem_size, long move_offset)
{
	imemcpy_me((char*)mem_base + move_offset, (char*)mem_base, mem_size);
}

int need_expend_headers(const void* file_image)
{
	PIMAGE_NT_HEADERS pNtHeader_File = (PIMAGE_NT_HEADERS)NTHEADER(file_image);
	long sectionCount = pNtHeader_File->FileHeader.NumberOfSections;
	long sizeOfHeaders = pNtHeader_File->OptionalHeader.SizeOfHeaders;

	long headers_sizes = ((long)pNtHeader_File - (long)file_image) + sizeof(IMAGE_NT_HEADERS);
	long sections_sizes = sectionCount * sizeof(IMAGE_SECTION_HEADER);
	long used_size = headers_sizes + sections_sizes;
	long freeSpace = sizeOfHeaders - used_size;

	return (freeSpace < sizeof(IMAGE_SECTION_HEADER));
}

void* append_section_raw(const void* target_file_base, long target_file_size, long* output_file_size,
		const char *SectionName, const void *NewRawData, long NewRawSize, long NewVirtualSize, long Characteristics)
{
	assert(NewRawData || NewRawSize || NewVirtualSize);
	assert(target_file_base && target_file_size);
	assert(SectionName);
	assert(output_file_size);

	if (Characteristics == 0)
	{
		Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_4BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	}

	if (NewVirtualSize < NewRawSize)
		NewVirtualSize = NewRawSize;

	long uFileSizeOri = target_file_size;
	void *pFileBaseOri = calloc(uFileSizeOri + NewRawSize + 0x1000*2, sizeof(char));
	memcpy(pFileBaseOri, target_file_base, uFileSizeOri);

	assert(pFileBaseOri);

	int i;
	PIMAGE_NT_HEADERS pNtHeader_File = (PIMAGE_NT_HEADERS)NTHEADER(pFileBaseOri);
	long sectionCount = pNtHeader_File->FileHeader.NumberOfSections;
	long sizeOfHeaders = pNtHeader_File->OptionalHeader.SizeOfHeaders;
	long fileAlignment = pNtHeader_File->OptionalHeader.FileAlignment;
	long sectionAlignment = pNtHeader_File->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(pNtHeader_File);
	PIMAGE_SECTION_HEADER NewAdd = Sections + sectionCount;

	//计算头节的剩余空间，如果不够，则需要扩展
	if (need_expend_headers(pFileBaseOri))
	{
		DbgPrint("expend headers");
		long bufsize = uFileSizeOri - sizeOfHeaders;
		char *tmpBuf = (char*)malloc(bufsize);
		memcpy(tmpBuf, pFileBaseOri + sizeOfHeaders, bufsize);
		memcpy(pFileBaseOri + sizeOfHeaders + fileAlignment, tmpBuf, bufsize);
		free(tmpBuf);

		long headers_align_ori = round_align(pNtHeader_File->OptionalHeader.SizeOfHeaders, sectionAlignment);
		pNtHeader_File->OptionalHeader.SizeOfHeaders += fileAlignment;
		long headers_align_now = round_align(pNtHeader_File->OptionalHeader.SizeOfHeaders, sectionAlignment);
		long header_section_offset = headers_align_now - headers_align_ori;

		for (i=0; i<sectionCount; i++)
		{
			Sections[i].PointerToRawData += fileAlignment;
			if (header_section_offset)
			{
				Sections[i].VirtualAddress += header_section_offset;
			}
		}

		if (header_section_offset)
		{
			DbgPrint("expend SizeOfImage: %d", header_section_offset);
			pNtHeader_File->OptionalHeader.SizeOfImage += header_section_offset;
		}

		DbgPrint("expend FileSize: %d", fileAlignment);
		uFileSizeOri += fileAlignment;
	}

	//计算新节应该加载的虚拟地址，应该填入的文件地址
	PIMAGE_SECTION_HEADER LastSection = Sections;
	PIMAGE_SECTION_HEADER LastFileSection = Sections;
	for (i=0; i<sectionCount; i++)
	{
		if (stricmp(Sections[i].Name, SectionName) == 0)
		{
			DbgPrint("already packed: %s", SectionName);
			free(pFileBaseOri);
			return (NULL);
		}
		if (Sections[i].VirtualAddress > LastSection->VirtualAddress)
			LastSection = &Sections[i]; 

		if ((Sections[i].SizeOfRawData) || (Sections[i].PointerToRawData))
			if (Sections[i].PointerToRawData >= LastFileSection->PointerToRawData)
				LastFileSection = &Sections[i]; 
	}
	long newSectionVirtualAddr = round_align(LastSection->VirtualAddress + LastSection->Misc.VirtualSize, sectionAlignment);
	long newSectionFileAddr = round_align(LastFileSection->PointerToRawData + LastFileSection->SizeOfRawData, fileAlignment);

	DbgPrint("last %s va:%x, %s raw:%x", LastSection->Name, newSectionVirtualAddr, LastFileSection->Name, newSectionFileAddr);

	//填充新节内容
	memset(NewAdd , 0, sizeof(IMAGE_SECTION_HEADER));
	strcpy(NewAdd->Name, SectionName);
	NewAdd->Misc.VirtualSize = NewVirtualSize;
	NewAdd->VirtualAddress = newSectionVirtualAddr;
	NewAdd->Characteristics = Characteristics; 

	if (NewRawData)
	{
		long extra_size = uFileSizeOri - newSectionFileAddr;
		NewAdd->PointerToRawData = newSectionFileAddr;
		NewAdd->SizeOfRawData = round_align(NewRawSize, fileAlignment);

		if (extra_size > 0)
		{
			DbgPrint("AppendSection:: has extra size %d bytes", extra_size);
			move_highbit(NewAdd->PointerToRawData + pFileBaseOri, extra_size, NewAdd->SizeOfRawData);
			memset(NewRawSize + NewAdd->PointerToRawData + pFileBaseOri, 0, NewAdd->SizeOfRawData - NewRawSize);
		}

		memcpy(NewAdd->PointerToRawData + pFileBaseOri, NewRawData, NewRawSize);
	}
	else
	{	
		NewAdd->PointerToRawData = 0;
		NewAdd->SizeOfRawData = 0;
	}
	uFileSizeOri += NewAdd->SizeOfRawData;

	DbgPrint("add section: %s", SectionName);
	DbgPrint("--- VirutalSize=%x", NewAdd->Misc.VirtualSize);
	DbgPrint("--- VirutalAddr=%x", NewAdd->VirtualAddress);
	DbgPrint("--- SizeOfRawData=%x", NewAdd->SizeOfRawData);
	DbgPrint("--- PointerToRawData=%x", NewAdd->PointerToRawData);

	//修正头信息
	if (NewAdd->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
	{
		pNtHeader_File->OptionalHeader.SizeOfInitializedData += NewAdd->SizeOfRawData;
		DbgPrint("--- SizeOfInitializedData += %x", NewAdd->SizeOfRawData);
	}

	if (NewAdd->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
	{
		pNtHeader_File->OptionalHeader.SizeOfUninitializedData += NewAdd->SizeOfRawData;
		DbgPrint("--- SizeOfUninitializedData += %x", NewAdd->SizeOfRawData);
	}

	if (NewAdd->Characteristics & IMAGE_SCN_CNT_CODE)
	{
		pNtHeader_File->OptionalHeader.SizeOfCode += NewAdd->SizeOfRawData;
		DbgPrint("--- SizeOfCode += %x", NewAdd->SizeOfRawData);
	}

	pNtHeader_File->FileHeader.NumberOfSections = ++sectionCount;
	pNtHeader_File->OptionalHeader.SizeOfImage += round_align(NewAdd->Misc.VirtualSize, sectionAlignment);

	*output_file_size = uFileSizeOri;
	DbgPrint("add section finish");
	return (pFileBaseOri);
}

long append_section_try(const void* target_file_base, long *section_va, long *section_raw)
{
	assert(target_file_base);
	assert(section_va);
	assert(section_raw);

	PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER(target_file_base);
	long sectionCount = pNtHeader_File->FileHeader.NumberOfSections;
	long fileAlignment = pNtHeader_File->OptionalHeader.FileAlignment;
	long sectionAlignment = pNtHeader_File->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(pNtHeader_File);

	//计算新节应该加载的虚拟地址，应该填入的文件地址
	PIMAGE_SECTION_HEADER LastSection = Sections;
	PIMAGE_SECTION_HEADER LastFileSection = Sections;
	int i;
	for (i=0; i<sectionCount; i++)
	{
		if (Sections[i].VirtualAddress > LastSection->VirtualAddress)
			LastSection = &Sections[i];

		if ((Sections[i].SizeOfRawData) || (Sections[i].PointerToRawData))
			if (Sections[i].PointerToRawData >= LastFileSection->PointerToRawData)
				LastFileSection = &Sections[i];
	}
	*section_va = round_align(LastSection->VirtualAddress + LastSection->Misc.VirtualSize, sectionAlignment);
	*section_raw = round_align(LastFileSection->PointerToRawData + LastFileSection->SizeOfRawData, fileAlignment);
	long ImageBase = pNtHeader_File->OptionalHeader.ImageBase;

	if (need_expend_headers(target_file_base))
	{
		*section_raw += fileAlignment;
		DbgPrint("GetPreAddSectionInfo:: expend 0x%x", fileAlignment);
	}

	return ImageBase;
}

void* append_section(const void* target_file_base, long target_file_size, long* output_file_size, 
		const char *section_name, const void* section_data, long section_size)
{
	return append_section_raw(target_file_base, target_file_size, output_file_size, section_name, section_data, section_size, 0, 0);
}

int section_to_file(const char* src_file, const char* section_name, const char* to_file)
{
	long file_size;
	char* mem_file_base;
	char* section_base;
	PIMAGE_SECTION_HEADER section_head;

	if ((mem_file_base = mem_from_file(src_file, &file_size, 0)) == NULL)
	{
		DbgPrint("session_to_file : mem_from_file");
		return (0);
	}

	if ((section_head = get_spectial_section_byname(mem_file_base, section_name)) == NULL)
	{
		DbgPrint("session_to_file : session[%s] not found", section_name);
		return (0);
	}

	section_base = (char*)RVATOVA(mem_file_base, section_head->PointerToRawData);
	file_size = section_head->Misc.VirtualSize;
	return mem_to_file(to_file, section_base, file_size);
}

long rva_to_offset(PIMAGE_NT_HEADERS pNtHeader, long RVA, long *SizeOfRawData)
{
	if ((RVA == 0) || (pNtHeader == NULL))
	{
		return (0);
	}

	int i;
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(pNtHeader);

	for (i=0; i<pNtHeader->FileHeader.NumberOfSections; i++)
	{
		if (VALIDRANGE(RVA, Sections[i].VirtualAddress, Sections[i].Misc.VirtualSize))
		{
			if (Sections[i].PointerToRawData)
			{
				*SizeOfRawData = Sections[i].SizeOfRawData;
				return (Sections[i].PointerToRawData + (RVA - Sections[i].VirtualAddress));
			}
		}
	}

	*SizeOfRawData = 0;
	return 0;
}

long rva_to_raw(PIMAGE_NT_HEADERS nt_headers, long rva)
{
	long size_of_rawdata;
	return rva_to_offset(nt_headers, rva, &size_of_rawdata);
}

long va_to_raw(PIMAGE_NT_HEADERS nt_headers, long va)
{
	long image_base = nt_headers->OptionalHeader.ImageBase;
	long rva = va - image_base;
	long size_of_rawdata;
	return rva_to_offset(nt_headers, rva, &size_of_rawdata);
}


char* resid_to_string(long id)
{
	char nodeText[256];
	switch(id)
	{
		case 1: return "Cursor";
		case 2: return "Bitmap";
		case 3: return "Icon";
		case 4: return "Menu";
		case 5: return "Dialog";
		case 6: return "String";
		case 7: return "FontDir";
		case 8: return "Font";
		case 9: return "Accelerator";
		case 10: return "RCDATA";
		case 11: return "MessageTable";
		case 12: return "GroupCursor";
		case 14: return "GroupIcon";
		case 16: return "Version";
		case 17: return "DlgInclude";
		case 19: return "PlugPlay";
		case 20: return "VXD";
		case 21: return "ANICursor";
		case 22: return "ANIIcon";
		case 23: return "HTML";
		default:
			 wsprintf(nodeText, "ID: %ld", id);
			 return strdup(nodeText);
	}
}


void record_max_offset(long* current, void* base_addr, long size)
{
	long current_val = *current;
	long new_val = (long)base_addr + size;
	*current = max(current_val, new_val);
}

char * UnicodeToANSI( const wchar_t* str )
{
	char* result;
	int textlen;
	textlen = WideCharToMultiByte( CP_ACP, 0, str, -1, NULL, 0, NULL, NULL );
	result =(char *)malloc((textlen+1)*sizeof(char));
	memset( result, 0, sizeof(char) * ( textlen + 1 ) );
	WideCharToMultiByte( CP_ACP, 0, str, -1, result, textlen, NULL, NULL );
	return result;
}

long EnumChildNodeSize(long* data_entry_list, const void* lpImageBase, PIMAGE_NT_HEADERS pNtHeaders, DWORD tableAddress, PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry, int depth)
{
	int i;
	char nodeText[256];
	long RunResult = 0;
	long temp_result = 0;

	char prefix_str[32];
	memset(prefix_str, 0, 32);
	for (i=0; i<depth; i++)
	{
		prefix_str[i*3] = ' ';
		prefix_str[i*3+1] = ' ';
		prefix_str[i*3+2] = ' ';
	}

	record_max_offset(&RunResult, pEntry, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));

	//先确定节点文本
	if(pEntry->NameIsString) //检测最高位是不是1
	{
		PIMAGE_RESOURCE_DIR_STRING_U pString = (PIMAGE_RESOURCE_DIR_STRING_U)(tableAddress + pEntry->NameOffset);
		record_max_offset(&RunResult, pString, sizeof(IMAGE_RESOURCE_DIR_STRING_U) + pString->Length * sizeof(wchar_t));

		wchar_t dirstr[64];
		memcpy((char*)&dirstr[0], (char*)&(pString->NameString[0]), pString->Length * sizeof(wchar_t));
		dirstr[pString->Length] = '\0';
		wsprintf(nodeText, "%sname: %s", prefix_str, UnicodeToANSI(dirstr));
	}
	else
	{
		if(depth == 1)
		{
			wsprintf(nodeText, "%sid: %s", prefix_str, resid_to_string(pEntry->Id));
		}
		else
		{
			wsprintf(nodeText, "%sid: %d", prefix_str, pEntry->Id);
		}
	}

	//输出节点文本
	//      DbgPrint(nodeText);

	//再确定节点类型（目录还是叶子）
	if(pEntry->DataIsDirectory)
	{
		PIMAGE_RESOURCE_DIRECTORY pDir = (PIMAGE_RESOURCE_DIRECTORY)(tableAddress + pEntry->OffsetToDirectory);
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pDir + sizeof(IMAGE_RESOURCE_DIRECTORY));
		for(i=0; i<(pDir->NumberOfNamedEntries + pDir->NumberOfIdEntries); i++, pEntries++)
		{
			temp_result = EnumChildNodeSize(data_entry_list, lpImageBase, pNtHeaders, tableAddress, pEntries, depth+1);
			RunResult = max (RunResult, temp_result);
		}
	}
	else
	{
		//叶子
		PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(tableAddress + pEntry->OffsetToData);
		record_max_offset(&RunResult, pDataEntry, sizeof(IMAGE_RESOURCE_DATA_ENTRY));

		//具体的资源属于位于：pData->OffsetToData，这是一个RVA（不是相对于资源表头部的偏移！）
		long* scan = data_entry_list;
		int index = 0;
		while (*scan)
		{
			index++;
			scan++;
		}
		*scan = pEntry->OffsetToData;

		//DbgPrint("%sRVA: %08X; Size = %ld Bytes; DataEntry(%d): %x", prefix_str, pDataEntry->OffsetToData, pDataEntry->Size, index, data_entry_list[index]);
	}

	return RunResult;
}


void* get_resource_dirs(const char* file_base, long file_size, long* res_dir_size, long* data_entry_list)
{
	*res_dir_size = 0;

	PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER(file_base);
	long ImageBase = pNtHeader_File->OptionalHeader.ImageBase;
	PIMAGE_DATA_DIRECTORY directory = DATADIRECTORY(pNtHeader_File, IMAGE_DIRECTORY_ENTRY_RESOURCE);

	if (directory->VirtualAddress == 0)
		return NULL;

	long lDirCopyOffset= rva_to_raw(pNtHeader_File,  directory->VirtualAddress);

	DbgPrint("resource base: %x", lDirCopyOffset);

	long RunResult = 0;
	PIMAGE_RESOURCE_DIRECTORY pResTable = (PIMAGE_RESOURCE_DIRECTORY)RVATOVA(file_base, lDirCopyOffset);
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResTable + sizeof(IMAGE_RESOURCE_DIRECTORY));

	int i;
	long temp_result;
	for (i=0; i<(pResTable->NumberOfNamedEntries + pResTable->NumberOfIdEntries); i++, pEntries++)
	{
		temp_result = EnumChildNodeSize(data_entry_list, file_base, pNtHeader_File, (DWORD)pResTable, pEntries, 1);
		RunResult = max (RunResult, temp_result);
	}

	*res_dir_size = RunResult - (long)pResTable;

	DbgPrint("enum resource done: %d(0x%x) bytes", *res_dir_size, *res_dir_size);

	void* run_result = malloc(*res_dir_size);
	memcpy(run_result, (char*)pResTable, *res_dir_size);
	return run_result;
}

int CorrectResourceRVA(void *packer_imagebase, const char* res_section_name, const char* app_section_name, long* data_entry_list)
{
	if (data_entry_list[0] == 0)
	{
		DbgPrint("CorrectResourceRVA:: input zero");
		return 1;
	}

	//取出资源节段信息
	PIMAGE_SECTION_HEADER res_section = get_spectial_section_byname(packer_imagebase, res_section_name);
	long res_dir_base = res_section->PointerToRawData;

	//填写pe文件头的资源目录地址
	PIMAGE_NT_HEADERS pNtHeader_File = NTHEADER(packer_imagebase);
	PIMAGE_DATA_DIRECTORY directory = DATADIRECTORY(pNtHeader_File, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	directory->VirtualAddress = res_section->VirtualAddress;
	directory->Size = res_section->Misc.VirtualSize;

	//取出保存的被打包app所在的节段，然后找出它的资源节段
	PIMAGE_SECTION_HEADER packed_section = get_spectial_section_byname(packer_imagebase, app_section_name);
	void* packed_imagebase = (void*)RVATOVA(packer_imagebase, packed_section->PointerToRawData);

	PIMAGE_NT_HEADERS pNtHeader_packed= NTHEADER(packed_imagebase);
	PIMAGE_DATA_DIRECTORY dir_packed = DATADIRECTORY(pNtHeader_packed, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	long res_dir_base_old = rva_to_raw(pNtHeader_packed, dir_packed->VirtualAddress);

	//终于，找到了新旧两个resource table的基址了
	DbgPrint("host res dir: 0x%x, app res dir: 0x%x", res_dir_base, res_dir_base_old + packed_section->PointerToRawData);
	void* distin_res_dir = (void*)RVATOVA(packer_imagebase, res_dir_base);
	void* source_res_dir = (void*)RVATOVA(packed_imagebase, res_dir_base_old);
	long two_image_offset = (long)packed_imagebase - (long)packer_imagebase;

	DbgPrint("two image offset: %x", two_image_offset);

	PIMAGE_RESOURCE_DATA_ENTRY pDataEntry;
	int index;
	for (index=0; data_entry_list[index]; index++)
	{
		pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(distin_res_dir + data_entry_list[index]);
		long old_OffsetToData = pDataEntry->OffsetToData;
		long data_entry_file = rva_to_raw(pNtHeader_packed, pDataEntry->OffsetToData);
		pDataEntry->OffsetToData = packed_section->VirtualAddress + data_entry_file;
		//DbgPrint("(%d) OffsetToData: %x -> %x (size:%d)", index, old_OffsetToData, pDataEntry->OffsetToData, pDataEntry->Size);
	}

	DbgPrint("all resource relocate finish.");
	return (1);
}

void* append_section_mainpe(const void* target_file_base, long target_file_size, long* output_file_size, 
		const char *section_name, const void* pe_to_pack, long pe_size)
{
	void* run_result = NULL;
	void* new_pe_base_2 = NULL;
	void* new_pe_base = NULL;
	void* pResDirAddr = NULL;
	long  new_pe_size;
	long new_pe_size_2;
	long lResDirSize;

	//在来源文件中取出资源目录表
	long* data_entry_list = malloc(0x1000 * sizeof(long));
	memset(data_entry_list, 0, 0x1000*sizeof(long));

	pResDirAddr = get_resource_dirs(pe_to_pack, pe_size, &lResDirSize, data_entry_list);

	//将资源表写入到节段中
	new_pe_base = append_section(target_file_base,target_file_size,&new_pe_size,RESOURCE_SECTION_NAME,pResDirAddr,lResDirSize);
	if (new_pe_base == NULL)
	{
		DbgPrint("can't add %s section to file", RESOURCE_SECTION_NAME);
		goto error_exit;
	}

	//将pe文件写入到节段中
	new_pe_base_2 = append_section(new_pe_base, new_pe_size, &new_pe_size_2, section_name, pe_to_pack, pe_size);

	if (new_pe_base_2 == NULL)
	{
		DbgPrint("can't add %s section to file", section_name);
		goto error_exit;
	}

	//修正资源表中data entry的RVA
	if (!CorrectResourceRVA(new_pe_base_2, RESOURCE_SECTION_NAME, section_name, data_entry_list))
	{
		DbgPrint("can't CorrectResourceRVA");
		goto error_exit;
	}

	run_result = new_pe_base_2;
	*output_file_size = new_pe_size_2;
	goto succee_exit;

error_exit:
	*output_file_size = 0;
	if (new_pe_base_2)
		free(new_pe_base_2);
succee_exit:
	free(pResDirAddr);
	free(data_entry_list);
	if (new_pe_base)
		free(new_pe_base);
	return (run_result);
}

