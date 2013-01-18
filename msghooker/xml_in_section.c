#include <windows.h>
#include <assert.h>
#include <mxml.h>

#define RVATOVA(base, offset) (((INT)(base) + (INT)(offset)))
#define NTHEADER(hModule)   ((PIMAGE_NT_HEADERS)RVATOVA((hModule), ((PIMAGE_DOS_HEADER)(hModule))->e_lfanew))


static void DbgPrint_s(const char* format, ...)
{       
	static char dbg_msg_buff[0x1000]; 
        if (format)
        {
                va_list args;
                va_start(args, format);
                int len = wvsprintfA(dbg_msg_buff, format, args);
                va_end(args);
		OutputDebugStringA(dbg_msg_buff);
        }
}

static PIMAGE_SECTION_HEADER get_spectial_section_byname(void* pe_base, const char *section_name)
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

static void* get_section(void* pe_base, const char* section_name)
{
	if ((pe_base) && (section_name))
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

	DbgPrint("can't get_section from \"%x\"'s %s", pe_base, section_name);
	return (NULL);
}

static void* get_section_raw(void* file_base, const char* section_name)
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


const char* image_to_xmlstr(void* image_base, const char* section_name)
{
	return (const char*)get_section(image_base, section_name);
}

const char* file_to_xmlstr(void* file_base, const char* section_name)
{
	return (const char*)get_section_raw(file_base, section_name);
}

DWORD local_heap_tls = 0;

HANDLE get_tls_heap()
{
	if (local_heap_tls == 0)
	{
		local_heap_tls = TlsAlloc();
		if (local_heap_tls == 0)
		{
			return (NULL);
		}
	}

	void* tls_val = TlsGetValue(local_heap_tls);

	if (tls_val == NULL)
	{
		HANDLE heap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);
		if (heap == 0)
		{
			return (NULL);
		}
		tls_val = (void*)heap;
		TlsSetValue(local_heap_tls, tls_val);
	}

	return (HANDLE)tls_val;
}

void* malloc_tls(size_t size)
{
	return HeapAlloc(get_tls_heap(), HEAP_NO_SERIALIZE, size);
}

void free_tls()
{
	if (TlsGetValue(local_heap_tls))
	{
		HeapDestroy(get_tls_heap());
		TlsFree(local_heap_tls);
		local_heap_tls = 0;
	}
}

char* strdup_tls(const char* src)
{
	char* new_str = malloc_tls(strlen(src) + 1);
	strcpy(new_str, src);
	return (new_str);
}

const char*  set_keyvalue(const char* xmlstr, const char* catelog_name, const char* key_name, const char* value)
{
	if ((!catelog_name) || (!key_name) || (!value))
	{
		DbgPrint("get_keyvalue input parameter error");
		return (NULL);
	}

	mxml_node_t *xml;

	if (xmlstr == NULL)
	{
		xml = mxmlNewXML("1.0");
	}
	else
	{
		xml = mxmlLoadString(NULL, xmlstr, MXML_TEXT_CALLBACK);
	}

	if (xml == NULL)
	{
		DbgPrint("xml load err: %s", xmlstr);
		return (NULL);
	}

	mxml_node_t *catelog = mxmlFindElement(xml, xml, catelog_name, NULL, NULL, MXML_DESCEND);

	if (catelog == NULL)
	{
		catelog = mxmlNewElement(xml, catelog_name);
	}

	mxml_node_t *node = mxmlFindElement(catelog,catelog,key_name,NULL,NULL,MXML_DESCEND);
	if (node)
	{
		mxmlSetText(node, 0, value);
	}
	else
	{
		node = mxmlNewElement(catelog, key_name);
		mxmlNewText(node, 0, value);
	}

	mxmlSetWrapMargin(2);
	char* system_xmlstr = strdup_tls(mxmlSaveAllocString(xml, MXML_TEXT_CALLBACK));
	mxmlDelete(xml);

	return (system_xmlstr);
}

const char** get_keyvalue(const char* xmlstr, const char* catelog_name, const char* key_name)
{
	if (catelog_name == NULL)
	{
		DbgPrint("get_keyvalue input parameter error");
		return (NULL);
	}

	if (xmlstr == NULL)
	{
		free_tls();
		return (NULL);
	}

	mxml_node_t *tree = mxmlLoadString(NULL, xmlstr, MXML_TEXT_CALLBACK);

	if (tree == NULL)
	{
		DbgPrint("xml load err: %s", xmlstr);
		return (NULL);
	}

	mxml_node_t *catelog = mxmlFindElement(tree, tree, catelog_name, NULL, NULL, MXML_DESCEND);

	if (catelog == NULL)
	{
		DbgPrint("mxmlFindElement err");
		mxmlDelete(tree);
		return (NULL);
	}

	typedef struct _keyval_item
	{
		struct _keyval_item *next;
		char* keyname;
		char* keyvalue;
	} keyval_item;

	keyval_item* key_val_lst = NULL;
	int item_count = 0;

	mxml_node_t* current = catelog;
	while (current = mxmlFindElement(current, catelog, key_name, NULL, NULL, MXML_DESCEND))
	{
		const char* keyname =  current->value.element.name;
		const char* keyvalue = current->child->value.text.string;

		DbgPrint("found key:%s, val:%s", keyname, keyvalue);

		keyval_item* new_item = malloc_tls(sizeof(keyval_item));
		new_item->next = key_val_lst;
		new_item->keyname = strdup_tls(keyname);
		new_item->keyvalue = strdup_tls(keyvalue);
		key_val_lst = new_item;
		item_count++;
	}

	mxmlDelete(tree);

	if (key_val_lst == NULL)
	{
		DbgPrint("found nothing of %s", catelog_name);
		return(NULL);
	}

	const char** result = malloc_tls((item_count+1)*sizeof(char*)*2);

	int i;
	keyval_item* scan = key_val_lst;
	for (i=0; i<item_count*2; i+=2, scan=scan->next)
	{
		result[i] = scan->keyname;
		result[i+1] = scan->keyvalue;
	}
	result[i] = NULL;
	result[i+1] = NULL;
	return (result);
}

const char** get_catelog(const char* xmlstr, const char* catelog_name)
{
	return (get_keyvalue(xmlstr, catelog_name, NULL));
}
