#include <windows.h>


typedef struct __cs_item
{
	char* cs_id;
	CRITICAL_SECTION cs;
	struct __cs_item* next;
} cs_item;

cs_item root_cs;

void enter_cs(const char* cs_id)
{
	cs_item* new_item = NULL;

	if (root_cs.next == NULL)
	{
		root_cs.cs_id = NULL;
		InitializeCriticalSection(&root_cs.cs);
		new_item = malloc(sizeof(cs_item));
		root_cs.next = new_item;
	}

	if (new_item)
	{
		new_item->cs_id = strdup(cs_id);
		InitializeCriticalSection(&new_item->cs);
		new_item->next = NULL;
		EnterCriticalSection(&new_item->cs);
		return;
	}

	cs_item* scan_item = root_cs.next;

	for (; scan_item; scan_item=scan_item->next)
	{
		if (strcmp(scan_item->cs_id, cs_id) == 0)
		{
			EnterCriticalSection(&scan_item->cs);
			return;
		}
	}

	new_item = malloc(sizeof(cs_item));
	new_item->cs_id = strdup(cs_id);
	InitializeCriticalSection(&new_item->cs);

	EnterCriticalSection(&root_cs.cs);
	new_item->next = root_cs.next;
	root_cs.next = new_item;
	LeaveCriticalSection(&root_cs.cs);

	EnterCriticalSection(&new_item->cs);
	return;
}

void leave_cs(const char* cs_id)
{
	cs_item* scan_item = root_cs.next;

	for (; scan_item; scan_item=scan_item->next)
	{
		if (strcmp(scan_item->cs_id, cs_id) == 0)
		{
			LeaveCriticalSection(&scan_item->cs);
			return;
		}
	}
}
