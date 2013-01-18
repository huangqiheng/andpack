#include <windows.h>
#include <winnt.h>
#include <stdio.h>

int main (int argc, char *argv[])
{
    if (argc == 2) {
	char* bin_file_name = argv[1];
	int bin_filename_len = strlen(bin_file_name);
	if (bin_filename_len > 4) {
		printf("ready to loadlibraryA\n");
		HANDLE h = LoadLibrary(bin_file_name);
		printf("load result %x\n", h);
	} 
    }
}
