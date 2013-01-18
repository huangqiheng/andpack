#include <windows.h>
#include <stdio.h>
#include "../andpack/log_print.h"
#include "bin2head.h"

#define bin2inc_prefix "bin2inc_"

char* ResetFileExt(char* buffer, char* newext)
{
	int outnamesize = strlen(buffer);
	while (buffer[--outnamesize] != '.');
	strcpy((char*)&buffer[++outnamesize], newext);
	return buffer;
}

char* ResetShortFileName(char* buffer, char* newname)
{
	int outnamesize = strlen(buffer);
	while (buffer[--outnamesize] != '\\');
	strcpy((char*)&buffer[++outnamesize], newname);
	return buffer;
}

char* get_short_filename(char* buffer)
{
	int outnamesize = strlen(buffer);
	while (buffer[--outnamesize] != '\\');
	return &buffer[++outnamesize];
}

char* select_target_file(char* init_file)
{		
	static char full_packsrc_name[MAX_PATH];
	strcpy(full_packsrc_name, init_file);
	OPENFILENAME ofn; 
	memset(&ofn, 0, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = 0;
	ofn.lpstrFile = full_packsrc_name;
	ofn.nMaxFile = sizeof(full_packsrc_name);
	ofn.lpstrFilter = "All\0*.*\0PE file\0*.exe;*.dll\0";
	ofn.nFilterIndex = 2;
	ofn.lpstrFileTitle = NULL;
	ofn.lpstrTitle = "please select a PE file, as transfer target";
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileName(&ofn) == 0)
	{
		DbgPrint("src file pick error(%s)", full_packsrc_name);
		return (NULL);
	}
	return (full_packsrc_name);
}

char* get_init_file(char* path, char* file_name)
{
	static char full_path_name[256];
	GetFullPathName(path, 256, full_path_name, NULL);
	strcat(full_path_name, file_name);
	return (full_path_name);
}

char* get_init_tosave_file(char* path, char* file_name)
{
	static char full_path_name[256];
	GetFullPathName(path, 256, full_path_name, NULL);
	strcat(full_path_name, bin2inc_prefix);
	strcat(full_path_name, file_name);
	return (full_path_name);
}

char* select_tosave_file(char* init_file)
{
	static char to_save_name[MAX_PATH];
	strcpy(to_save_name, init_file);

	OPENFILENAME ofn; 
	memset(&ofn, 0, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = 0;
	ofn.lpstrFile = to_save_name;
	ofn.nMaxFile = sizeof(to_save_name);
	ofn.lpstrFilter = "All\0*.*\0inc file\0*.inc\0";
	ofn.nFilterIndex = 2;
	ofn.lpstrFileTitle = NULL;
	ofn.lpstrTitle = "please select a file to save, as transfer target";
	ofn.nMaxFileTitle = 0;
	//ofn.lpstrInitialDir = init_dir;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetSaveFileName(&ofn) == 0)
	{
		printf("src file pick error(%s)", to_save_name);
		return (NULL);
	}
	return (to_save_name);
}



int main (int argc, char *argv[])
{
	char* input_name = get_init_file("./", "stub.exe");
	char* input_file = select_target_file(input_name);
	if (input_file == NULL) return (0);
	DbgPrint("input file: %s", input_file);

	char* output_name = get_init_tosave_file("../../andpack/", get_short_filename(input_file));
	ResetFileExt(output_name, "inc");
	DbgPrint("init file: %s", output_name);

	char* tosave_file = select_tosave_file(output_name);
	if (tosave_file == NULL) return (0);
	DbgPrint("save to: %s", tosave_file);

	binfile_to_srcfile(input_file, tosave_file);
}
