#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void* read_file(char* input_file, unsigned long* file_size) 
{
	FILE *fpMem = fopen(input_file,"rb");
	fseek (fpMem, 0, SEEK_END);
	int nFileSize = ftell (fpMem);
	fseek(fpMem, 0, SEEK_SET);

	void* data = malloc(nFileSize);
	fread(data, 1, nFileSize, fpMem);
	fclose(fpMem);

	*file_size = nFileSize;
	return (data);
}

int is_path_break(char char2chk)
{
	return ((char2chk == '\\') || (char2chk == '/'))? 1 : 0;
}


char* seek_short_file_name(char* buffer)
{
	int outnamesize = strlen(buffer);
	while (!is_path_break(buffer[outnamesize]))
		outnamesize--;
	return &buffer[++outnamesize];
}

void make_capsule_headfile(char* filename, void* file_base, unsigned long size_of_file) 
{
        FILE *fp;
        fp = fopen(filename, "wb");

	char* short_name = seek_short_file_name(filename);
	short_name = strdup(short_name);

	int len = strlen(short_name);
	int i;
	int last_pos = 0;
	for (i=0; i<len; i++)
	{
		if (short_name[i] == '.')
		{
			short_name[i] = '_';
			last_pos = i;
		}
	}
	if (last_pos)
		short_name[last_pos] = '\0';

	fprintf(fp, "#ifndef __%s_h_once__\n", short_name);
	fprintf(fp, "#define __%s_h_once__\n\n", short_name);

        fprintf(fp, "#define %s_size %lu\n\n", short_name, size_of_file);
        fprintf(fp, "static char %s[%s_size] = {\n", short_name, short_name);

        int nLine = size_of_file / 16;
        int nLast = size_of_file % 16;
        int ii, jj;
        unsigned char* sScan = (unsigned char*)file_base;

        for (ii=0; ii<nLine; ii++) {
            fprintf (fp, "/*%.4x*/", ii);
            for (jj=0; jj<16; jj++) {
                fprintf (fp, "0x%.2X,", sScan [ii*16 + jj]);
            }
            fputs ("\n", fp);
        }

        if (nLast > 0) {
                fprintf (fp, "/*%.4x*/", ii);
                for (jj=0; jj<nLast; jj++) {
                    fprintf (fp, "0x%x,", sScan [ii*16 + jj]);
                }
        }
        fseek(fp, -1, SEEK_END);
        fprintf(fp, "\n};\n");
	fprintf(fp, "#endif\n");
        fclose(fp);
}


void binfile_to_srcfile(char* bin_file_name, char* src_file_name)
{
	unsigned long file_size;
	char* file_base = read_file(bin_file_name, &file_size);
	make_capsule_headfile(src_file_name, file_base, file_size);
}
