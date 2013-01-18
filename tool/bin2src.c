#include <stdio.h>
#include "bin2head.h"


int main(int argc, char* argv[])
{
	if (argc != 3)
		return 0;

	binfile_to_srcfile(argv[1], argv[2]);
	return 0;
}
