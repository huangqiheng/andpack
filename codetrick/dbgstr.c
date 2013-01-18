#include <stdio.h>
#include <windows.h>
#include "LightLoader.h"

int main(int argc, char* argv[]) 
{
	OutputDebugStringA("hallo dbgstr.exe");
	int i;
	char* debugstr;
	INTSTRING *intstr;
	char container[sizeof(INTSTRING)];

	for (i=1; i<argc; i++){
		debugstr = argv[i];
		memset(&container, 0, sizeof(container));
		strncpy(container, debugstr, sizeof(container) - 1);
		intstr = (INTSTRING*)&container[0];
		printf("PrintCode(%#I64XLL, %#I64XLL, %#I64XLL);//%s\n", intstr->a, intstr->b, intstr->c, container);
	}
	OutputDebugStringA("finish dbgstr.exe");
}
