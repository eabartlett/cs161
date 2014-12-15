#include <string.h>
#include <stdio.h>

void foo (char *s)
{
	char buf[4];
	strcpy(buf, s);
	printf("You entered: %s\n", buf);
}

void bar ()
{
	printf("What? I shouldn't have been called!!\n\n");
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Usage: %s some_string", argv[0]);
		return 2;
	}
	foo(argv[1]);
	return 0;
}
