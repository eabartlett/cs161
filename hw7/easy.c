/*
 *  Buffer overflow HW7 -easy (CS 161, Fall 2014)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void foo (char *s)
{
	char 	buf[4];
	int  	i;

	strcpy(buf, s);
	i = strlen(buf);
	printf("Your string has %d chars\n", i);
}

void bar()
{
	printf("What?  I am not supposed to be called!\n\n");
	fflush(stdout);
}

int main (int argc, char *argv[])
{
	if (argc != 2)
	{
		printf ("Usage: %s some_string", argv[0]);
		exit (-1);
	}
	foo(argv[1]);
	return 0;
}
