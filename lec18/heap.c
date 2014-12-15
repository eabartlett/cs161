#include <stdlib.h>

int main()
{
  int *x = (int *) malloc(sizeof(int));
  int y = *x;
  free(x);
  return 0;
}
