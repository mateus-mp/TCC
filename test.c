#include <stdio.h>

int main() {
  FILE *f;
  for (int i = 0; i < 10; i++) {
    f = fopen("/home/mateus/teste/teste.txt", "r");
    fclose(f);
  }
  return 0;
}

