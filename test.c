#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    FILE *file = fopen("/home/beringela/teste/teste.txt", "w");
    sleep(5);
    fclose(file);
    return 0;
}