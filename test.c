#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    FILE *file = fopen("/home/beringela/teste/teste.txt", "a");
    sleep(5);
    //fprintf(file, "append");
    fclose(file);
    return 0;
}
