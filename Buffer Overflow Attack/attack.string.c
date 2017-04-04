#include<stdio.h>
int main(int args, char *argv[]){

char input[112] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
fputs(input, stdout);
fputs(argv[1], stdout);
return 0;
}