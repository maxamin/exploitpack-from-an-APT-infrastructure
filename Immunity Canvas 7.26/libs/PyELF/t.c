#include <stdio.h>

int
main(int argc, char **argv, char **envp)
{
    char *p = NULL;
    int i;

    printf("### HI IM A NEW ELF BINARY ###\n");
    for (i = 0; i < argc; i ++)
        printf("argv[%d]: %s\n", i, argv[i]);
    for (i = 0; envp[i]; i ++)
        printf("envp[%d]: %s\n", i, envp[i]);

    return 0;
}
