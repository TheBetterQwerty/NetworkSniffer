#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "argparse.h"

static void print_help(char* arg) {
    printf("[HELP] Usage: sudo %s -i <interface> [--filter <filter>]\n", arg);
    printf("\n\t%-10s: interface name\n", "-i");
    printf("\t%-10s: filter type (e.g., TCP, UDP, ICMP)\n", "--filter");
    printf("\t%-10s: help page\n", "-h, --help");
}

void argparse(int args, char** argv, char** dev, char* filter, int* cnt) {
    if (args < 2)
    {  return;  }
    
    for (int i = 0; i < args; i++) {
        if ((strcmp("-h", argv[i]) == 0) || (strcmp("--help", argv[i]) == 0)) {
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
        }

        if ((strcmp("-i", argv[i]) == 0) && ( i + 1 < args)) {
            *dev = argv[i + 1];
        }

        if ((strcmp("--filter", argv[i]) == 0) && ( i + 1 < args)) {
            strncpy(filter, argv[i+1], 5 * sizeof(char));
            filter[strcspn(filter, " ")] = '\0';
        }

        if ((strcmp("-cnt", argv[i]) == 0) && ( i + 1 < args)) {
            *cnt = atoi(argv[i+1]);
        }
    }
}
