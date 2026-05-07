#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../includes/argparse.h"

static void print_help(char* arg) {
    printf("[HELP] Usage: sudo %s -i <interface> [--filter <filter>]\n", arg);
    printf("\n\t%-10s: interface name\n", "-i");
    printf("\t%-10s: filter type (e.g., TCP, UDP, ICMP)\n", "--filter");
	printf("\n\t%-10s: number of packets\n", "--cnt");
    printf("\t%-10s: help page\n", "-h, --help");
}

void argparse(int args, char** argv, Config* parser) {
    if (args < 2) return;
	parser->cnt = -1;

    for (int i = 0; i < args; i++) {
        if ((strcmp("-h", argv[i]) == 0) || (strcmp("--help", argv[i]) == 0)) {
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
        }

        if ((strcmp("-i", argv[i]) == 0) && (i + 1 < args)) {
			parser->dev = argv[i++ +1];
			continue;
        }

        if ((strcmp("--filter", argv[i]) == 0) && (i + 1 < args)) {
            strncpy(parser->filter, argv[i++ +1], 5 * sizeof(char));
            parser->filter[strcspn(parser->filter, " ")] = '\0';
			continue;
        }

        if ((strcmp("--cnt", argv[i]) == 0) && (i + 1 < args)) {
            parser->cnt = atoi(argv[i++ +1]);
			continue;
        }

		if ((strcmp("--src", argv[i]) == 0) && (i + 1 < args)) {
			parser->src = argv[i++ + 1];
			continue;
		}

		if ((strcmp("--dst", argv[i]) == 0) && (i + 1 < args)) {
			parser->dst = argv[i++ +1];
			continue;
		}
    }
}
