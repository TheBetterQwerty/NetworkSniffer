#ifndef ARGPARSE_H
#define ARGPARSE_H

#define SIZE 50
#define SNAPLEN 65535
#define PROMISC 1 // using promisc mode
#define TIMEOUT 1000 // 1 second

typedef struct {
	char filter[5];
	int cnt;
	char* dev;
	char* src;
	char* dst;
} Config;

void argparse(int args, char** argv, Config* parser);

#endif
