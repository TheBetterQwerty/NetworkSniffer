#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>

#include "../includes/argparse.h"

Config parser = { 0 };
int pkt_captured = 0;

void capture_packets(u_char* user __attribute_maybe_unused__, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data) {
    if (pkt_header->len < 14) {
        printf("[!] Packet too short!\n");
        return;
    }

    struct ip* ip_headers = (struct ip*) (pkt_data + 14);

    char* protocol = NULL;
    switch (ip_headers->ip_p) {
        case IPPROTO_ICMP: protocol = "ICMP"; break;
        case IPPROTO_UDP : protocol = "UDP"; break;
        case IPPROTO_TCP : protocol = "TCP"; break;
		case IPPROTO_RAW : protocol = "RAW"; break;
		default: return;
    }

    if (strncmp(protocol, parser.filter, strlen(parser.filter))) return;
	if (parser.cnt != -1 && pkt_captured > parser.cnt) exit(0);

	char* src_ip = inet_ntoa(ip_headers->ip_src);
	char* dst_ip = inet_ntoa(ip_headers->ip_dst);

	if (parser.src && strncmp(parser.src, src_ip, strlen(src_ip))) return; // Shows only specified src or dst
	if (parser.dst && strncmp(parser.dst, dst_ip, strlen(dst_ip))) return;

	printf(parser.cnt == -1 ? "[INFO] Packet Captured : \n" : "[INFO] Packet Captured (%d/%d): \n", pkt_captured, parser.cnt);

    printf("   %-20s: %s\n", "Source IP", src_ip);
    printf("   %-20s: %s\n", "Destination IP", dst_ip);


    if (strlen(protocol)) printf("   %-20s: %s\n", "Protocol", protocol);
    printf("   %-20s: %d bytes\n", "Packet Size", pkt_header->caplen);
    printf("-----------------------------------------\n");
	++pkt_captured;
}

char* select_dev(pcap_if_t* alldevsp) {
    int idx = 0;
    char** devs = malloc(SIZE * sizeof(char*));
    if (devs == NULL) {
        printf("[!] Error allocating memory!\n");
        return NULL;
    }

    printf("[INFO] Available Devices: \n");
    while ((alldevsp != NULL) && (idx < SIZE)) {
        devs[idx++] = alldevsp->name;
        printf("   %-2d. %-10s ", idx, alldevsp->name);
        if (alldevsp->description == NULL) {
            printf("(No description)\n");
        } else {
            printf("(%s)\n", alldevsp->description);
        }
        alldevsp = alldevsp->next;
    }

    devs = realloc(devs, idx * sizeof(char*));

    int input = -1;
    printf("[+] Enter your choice: ");
    scanf("%d", &input);
    input--;

    if ((input < 0) || (input > idx)) {
        printf("[!] Not a valid device!\n");
        return NULL;
    }

    char* dev = devs[input];
    free(devs);
    printf("-----------------------------------------\n");
    return dev;
}

int main(int args, char** argv) {

    argparse(args, argv, &parser);

    if (geteuid() != 0) {
        printf("[!] Elevated Privilages required to run this script. Use --help to see the help page\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevsp = NULL;

    if (pcap_findalldevs(&alldevsp, errbuf) < 0) {
        printf("[!] Error: %s\n", errbuf);
        return 1;
    }

    if (!parser.dev) parser.dev = select_dev(alldevsp);

    pcap_t* handle = pcap_open_live((const char*) parser.dev, SNAPLEN, PROMISC, TIMEOUT, errbuf);
    if (handle == NULL) {
        printf("[!] Error opening %s\n", parser.dev);
        goto cleanup;
    }

    printf("[*] Sniffing with %s\n", parser.dev);
    if (pcap_loop(handle, -1, capture_packets, NULL) < 0) {
        printf("[!] Error capturing packets!\n");
        goto cleanup;
    }

    cleanup:
        if (alldevsp != NULL) pcap_freealldevs(alldevsp);
        if (handle != NULL) pcap_close(handle);
        printf("[#] Exitting ... \n");
    return 0;
}
