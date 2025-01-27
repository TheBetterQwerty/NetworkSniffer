#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>

#define SIZE 10 // Maximum number of devs
#define SNAPLEN 65535 // Maximum size of a packet that is captured
#define TIMEOUT 1000 // in milliseconds

// Global Constants
char* dev = "";
int cnt = 0;
int promisc = 0;

void callback(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data) {
    struct ip* ip_headers = (struct ip*) (pkt_data + 14);
    printf("[#] %s -> %s \n", inet_ntoa(ip_headers->ip_src), inet_ntoa(ip_headers->ip_dst));
}

char* select_interface(pcap_if_t* alldevs) {
    char** found_devs = (char**) malloc(SIZE * sizeof(char*));
    if (!found_devs) {
        printf("[!] Error Allocating Memory!\n");
        return NULL;
    }

    int idx = 0;
    printf("[+] Interfaces Found ... \n");
    while (alldevs != NULL && idx < SIZE) {
        found_devs[idx] = alldevs->name;
        printf("  %d. %s", ++idx, alldevs->name);
        if (!alldevs->description) {
            printf(" [No Description Available]\n");
        } else {
            printf(" [%s]\n", alldevs->description);
        }
        alldevs = alldevs->next;
    }

    int choice = -1;
    printf("[?] Enter Your Choice: ");
    scanf("%d", &choice);
    choice--;

    if (choice < 0 || choice > idx) {
        printf("[!] Please Enter a Valid Choice!\n");
        return NULL;
    }

    char* dev = found_devs[choice];
    free(found_devs);
    return dev;
}

int initialize_network_devices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    int is_dev_empty = strlen(dev);
    pcap_if_t* alldevs;

    if (!is_dev_empty) {
        if (pcap_findalldevs(&alldevs, errbuf) < 0) {
            printf("[!] Error %s\n", errbuf);
            return 1;
        }

        dev = select_interface(alldevs);
        if (!dev) {
            pcap_freealldevs(alldevs);
            return 1;
        }
    }

    pcap_t* handle = pcap_open_live(dev, SNAPLEN, promisc, TIMEOUT, errbuf);
    if (strlen(errbuf)) {
        printf("[!] Error %s\n", errbuf);
        return 1;
    }

    printf("[*] Sniffing ...\n");
    if (pcap_loop(handle, cnt, callback, NULL) < 0) {
        printf("[!] Error\n");
    }

    // Cleanup
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}

int argparser(int args, char** argv) {
    int flag = 0;
    if (args < 2) {
        printf("[?] Usage: %s -i <interface (opt)> -p <promisc (false)> -cnt <packets (req)> \n", argv[0]);
        return 1;
    }

    for (int i = 0; i < args; i++) {
        if (!strcmp(argv[i], "-i") && (i+1 < args)) {
            dev = argv[i+1];
        }

        if (!strcmp(argv[i], "-p") && (i+1 < args)) {
            promisc = atoi(argv[i+1]);
        }

        if (!strcmp(argv[i], "-cnt") && (i+1 < args)) {
            cnt = atoi(argv[i+1]);
            flag++;
        }
    }

    if (flag == 0) {
        printf("[?] Usage: %s -i <interface (opt)> -p <promisc (false)> -cnt <packets (req)> \n", argv[0]);
        return 1;
    }
    return 0;
}

int main(int args, char** argv) {
    if (geteuid()) {
        printf("[!] Please run this script with root privilages!\n");
        return 1;
    }

    if (argparser(args, argv)) {
        return 1;
    }

    if (!initialize_network_devices()) {
        return 1;
    }

    return 0;
}
