#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

#include "arguments.h"
#include "sniff.h"
#include "parse_cap.h"

int main(int argc, const char *argv[])
{
        struct arguments config;
        int status;
        pcap_t *handle;

        struct sniff_stat stat;

        status = handle_arguments(argc, argv, &config);
        if (status) {
                printf_help();
                exit(EXIT_FAILURE);
        }
        printf_arguments(&config);

        //Sniff beacons to cap-file
        handle = pcap_init(&config);
        sniff(handle, &config);
        stat_sniff(handle);
        pcap_close(handle);

        //Parse cap-file to txt-file
        sniff_stat_init(&config, &stat);
        parse_cap(&config, &stat);

        free(stat.result);

        return 0;
}
