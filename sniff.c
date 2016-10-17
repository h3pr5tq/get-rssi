#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>

#include "sniff.h"
#include "arguments.h"


/*
 *Max length of snapshot in bytes
 *This value matches with number bytes of each packet are sniffed this application
 */
#define MAX_SNAPSHOT_LENGTH 512

/*
 *Initial pcap filter expression
 *and estimated size this expression
 */
#define INIT_FILTER_EXPRESSION "subtype beacon and (wlan addr2 "
#define SIZE_INIT_FILTER_EXPRESSION 50

//Init pcap to sniff beacons
pcap_t * pcap_init(const struct arguments *config)
{
        //init
        pcap_t *handle;
        char   errbuf[PCAP_ERRBUF_SIZE]; //Buffer for save error message
        int    status;

        handle = pcap_create(config->interface, errbuf);
        if (!handle) {
                fprintf(stderr, "system error: pcap_create: %s\n", errbuf);
                exit(EXIT_FAILURE);
        }

        status = pcap_set_snaplen(handle, MAX_SNAPSHOT_LENGTH);
        if (status) {
                fprintf(stderr, "system error: pcap_set_snaplen: %s\n", pcap_statustostr(status));
                exit(EXIT_FAILURE);
        }

        // ... //
        //set rfmon
        //set timeout
        //set buffersize - I try, but this option doesn't work for me
        //set time stamp type
        // these options must be before pcap_activate! //


        //activate
        status = pcap_activate(handle);
        if (status == PCAP_WARNING_TSTAMP_TYPE_NOTSUP) {

                fprintf(stderr, "system warning: pcap_activate: %s\n", pcap_statustostr(status));

        } else if (status == PCAP_WARNING ||
                   status == PCAP_WARNING_PROMISC_NOTSUP) {

                fprintf(stderr, "system warning: pcap_activate: %s\n"
                                "system warning: pcap_activate: %s\n", pcap_statustostr(status), pcap_geterr(handle));

        } else if (status == PCAP_ERROR_ACTIVATED           ||
                   status == PCAP_ERROR_PROMISC_PERM_DENIED ||
                   status == PCAP_ERROR_RFMON_NOTSUP        ||
                   status == PCAP_ERROR_IFACE_NOT_UP) {

                fprintf(stderr, "system error: pcap_activate: %s\n", pcap_statustostr(status));
                exit(EXIT_FAILURE);

        } else if (status) {
                fprintf(stderr, "system error: pcap_activate: %s\n"
                                "system error: pcap_activate: %s\n", pcap_statustostr(status), pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }


        //filter
        struct bpf_program fp;
        char filter_expression[SIZE_INIT_FILTER_EXPRESSION + MAX_BSSID * 17] = INIT_FILTER_EXPRESSION;

        make_filter_expression(filter_expression, SIZE_INIT_FILTER_EXPRESSION + MAX_BSSID * 17,
                               config->bssid, config->bssid_cnt);

        status = pcap_compile(handle, &fp, filter_expression, 0, PCAP_NETMASK_UNKNOWN);
        if (status) {
                fprintf(stderr, "system error: pcap_compile: %s\n", pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        status = pcap_setfilter(handle, &fp);
        if (status) {
                fprintf(stderr, "system error: pcap_setfilter: %s\n", pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }


        //printf info about configure of pcap
        status = pcap_snapshot(handle);
        if (status == PCAP_ERROR_NOT_ACTIVATED) {
                fprintf(stderr, "system error: pcap_snapshot: %s\n", pcap_statustostr(status));
                exit(EXIT_FAILURE);
        }
        printf("info: snapshot length = %d bytes\n", status);


        int *dlt_buf;
        status = pcap_list_datalinks(handle, &dlt_buf);
        if (status == PCAP_ERROR_NOT_ACTIVATED) {

                fprintf(stderr, "system error: pcap_list_datalinks: %s\n", pcap_statustostr(status));
                exit(EXIT_FAILURE);

        } else if (status == -1) {
                fprintf(stderr, "system error: pcap_list_datalinks: %s\n"
                                "system error: pcap_list_datalinks: %s\n", pcap_statustostr(status), pcap_geterr(handle));
                exit(EXIT_FAILURE);

        }

        printf("info: name of link-header: %s\n"
               "      description:         %s\n", pcap_datalink_val_to_name(*dlt_buf), pcap_datalink_val_to_description(*dlt_buf));
        for (int i = 1; i < status; i++)
                printf("info: name of link-header: %s\n"
                       "      description:         %s\n",
                        pcap_datalink_val_to_name(dlt_buf[i]), pcap_datalink_val_to_description(dlt_buf[i]));

        /*Unnecessary
        //Check present link-header: DLT_IEEE802_11_RADIO
        for (int i = 0; i < status; i++) {
                if (dlt_buf[i] == DLT_IEEE802_11_RADIO)
                        return handle;
                else {
                        fprintf(stderr, "sytem error: pcap_init: radiotap link-header is absent\n");
                        exit(EXIT_FAILURE);
                }
        }
        */

        return handle;
}

void make_filter_expression(char * str, int memory_size, const char (*bssid)[18], int bssid_cnt)
{
        //check fit or not filter expression in allocate memory
        int str_len = strlen(str);
        if (memory_size < str_len + bssid_cnt * 17 + 10) { //+10 reserve
                fprintf(stderr, "system_error: make_filter_expression: filter expression string doesn't fit in memory\n"
                                "system_error: make_filter_expression: report about this bug\n");
                exit(EXIT_FAILURE);
        }

        //make filter expression
        strcat(str, bssid[0]);
        for (int i = 1; i < bssid_cnt; i++) {
                strcat(str, " or ");
                strcat(str, bssid[i]);
        }
        strcat(str, ")");

        printf("info: pcap filter expression:\n"
               "      \"%s\"\n", str);
}

//Executes sniff beacons
void sniff(pcap_t *handle, const struct arguments *config)
{
        pcap_dumper_t      *dump_ptr;
        struct pcap_pkthdr h;
        const u_char       *frame_ptr;
        double             t1, t2;


        //dump-file
        dump_ptr = pcap_dump_open(handle, config->file_cap);
        if (!dump_ptr) {
                fprintf(stderr, "system error: pcap_dump_open: %s\n", pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }


        //sniff //CHANGE TIME CONTROL //LEAVE LOOP //PCAP_BREAKLOOP
        printf("info: start sniff wifi beacon frames...\n");
        frame_ptr = pcap_next(handle, &h);
        if (!frame_ptr)
                fprintf(stderr, "info / system warning: pcap_next\n");
        pcap_dump( (u_char *)dump_ptr, &h, frame_ptr );
        t1 = timeval2double(&h.ts);
        t2 = t1;

        while ( (t2 - t1) < (double)config->time  ) {

                frame_ptr = pcap_next(handle, &h);
                if (!frame_ptr)
                        fprintf(stderr, "info / system warning: pcap_next\n");
                pcap_dump( (u_char *)dump_ptr, &h, frame_ptr );
                t2 = timeval2double(&h.ts);

        }
        printf("info: finished sniff wifi beacon frames\n");


        pcap_dump_close(dump_ptr);
        printf("info: estimated sniff time = %.6f sec\n", t2 - t1);
}

void stat_sniff(pcap_t *handle)
{
        struct pcap_stat ps;
        int              status;

        status = pcap_stats(handle, &ps);
        if (status == -1) {
                fprintf(stderr, "system error: pcap_stats: %s\n", pcap_geterr(handle));
                exit(EXIT_FAILURE);
        } else {
                printf("info: number of frames received = %u\n"
                       "      number of frames drop (buffer / read timeout) = %u\n"
                       "      number of frames drop (driver / WNIC) = %u\n",
                       ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
        }
}

double timeval2double(const struct timeval *tm_val)
{
        double tm_double = tm_val->tv_sec + tm_val->tv_usec * 1.0e-6;
        return tm_double;
}

