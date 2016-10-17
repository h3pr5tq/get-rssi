#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>

#include "parse_cap.h"
#include "arguments.h"
#include "sniff.h"

#include "radiotap/radiotap_iter.h"
#include "radiotap/radiotap.h"
#include "radiotap/platform.h"

void parse_cap(const struct arguments *config, struct sniff_stat *stat)
{
        pcap_t             *handle;
        struct pcap_pkthdr *pkt_header;
        const u_char       *pkt_data;

        char   errbuf[PCAP_ERRBUF_SIZE];
        int    status;
        double t1;

        FILE *fp;
        struct bssid_inf wifi_inf;

        printf("info: start parse cap-file to txt-file...\n");

        //Open cap-file
        handle = pcap_open_offline(config->file_cap, errbuf);
        if (!handle) {
                fprintf(stderr, "system error: pcap_open_offline: %s\n", errbuf);
                exit(EXIT_FAILURE);
        }
        status = pcap_set_datalink(handle, DLT_IEEE802_11_RADIO); //Set type of link-header
        if (status) {
                fprintf(stderr, "system error: pcap_set_datalink: %s\n", pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        //Open txt-file
        fp = fopen(config->file_txt, "w");
        if (!fp) {
                fprintf(stderr, "system error: fopen: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
        }


        /* M A I N    L O O P */
        //Parse cap-file and write link info in txt-file
        status = pcap_next_ex(handle, &pkt_header, &pkt_data);

        if (status == -1) {
                fprintf(stderr, "system error: pcap_next_ex: %s\n", pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        t1 = timeval2double(&pkt_header->ts);
        wifi_inf.timestamp = timeval2double(&pkt_header->ts) - t1;
        wifi_inf.rssi = parse_radiotap(pkt_data);

        parse_beacon(pkt_data, wifi_inf.bssid);

        cnt_frames(wifi_inf.bssid, config->bssid, config->bssid_cnt, stat->result);
        stat->cnt_frames++;

        fprintf(fp, "timestamp (sec):  RSSI (dBm):  BSSID:\n\n");
        fprintf_bssid_inf(fp, &wifi_inf);

        while ( (status = pcap_next_ex(handle, &pkt_header, &pkt_data)) != -2 ) {

                if (status == -1) {
                        fprintf(stderr, "system error: pcap_next_ex: %s\n", pcap_geterr(handle));
                        exit(EXIT_FAILURE);
                }

                wifi_inf.timestamp = timeval2double(&pkt_header->ts) - t1;
                wifi_inf.rssi = parse_radiotap(pkt_data);

                parse_beacon(pkt_data, wifi_inf.bssid);

                cnt_frames(wifi_inf.bssid, config->bssid, config->bssid_cnt, stat->result);
                stat->cnt_frames++;

                fprintf_bssid_inf(fp, &wifi_inf);
        }
        fprintf_sniff_stat(fp, config, stat);

        //Deallocate resources
        pcap_close(handle);
        fclose(fp);
        printf("info: finished parse cap-file to txt-file\n");
}


/*
 *Extract wifi rssi value from radiotap-header of frames
 *This func executes parse regardless of radiotap header length (length depend on driver / WNIC)
 */
signed char parse_radiotap(const unsigned char *pkt_data)
{
        struct ieee80211_radiotap_iterator iterator;
        struct ieee80211_radiotap_header   *radiotap_header = (struct ieee80211_radiotap_header *)pkt_data;

        int max_length = get_unaligned_le16(&radiotap_header->it_len);
        int status;

        signed char rssi = 0;

        status = ieee80211_radiotap_iterator_init(&iterator, radiotap_header, max_length, NULL);
        if (status) {
                fprintf(stderr, "system error: ieee80211_radiotap_iterator_init: couldn't get iterator\n");
                exit(EXIT_FAILURE);
        }

        while (!status) {
                status = ieee80211_radiotap_iterator_next(&iterator);

                if (status)
                        continue;

                if (iterator.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL)
                        rssi = *iterator.this_arg;
        }

        return rssi;
}

/*
 *Extract source address (MAC of AP)
 *This function skips radiotap header
 */
void parse_beacon(const unsigned char *pkt_data, unsigned char *bssid)
{
        struct ieee80211_radiotap_header   *radiotap_header = (struct ieee80211_radiotap_header *)pkt_data;

        int radiotap_length = get_unaligned_le16(&radiotap_header->it_len);

        pkt_data += radiotap_length;       //skip radiotap header of frame
        pkt_data += NUMBER_BYTE_BEFORE_SA; //skip unnecessary beacon inforation

        for (int i = 0; i < 6; i++)
                bssid[i] = *(pkt_data + i);
}

//Wtire to file @struct bssid_inf information
void fprintf_bssid_inf(FILE *fp, const struct bssid_inf *wifi_inf)
{
        fprintf(fp, "%-18.6f%-13hhd", wifi_inf->timestamp, wifi_inf->rssi);
        for (int i = 0; i < 5; i++)
                fprintf(fp, "%02X:", wifi_inf->bssid[i]);
        fprintf(fp, "%02X\n", wifi_inf->bssid[5]);
}

//
void cnt_frames(const unsigned char *frame_bssid_num, const char (*arg_bssid)[18], const int arg_bssid_cnt, unsigned int *result)
{
        int status;
        char frame_bssid_str[18];
        bssid_num2str(frame_bssid_num, frame_bssid_str);

        for (int i = 0; i < arg_bssid_cnt; i++) {
                status = strcmp(frame_bssid_str, arg_bssid[i]);
                if (!status)
                        result[i] += 1;;
        }

}

void bssid_num2str(const unsigned char *frame_bssid_num, char *frame_bssid_str)
{
        int status = 0;
        char *ptr = frame_bssid_str;

        for (int i = 0; i < 5; i++) {
                ptr += status;
                status = sprintf(ptr, "%02X:", frame_bssid_num[i]);
                if (status != 3)
                        fprintf(stderr, "system error: bssid_num2str: sprintf error\n");
        }
        sprintf(ptr + status, "%02X", frame_bssid_num[5]);
}

void sniff_stat_init(const struct arguments *config, struct sniff_stat *stat)
{
        stat->cnt_bssid = config->bssid_cnt;
        stat->result = (unsigned int *) calloc (stat->cnt_bssid, sizeof(unsigned int));
        stat->cnt_frames = 0;
}

void fprintf_sniff_stat(FILE *fp, const struct arguments *config, const struct sniff_stat *stat)
{
        fprintf(fp, "________________________________________________\n\n");

        fprintf(fp, "Number of all sniff beacon frames: %u (it coincides with number of RSSI values)\n", stat->cnt_frames);
        for (int i = 0; i < stat->cnt_bssid; i++) {
                fprintf(fp, "BSSID %s : %u of %u\n", config->bssid[i], stat->result[i], stat->cnt_frames);
        }
}
