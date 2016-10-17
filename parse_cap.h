#ifndef PARSE_CAP_H
#define PARSE_CAP_H

#include <stdint.h>

#include "arguments.h"

/*
 *Number of bytes is before field with Source Address
 *Source Address is MAC of AP (BSSID)
 */
#define NUMBER_BYTE_BEFORE_SA 10

/*
 * @bssid - MAC of AP (BSSID)
 * @rssi - wifi signal strength value of the BSSID
 * @timestamp - time of measure signal strength
 */
struct bssid_inf {
        unsigned char bssid[6]; //?
        signed char   rssi;
        double        timestamp;
};

/*
 *Finish statistic of sniff/parse frames
 * @cnt_frames - number of all sniff/parse frames
 * @cnt_bssid - number of BSSIDs; the program sniffs frames these BSSIDs
 * @result - array (1 x cnt_bssid); each cell contain number frames certain BSSID
 */
struct sniff_stat {
        unsigned int cnt_frames;
        unsigned int cnt_bssid;
        unsigned int *result;
};

void parse_cap(const struct arguments *config, struct sniff_stat *stat);

/*
 *Extract wifi rssi value from radiotap-header of frames
 *This func executes parse regardless of radiotap header length (length depend on driver / WNIC)
 */
signed char parse_radiotap(const unsigned char *pkt_data);

/*
 *Extract source address (MAC of AP)
 *This function skips radiotap header
 */
void parse_beacon(const unsigned char *pkt_data, unsigned char *bssid);

//Wtire to file @struct bssid_inf information
void fprintf_bssid_inf(FILE *fp, const struct bssid_inf *wifi_inf);

void sniff_stat_init(const struct arguments *config, struct sniff_stat *stat);

void cnt_frames(const unsigned char *frame_bssid_num, const char (*arg_bssid)[18], const int arg_bssid_cnt, unsigned int *result);
void bssid_num2str(const unsigned char *frame_bssid_num, char *frame_bssid_str);
void fprintf_sniff_stat(FILE *fp, const struct arguments *config, const struct sniff_stat *stat);

#endif
