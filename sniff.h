#ifndef SNIFF_H
#define SNIFF_H

#include <pcap/pcap.h>

#include "arguments.h"

//Init pcap to sniff beacons
pcap_t * pcap_init(const struct arguments *config);
void make_filter_expression(char * str, int memory_size, const char (*bssid)[18], int bssid_cnt);

//Executes sniff beacons
void sniff(pcap_t *handle, const struct arguments *config);
void stat_sniff(pcap_t *handle);

double timeval2double(const struct timeval *tm_val);

#endif
