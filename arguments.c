#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <getopt.h>
#include "arguments.h"


int handle_arguments(const int argc, const char *argv[], struct arguments *config)
{
        int opt, longind, status;
        uint_least32_t is_all_arguments = 0x0000;
        const struct option longopts[] = {
                {"interface", required_argument, NULL, 'i'},
                {"file",      required_argument, NULL, 'f'},
                {"bssid",     required_argument, NULL, 'b'},
                {"time",      required_argument, NULL, 't'},
                {NULL,        0,                 NULL,  0 }
        };

        opterr = 0;

        while ( (opt = getopt_long(argc, (char * const *)argv, "i:f:b:t:", longopts, &longind)) != -1 ) {
                switch (opt) {
                        case 'i': config->interface = optarg;
                                  is_all_arguments |= 0x0001;
                                  break;

                        case 'f': status = parse_arg_file(optarg, config->file_cap, config->file_txt, MAX_LEN_FILE_NAME);
                                  if (status)
                                        return 1;
                                  is_all_arguments |= 0x0010;
                                  break;

                        case 'b': status = parse_arg_bssid(optarg, config->bssid, &config->bssid_cnt);
                                  if (status) {
                                        fprintf(stderr, "user error: BSSIDs is not correct\n");
                                        return 1;
                                  }
                                  printf("info: finished parse BSSIDs\n");
                                  is_all_arguments |= 0x0100;
                                  break;

                        case 't': config->time = atoi(optarg);
                                  if (config->time <= 0) {
                                        fprintf(stderr, "user error: sniff time - is not positive integer\n");
                                        return 1;
                                  }
                                  is_all_arguments |= 0x1000;
                                  break;

                        default : return 1;
                }
        }

        return (is_all_arguments == 0x1111) ? 0 : 1;
}


int parse_arg_bssid(const char *arg_bssid, char (*bssid)[18], int * const bssid_cnt)
{
        printf("info: start parse BSSIDs...\n");

        //check the first symbol of optarg
        if (*arg_bssid == '\0')
                return 1;

        int j = 1; //numer of MACs
        int i = 1; //numer of symbol in MAC
        while (1) {

                //check finish of MAC, or exist yet other MACs
                if (i == 18) {

                        bssid[j-1][i-1] = '\0';
                        if (*arg_bssid == ',') {

                                arg_bssid++;
                                i = 1;
                                j++;

                                if (j >= MAX_BSSID) {
                                        fprintf(stderr, "user error: parse_arg_bssid: excess of MAX_BSSID\n");
                                        return 1;
                                }

                                continue;

                        } else {
                                *bssid_cnt = j;
                                return 0;
                        }
                }

                //check symbol belong MAC
                if ( isxdigit(*arg_bssid) ||
                     (i % 3 == 0 && *arg_bssid == ':') )

                        bssid[j-1][i-1] = *arg_bssid;

                else
                        return 1;

                arg_bssid++;
                i++;
        }

        return 1;
}


int parse_arg_file(const char *arg_file, char *file_cap, char *file_txt, int max_len_file_name)
{
        if ( strlen(arg_file) + 9 > max_len_file_name ) { //+9 = .cap + .txt + '\0'
                fprintf(stderr, "user error: parse_arg_file: file name too long, sorry\n");
                return 1;
        }

        file_cap[0] = '\0';
        file_txt[0] = '\0';

        strcat(file_cap, arg_file);
        strcat(file_cap, ".cap");

        strcat(file_txt, arg_file);
        strcat(file_txt, ".txt");

        return 0;
}

void printf_help(void)
{
	printf("Get-rssi v0.1 2016. Questions and bugs send to <h3pr5tq@gmail.com>\n"
               "Execute sniff beacons specified BSSID (MAC of AP) to cap-file\n"
               "After execute parse cap-file to txt-file; the txt-file will contain wifi rssi values\n\n"

	       "Usage:\n"
	       " get-rssi  -i <interface name>  -f <file name>  -b <BSSID>  -t <sniff time>\n"
	       "Required arguments:\n"
	       " -i,                             Wifi interface name (in monitor mode)\n"
	       " --interface=<mon0>              For found out the name, use iw or airmon-ng\n\n"

	       " -f,                             Path to file\n"
	       " --file=<~/wifi/rssi>            The program creates 2 files: file.cap and file.txt\n\n"

	       " -b,                             One or more BSSIDs (MAC of AP)\n"
               " --bssid=<01:FA:23:18:12:F2>     Sniff only beacons of these BSSIDs\n\n"

	       " -t,                             Sniff time in sec (positive integer)\n"
	       " --time=<10>                     Approximately correspond program's runtime\n\n"

               "NOTE: 1)interface must be in monitor mode (use airmon-ng)\n"
               "      2)All BSSIDs must be on SAME FREQ CHANNEL\n"
               "      3)FREQ CHANNEL of INTERFACE and of BSSIDs MUST MATCH (use iw set channel)\n\n"

	       "Examples:\n"
	       " get-rssi  -i mon0  -f ~/rssi  -b 01:FA:23:18:12:F2                    -t 10\n"
	       " get-rssi  -i mon0  -f ~/rssi  -b 01:FA:23:18:12:F2,02:bc:19:72:af:ff  -t 10\n");
}

void printf_arguments(const struct arguments *config)
{
        printf("info: wifi interface name:        %s\n"
               "      absolute path to cap-file:  %s\n"
               "      absolute path to txt-file:  %s\n",
               config->interface, config->file_cap, config->file_txt);

        printf("      BSSIDs (%d):                 %s",
               config->bssid_cnt, config->bssid[0]);

        for (int i = 1; i < config->bssid_cnt; i++)
                printf(", %s", config->bssid[i]);
        printf("\n");

        printf("      sniff time:                 %d (sec)\n",
               config->time);
}
