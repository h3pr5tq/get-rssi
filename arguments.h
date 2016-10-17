#ifndef ARGUMENTS_H
#define ARGUMENTS_H

/*
 *Max length of absolute name of file
 */
#define MAX_LEN_FILE_NAME 512

/*
 *Max count of BSSIDs in argument --bssid
 */
#define MAX_BSSID  10

/*
 * struct arguments - input parameters of program
 * @interface - wifi interface name
 * @file_cap - file name (string) for cap-file; contain beacons
 * @file_txt - file name (string) for txt-file; gets the txt-file after parse cap-file
 * @bssid - 2D array with MACs; MAC present as string (length of string 17 + '\0')
 * @bssid_cnt - number of MACs in @bssid
 * @time - sniff time in sec
 */
struct arguments {
        const char *interface;
        char file_cap[MAX_LEN_FILE_NAME];
        char file_txt[MAX_LEN_FILE_NAME];

        char bssid[MAX_BSSID][18];
        int  bssid_cnt;

        int time;
};

/* handle options and arguments of command line,
 * check that all necessary options is present,
 * return 0 if all is right,else return 1
 */
int handle_arguments(const int argc, const char *argv[], struct arguments *config);

/*
 *parse the string type of "01:FA:23:18:12:F2,01:FA:23:aa:AA:aa,01:FA:23:aa:AA:aa"
 *in 2D array type of { {"01:FA:23:18:12:F2"}, {"01:FA:23:aa:AA:aa"}, {"01:FA:23:aa:AA:aa"} };
 *also check the correctnest of symbols in the string
 */
int parse_arg_bssid(const char *arg_bssid, char (*bssid)[18], int * const bssid_cnt);

/*
 *construct filename.txt and filename.cap, where filename - absolute path to file
 *filename is argument which enter after option -f
 */
int parse_arg_file(const char *arg_file, char *file_cap, char *file_txt, int max_len_file_name);

void printf_help(void);
void printf_arguments(const struct arguments * config);

#endif
