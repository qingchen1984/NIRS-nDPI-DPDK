#include <stdint.h>

#ifndef CONFIGURATOR_H_
#define CONFIGURATOR_H_

/* ---PARSE MODES--- */

// Single thread for all protocols
#define PARSE_SINGLETHREAD                  0
// New thread for every protocol
#define PARSE_MULTITHREAD_FOR_EVERY_PROTO   1
// New thread for every packet
#define PARSE_MULTITHREAD_FOR_EVERY_PACKET  2

/* ---WRITE MODES--- */

// Write to disk when size of block is more than some value
#define WRITE_BY_SIZE 0
// Write to disk when time diff from previous write is more than some value
#define WRITE_BY_TIME 1
// Write to disk when size or time is more than specified value
#define WRITE_BY_ANY  2

typedef struct Config_s {
    int         write_value_by_time;
    long        write_value_by_size;
    int         write_mode;
    int         parse_mode;
    int         max_threads;
    char*       output_filename_mask;
    char*       output_subdirname_mask;
    char*       output_dir;
    int*        proto_to_parse;
    int*        proto_blacklist;
    uint32_t*   ip_blacklist;
} Config;

struct Config_s read_config(const char* file_path);

#endif // CONFIGURATOR_H_
