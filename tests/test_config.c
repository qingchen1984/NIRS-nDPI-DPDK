#include "../src/configurator.h"
#include <string.h>
#include <stdio.h>

void printConfig(Config_s config)
{
    printf("WRITE_MODE: %i\n", config.write_mode);
    printf("WRITE_BY_SIZE: %li\n", config.write_value_by_size);
    printf("WRITE_BY_TIME: %i\n", config.write_value_by_time);
    printf("PARSE_MODE: %i\n", config.parse_mode);
    printf("MAX_THREADS: %i\n", config.max_threads);
    printf("OUTPUT_DIR: %s\n", config.output_dir);
    printf("FILE_MASK: '%s'\n", config.output_filename_mask);
    printf("DIR_MASK: '%s'\n", config.output_subdirname_mask);
}

int main(int argc, char const *argv[])
{
    if (argc < 3) return 1;
    if (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--config") == 0){
        Config_s config = read_config(argv[2]);
        printConfig(config);
        printf("Config readed\n");
    }
    return 0;
}
