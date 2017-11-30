#include "configurator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define UNKNOWN_PARAM              -1
#define WRITE_BY_TIME_PARAM         1
#define WRITE_BY_SIZE_PARAM         2
#define PARSE_MODE_PARAM            3
#define MAX_THREADS_PARAM           4
#define OUTPUT_FILENAME_MASK_PARAM  5
#define OUTPUT_DIRNAME_MASK_PARAM   6
#define OUTPUT_DIRPATH_PARAM        7
#define BLACKLIST_PARAM             8

typedef struct {
    char*   key_string;
    int     key_id;
    char*   value_string;
} Parameter_s;

Parameter_s parse_config_line(char* buf)
{
    size_t length = strlen(buf);

    char* param_name = (char*) malloc(50 * sizeof(char));

    sscanf(buf, "%s", param_name);
    Parameter_s param;
    param.key_string = param_name;

    param.key_id = UNKNOWN_PARAM;

    if (strcmp(param_name, "write_by_time")     == 0) param.key_id = WRITE_BY_TIME_PARAM;
    if (strcmp(param_name, "write_by_size")     == 0) param.key_id = WRITE_BY_SIZE_PARAM;
    if (strcmp(param_name, "parse")             == 0) param.key_id = PARSE_MODE_PARAM;
    if (strcmp(param_name, "max_threads")       == 0) param.key_id = MAX_THREADS_PARAM;
    if (strcmp(param_name, "output_filename")   == 0) param.key_id = OUTPUT_FILENAME_MASK_PARAM;
    if (strcmp(param_name, "output_subdirname") == 0) param.key_id = OUTPUT_DIRNAME_MASK_PARAM;
    if (strcmp(param_name, "output_dir")        == 0) param.key_id = OUTPUT_DIRPATH_PARAM;
    if (strcmp(param_name, "skip")              == 0) param.key_id = BLACKLIST_PARAM;

    int pos = 0;
    while (param_name[pos] != '\0' && pos < 50){
        pos++;
    }

    pos++; // Skip space after param name

    param.value_string = malloc((length - pos) * sizeof(char));
    strncpy(param.value_string, (buf+pos), length-pos-1);

    free(param_name);
    param_name = NULL;

    return param;
}

// Increasing vector size
void increase_blacklist(Blacklist_s** blacklist)
{
    Blacklist_s* new_blacklist = (Blacklist_s*) malloc(sizeof(Blacklist_s));
    Blacklist_s* list = *blacklist;

    if (list == NULL){
        new_blacklist->arr_size = 4;
        new_blacklist->arr_items_count = 0;
        new_blacklist->blocks = malloc(new_blacklist->arr_size * sizeof(uint32_t));
    }
    else {
        new_blacklist->arr_size = (list->arr_size > 128) ? list->arr_size + 128 : list->arr_size * 2;
        new_blacklist->arr_items_count = list->arr_items_count;
        new_blacklist->blocks = malloc(new_blacklist->arr_size * sizeof(uint32_t));
        int i = 0;
        for (; i < new_blacklist->arr_items_count; i++){
            new_blacklist->blocks[i] = list->blocks[i];
        }

        free(*blacklist);
    }

    *blacklist = new_blacklist;

    return;
}

uint32_t convert_ip_to_binary(unsigned char* ip)
{
    uint32_t binIp = (uint32_t) ip[0];

    binIp = (binIp << 8) + ip[1];
    binIp = (binIp << 8) + ip[2];
    binIp = (binIp << 8) + ip[3];

    return binIp;
}

Config_s update_config_from_buf(Config_s config, char* buf)
{
    size_t length = strlen(buf);
    if (buf[0] == '#' || buf[0] == '\n') return config;

    Parameter_s current_param = parse_config_line(buf);

    long paramLong;

    switch (current_param.key_id){
        case WRITE_BY_TIME_PARAM:
            sscanf(current_param.value_string, "%li", &paramLong);

            config.write_value_by_time = (int) paramLong;
            if (config.write_mode == WRITE_BY_SIZE || config.write_mode == WRITE_BY_ANY){
                config.write_mode = WRITE_BY_ANY;
            }
            else config.write_mode = WRITE_BY_TIME;
            break;

        case WRITE_BY_SIZE_PARAM: ;
            char* sizeMod = (char*) malloc(3 * sizeof(char));

            sscanf(current_param.value_string, "%li%s", &paramLong, sizeMod);

            switch (sizeMod[0]){
                case 'K':
                    paramLong *= 1024;
                    break;
                case 'M':
                    paramLong *= 1024*1024;
                    break;
                case 'G':
                    paramLong *= 1024*1024*1024;
                    break;
                case '\0':
                    break;
                default:
                    break;
            }

            free(sizeMod);
            sizeMod = NULL;

            config.write_value_by_size = paramLong;
            if (config.write_mode == WRITE_BY_TIME || config.write_mode == WRITE_BY_ANY){
                config.write_mode = WRITE_BY_ANY;
            }
            else config.write_mode = WRITE_BY_SIZE;
            break;

        case PARSE_MODE_PARAM:
            if (strcmp(current_param.value_string, "singlethread") == 0)
                config.parse_mode = PARSE_SINGLETHREAD;
            if (strcmp(current_param.value_string, "multithread-for-proto") == 0)
                config.parse_mode = PARSE_MULTITHREAD_FOR_EVERY_PROTO;
            if (strcmp(current_param.value_string, "multithread-for-packet") == 0)
                config.parse_mode = PARSE_MULTITHREAD_FOR_EVERY_PACKET;
            break;

        case MAX_THREADS_PARAM:
            sscanf(current_param.value_string, "%li", &paramLong);
            config.max_threads = (int) paramLong;
            break;

        case OUTPUT_FILENAME_MASK_PARAM:
            config.output_filename_mask = current_param.value_string;
            break;

        case OUTPUT_DIRNAME_MASK_PARAM:
            config.output_subdirname_mask = current_param.value_string;
            break;

        case OUTPUT_DIRPATH_PARAM:
            config.output_dir = current_param.value_string;
            break;

        case BLACKLIST_PARAM: ;
            char* blacklist_type = (char*) malloc(50 * sizeof(char));
            sscanf(current_param.value_string, "%s", blacklist_type);

            if (strcmp(blacklist_type, "ip") == 0){
                unsigned char* octets = (unsigned char*) malloc(4 * sizeof(unsigned char));
                sscanf(
                    current_param.value_string,
                    "%s %hhu.%hhu.%hhu.%hhu",
                    blacklist_type,
                    &octets[0],
                    &octets[1],
                    &octets[2],
                    &octets[3]);

                if (config.ip_blacklist == NULL) increase_blacklist(&config.ip_blacklist);
                else if (config.ip_blacklist->arr_items_count == config.ip_blacklist->arr_size){
                    increase_blacklist(&config.ip_blacklist);
                }

                config.ip_blacklist->blocks[config.ip_blacklist->arr_items_count] = convert_ip_to_binary(octets);
                config.ip_blacklist->arr_items_count++;
            }
            else if (strcmp(blacklist_type, "proto") == 0){
                uint32_t protoId;
                sscanf(current_param.value_string, "%s %u", blacklist_type, &protoId);

                if (config.proto_blacklist == NULL) increase_blacklist(&config.proto_blacklist);
                else if (config.proto_blacklist->arr_items_count == config.proto_blacklist->arr_size){
                    increase_blacklist(&config.proto_blacklist);
                }

                config.proto_blacklist->blocks[config.proto_blacklist->arr_items_count] = protoId;
                config.proto_blacklist->arr_items_count++;
            }

            free(blacklist_type);
            blacklist_type = NULL;
    }
    return config;
}

Config_s read_config(const char* file_path)
{
    Config_s config;

    // Default values
    config.parse_mode = PARSE_SINGLETHREAD;
    config.output_dir = "./result";
    config.output_filename_mask = "packet_%yyyy/%MM/%dd";
    config.output_subdirname_mask = "proto_%pr";
    config.write_mode = -1;
    config.ip_blacklist = NULL;
    config.proto_blacklist = NULL;

    FILE* file = fopen(file_path, "r");

    if (file != NULL){

        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        char* file_content = (char*) malloc(file_size * sizeof(char) + 1);

        while (fgets(file_content, file_size, file) != NULL){
            config = update_config_from_buf(config, file_content);
        }

        fclose(file);

        free(file_content);
        file_content = NULL;
    }

    // Default values
    if (config.write_mode == -1) {
        config.write_mode = WRITE_BY_SIZE;
        config.write_value_by_size = 4 * 1024;
    }

    return config;
}
