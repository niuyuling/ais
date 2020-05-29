#ifndef CONF_H
#define CONF_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <error.h>
#include <unistd.h>

// 配置文件结构
typedef struct CONF {
    char *IP_SEGMENT;
} conf;

void read_conf(char *filename, conf * configure);
void free_conf(conf * p);
void split_string(char string[], char delims[], char (*whitelist_ip)[32]);

#endif
