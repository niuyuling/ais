#include "conf.h"

/* 在content中，设置变量(var)的首地址，值(val)的位置首地址和末地址，返回下一行指针 */
static char *set_var_val_lineEnd(char *content, char **var, char **val_begin, char **val_end)
{

    char *p, *pn, *lineEnd;
    ;
    int val_len;

    while (1) {
        if (content == NULL)
            return NULL;

        for (; *content == ' ' || *content == '\t' || *content == '\r' || *content == '\n'; content++) ;
        if (*content == '\0')
            return NULL;
        *var = content;
        pn = strchr(content, '\n');
        p = strchr(content, '=');
        if (p == NULL) {
            if (pn) {
                content = pn + 1;
                continue;
            } else
                return NULL;
        }
        content = p;
        //将变量以\0结束
        for (p--; *p == ' ' || *p == '\t'; p--) ;
        *(p + 1) = '\0';
        //值的首地址
        for (content++; *content == ' ' || *content == '\t'; content++) ;
        if (*content == '\0')
            return NULL;
        //双引号引起来的值支持换行
        if (*content == '"') {
            *val_begin = content + 1;
            *val_end = strstr(*val_begin, "\";");
            if (*val_end != NULL)
                break;
        } else
            *val_begin = content;
        *val_end = strchr(content, ';');
        if (pn && *val_end > pn) {
            content = pn + 1;
            continue;
        }
        break;
    }

    if (*val_end) {
        **val_end = '\0';
        val_len = *val_end - *val_begin;
        lineEnd = *val_end;
    } else {
        val_len = strlen(*val_begin);
        *val_end = lineEnd = *val_begin + val_len;
    }
    *val_end = *val_begin + val_len;
    //printf("var[%s]\nbegin[%s]\n\n", *var, *val_begin);
    return lineEnd;
}

static void parse_global_module(char *content, conf * p)
{
    char *var, *val_begin, *val_end, *lineEnd;
    int val_begin_len;

    while ((lineEnd = set_var_val_lineEnd(content, &var, &val_begin, &val_end)) != NULL) {
        if (strcasecmp(var, "IP_SEGMENT") == 0) {
            val_begin_len = strlen(val_begin) + 1;
            p->IP_SEGMENT = (char *)malloc(val_begin_len);
            memset(p->IP_SEGMENT, 0, val_begin_len);
            memcpy(p->IP_SEGMENT, val_begin, val_begin_len);
        }
        content = strchr(lineEnd + 1, '\n');
    }
}

/* 在buff中读取模块(global http https httpdns httpudp)内容 */
static char *read_module(char *buff, const char *module_name)
{
    int len;
    char *p, *p0;

    len = strlen(module_name);
    p = buff;
    while (1) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (strncasecmp(p, module_name, len) == 0) {
            p += len;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
                p++;
            if (*p == '{')
                break;
        }
        if ((p = strchr(p, '\n')) == NULL)
            return NULL;
    }

    if ((p0 = strchr(++p, '}')) == NULL)
        return NULL;
    return strndup(p, p0 - p);
}

void read_conf(char *filename, conf * configure)
{
    char *buff, *global_content;
    FILE *file;
    long file_size;

    file = fopen(filename, "r");
    if (file == NULL)
        perror("cannot open config file.");
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    buff = (char *)alloca(file_size + 1);
    if (buff == NULL)
        perror("out of memory.");
    rewind(file);
    fread(buff, file_size, 1, file);
    fclose(file);
    buff[file_size] = '\0';

    if ((global_content = read_module(buff, "global")) == NULL) {
        perror("read global module error");
    }
    parse_global_module(global_content, configure);
    free(global_content);
}

void free_conf(conf * p)
{
    free(p->IP_SEGMENT);
    return;
}

void split_string(char string[], char delims[], char (*whitelist_ip)[32])
{
    int i = 0;
    char *result = NULL;
    result = strtok(string, delims);
    while (result != NULL) {
        i++;
        strcpy(whitelist_ip[i], result);
        result = strtok(NULL, delims);
    }
}
