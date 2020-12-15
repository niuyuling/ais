#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "ais.h"
#include "conf.h"

//#define DEBUG 1
#define BUF_SIZE 8192

#define READ  0
#define WRITE 1

#define DEFAULT_LOCAL_PORT    8080
#define DEFAULT_REMOTE_PORT   8081
#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define CREATE_PIPE_ERROR -8
#define BROKEN_PIPE_ERROR -9
#define HEADER_BUFFER_FULL -10
#define BAD_HTTP_PROTOCOL -11

#define MAX_HEADER_SIZE 8192

#if defined(OS_ANDROID)
#include <android/log.h>

#define LOG(fmt...) __android_log_print(ANDROID_LOG_DEBUG,__FILE__,##fmt)

#else
#define LOG(fmt...)  do { fprintf(stderr,"%s %s ",__DATE__,__TIME__); fprintf(stderr, ##fmt); } while(0)
#endif

char remote_host[128];
int remote_port;
int local_port;

int server_sock;
int server_sock6;
int client_sock;
int client_sock6;
int remote_sock;

char *header_buffer;
int sslEncodeCode;

enum {
    FLG_NONE = 0,               /* 正常数据流不进行编解码 */
    R_C_DEC = 1,                /* 读取客户端数据仅进行解码 */
    W_S_ENC = 2                 /* 发送到服务端进行编码 */
};

static int io_flag;             /* 网络io的一些标志位 */
static int m_pid;               /* 保存主进程id */

void server_loop(int signal, char *conffile);
void stop_server();
void handle_client(int client_sock, struct sockaddr_in client_addr);
void forward_header(int destination_sock);
void forward_data(int source_sock, int destination_sock);
void rewrite_header();
int send_data(int socket, char *buffer, int len);
int receive_data(int socket, char *buffer, int len);
void hand_mproxy_info_req(int sock, char *header_buffer);
void get_info(char *output);
const char *get_work_mode();
int create_connection6(char *remote_host, int remote_port);
int _main(int argc, char *argv[]);

ssize_t readLine(int fd, void *buffer, size_t n)
{
    ssize_t numRead;
    size_t totRead;
    char *buf;
    char ch;

    if (n <= 0 || buffer == NULL) {
        errno = EINVAL;
        return -1;
    }

    buf = buffer;

    totRead = 0;
    for (;;) {
        numRead = receive_data(fd, &ch, 1);

        if (numRead == -1) {
            if (errno == EINTR)
                continue;
            else
                return -1;      /* 未知错误 */
        } else if (numRead == 0) { /* EOF */
            if (totRead == 0)   /* No bytes read; return 0 */
                return 0;
            else                /* Some bytes read; add '\0' */
                break;
        } else {
            if (totRead < n - 1) { /* Discard > (n - 1) bytes */
                totRead++;
                *buf++ = ch;
            }

            if (ch == '\n')
                break;
        }
    }

    *buf = '\0';
    return totRead;
}

int read_header(int fd, void *buffer)
{
    // bzero(header_buffer,sizeof(MAX_HEADER_SIZE));
    memset(header_buffer, 0, MAX_HEADER_SIZE);
    char line_buffer[2048];
    char *base_ptr = header_buffer;

    for (;;) {
        memset(line_buffer, 0, 2048);

        int total_read = readLine(fd, line_buffer, 2048);
        if (total_read <= 0) {
            return CLIENT_SOCKET_ERROR;
        }
        //防止header缓冲区蛮越界
        if (base_ptr + total_read - header_buffer <= MAX_HEADER_SIZE) {
            strncpy(base_ptr, line_buffer, total_read);
            base_ptr += total_read;
        } else {
            return HEADER_BUFFER_FULL;
        }

        //读到了空行，http头结束
        if (strcmp(line_buffer, "\r\n") == 0 || strcmp(line_buffer, "\n") == 0) {
            break;
        }

    }
    return 0;

}

void extract_server_path(const char *header, char *output)
{
    char *p = strstr(header, "GET /");
    if (p) {
        char *p1 = strchr(p + 4, ' ');
        strncpy(output, p + 4, (int)(p1 - p - 4));
    }

}

int extract_host(const char *header)
{
    char *_p = strstr(header, "CONNECT"); /* 在 CONNECT 方法中解析 隧道主机名称及端口号 */
    if (_p) {

        if (strchr(header, '[') || strchr(header, ']')) {       // ipv6
            char *_p1 = strchr(header, '[');
            //printf("%s\n", _p1+1);

            char *_p2 = strchr(_p1 + 1, ']');
            //printf("%s\n", _p2);

            strncpy(remote_host, _p1 + 1, (int)(_p2 - _p1) - 1);
            remote_port = 443;

            return 0;
        }

        char *_p1 = strchr(_p, ' ');
        char *_p2 = strchr(_p1 + 1, ':');
        char *_p3 = strchr(_p1 + 1, ' ');
        if (_p2) {
            char s_port[10];
            bzero(s_port, 10);

            strncpy(remote_host, _p1 + 1, (int)(_p2 - _p1) - 1);
            strncpy(s_port, _p2 + 1, (int)(_p3 - _p2) - 1);
            remote_port = atoi(s_port);

        } else {
            strncpy(remote_host, _p1 + 1, (int)(_p3 - _p1) - 1);
            remote_port = 80;
        }

        return 0;
    }

    char *p = strstr(header, "Host:");
    if (!p) {
        return -1;
    }
    char *p1 = strchr(p, '\n');
    if (!p1) {
        return -1;
    }

    char *p2 = strchr(p + 5, ':'); /* 5是指'Host:'的长度 */

    if (p2 && p2 < p1) {
        int p_len = (int)(p1 - p2 - 1);
        char s_port[p_len];
        strncpy(s_port, p2 + 1, p_len);
        s_port[p_len] = '\0';
        remote_port = atoi(s_port);

        int h_len = (int)(p2 - p - 5 - 1);
        strncpy(remote_host, p + 5 + 1, h_len); //Host:
        //assert h_len < 128;
        remote_host[h_len] = '\0';
    } else {
        int h_len = (int)(p1 - p - 5 - 1 - 1);
        strncpy(remote_host, p + 5 + 1, h_len);
        //assert h_len < 128;
        remote_host[h_len] = '\0';
        remote_port = 80;
    }
    return 0;
}

/* 响应隧道连接请求  */
int send_tunnel_ok(int client_sock)
{
    char *resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
    int len = strlen(resp);
    char buffer[len + 1];
    strcpy(buffer, resp);
    if (send_data(client_sock, buffer, len) < 0) {
        perror("Send http tunnel response  failed\n");
        return -1;
    }
    return 0;
}

//返回mproxy的运行基本信息
void hand_mproxy_info_req(int sock, char *header)
{
    char server_path[255];
    char response[8192];
    extract_server_path(header, server_path);

    LOG("server path:%s\n", server_path);
    char info_buf[1024];
    get_info(info_buf);
    sprintf(response, "HTTP/1.0 200 OK\nServer: AIS/0.1\n\
                    Content-type: text/html; charset=utf-8\n\n\
                     <html><body>\
                     <pre>%s</pre>\
                     </body></html>\n", info_buf);

    write(sock, response, strlen(response));
}

/* 获取运行的基本信息输出到指定的缓冲区 */
void get_info(char *output)
{
    int pos = 0;
    char line_buffer[512];
    sprintf(line_buffer, "======= AIS (v0.1) ========\n");
    int len = strlen(line_buffer);
    memcpy(output, line_buffer, len);
    pos += len;

    sprintf(line_buffer, "%s\n", get_work_mode());
    len = strlen(line_buffer);
    memcpy(output + pos, line_buffer, len);
    pos += len;

    if (strlen(remote_host) > 0) {
        sprintf(line_buffer, "start server on %d and next hop is %s:%d\n", local_port, remote_host, remote_port);
    } else {
        sprintf(line_buffer, "start server on %d\n", local_port);
    }

    len = strlen(line_buffer);
    memcpy(output + pos, line_buffer, len);
    pos += len;

    output[pos] = '\0';

}

const char *get_work_mode()
{
    if (strlen(remote_host) == 0) {
        if (io_flag == FLG_NONE) {
            return "start as normal http proxy";
        } else if (io_flag == R_C_DEC) {
            return "start as remote forward proxy and do decode data when recevie data";
        }

    } else {
        if (io_flag == FLG_NONE) {
            return "start as remote forward proxy";
        } else if (io_flag == W_S_ENC) {
            return "start as forward proxy and do encode data when send data";
        }
    }

    return "unknow";

}

/* 处理客户端的连接 */
void handle_client(int client_sock, struct sockaddr_in client_addr)
{
    int is_http_tunnel = 0;
    if (strlen(remote_host) == 0) { /* 未指定远端主机名称从http 请求 HOST 字段中获取 */
#ifdef DEBUG
        LOG(" ============ handle new client ============\n");
        LOG(">>>Header:%s\n", header_buffer);
#endif

        if (read_header(client_sock, header_buffer) < 0) {
            LOG("Read Http header failed\n");
            return;
        } else {
            char *p = strstr(header_buffer, "CONNECT"); /* 判断是否是http 隧道请求 */
            if (p) {
                LOG("receive CONNECT request\n");
                is_http_tunnel = 1;
            }

            if (strstr(header_buffer, "GET /AIS") > 0) {
                LOG("====== hand AIS info request ====");
                hand_mproxy_info_req(client_sock, header_buffer);

                return;
            }

            if (extract_host(header_buffer) < 0) {
                LOG("Cannot extract host field,bad http protrotol");
                return;
            }
            LOG("Host:%s port: %d io_flag:%d\n", remote_host, remote_port, io_flag);

        }
    }
    // 打印HTTP header
    printf("%s", header_buffer);

    if ((remote_sock = create_connection6(remote_host, remote_port)) < 0) {
        LOG("Cannot connect to host [%s:%d]\n", remote_host, remote_port);
        return;
    }

    if (fork() == 0) {          // 创建子进程用于从客户端转发数据到远端socket接口
        if (strlen(header_buffer) > 0 && !is_http_tunnel) {
            forward_header(remote_sock); //普通的http请求先转发header
        }

        forward_data(client_sock, remote_sock);
        exit(0);
    }

    if (fork() == 0) {          // 创建子进程用于转发从远端socket接口过来的数据到客户端
        if (io_flag == W_S_ENC) {
            io_flag = R_C_DEC;  //发送请求给服务端进行编码，读取服务端的响应则进行解码
        } else if (io_flag == R_C_DEC) {
            io_flag = W_S_ENC;  //接收客户端请求进行解码，那么响应客户端请求需要编码
        }

        if (is_http_tunnel) {
            send_tunnel_ok(client_sock);
        }

        forward_data(remote_sock, client_sock);
        exit(0);
    }

    close(remote_sock);
    close(client_sock);
}

void forward_header(int destination_sock)
{
    rewrite_header();
#ifdef DEBUG
    LOG("================ The Forward HEAD =================");
    LOG("%s\n", header_buffer);
#endif

    int len = strlen(header_buffer);
    send_data(destination_sock, header_buffer, len);
}

int send_data(int socket, char *buffer, int len)
{
    if (io_flag == W_S_ENC) {
        int i;
        for (i = 0; i < len; i++) {
            buffer[i] ^= sslEncodeCode;
        }
    }

    return send(socket, buffer, len, 0);
}

int receive_data(int socket, char *buffer, int len)
{
    int n = recv(socket, buffer, len, 0);
    if (io_flag == R_C_DEC && n > 0) {
        int i;
        for (i = 0; i < n; i++) {
            buffer[i] ^= sslEncodeCode;
            // printf("%d => %d\n",c,buffer[i]);
        }
    }

    return n;
}

/* 代理中的完整URL转发前需改成 path 的形式 */
void rewrite_header()
{
    char *p = strstr(header_buffer, "http://");
    char *p0 = strchr(p, '\0');
    char *p5 = strstr(header_buffer, "HTTP/"); /* "HTTP/" 是协议标识 如 "HTTP/1.1" */
    int len = strlen(header_buffer);
    if (p) {
        char *p1 = strchr(p + 7, '/');
        if (p1 && (p5 > p1)) {
            //转换url到 path
            memcpy(p, p1, (int)(p0 - p1));
            int l = len - (p1 - p);
            header_buffer[l] = '\0';
        } else {
            char *p2 = strchr(p, ' '); //GET http://3g.sina.com.cn HTTP/1.1
            // printf("%s\n",p2);
            memcpy(p + 1, p2, (int)(p0 - p2));
            *p = '/';           //url 没有路径使用根
            int l = len - (p2 - p) + 1;
            header_buffer[l] = '\0';
        }
    }
}

void forward_data(int source_sock, int destination_sock)
{
    char buffer[BUF_SIZE];
    int n;

    while ((n = receive_data(source_sock, buffer, BUF_SIZE)) > 0) {

        send_data(destination_sock, buffer, n);
    }

    shutdown(destination_sock, SHUT_RDWR);
    shutdown(source_sock, SHUT_RDWR);
}

/* Check for valid IPv4 or Iv6 string. Returns AF_INET for IPv4, AF_INET6 for IPv6 */
int check_ipversion(char *address)
{
    struct in6_addr bindaddr;

    if (inet_pton(AF_INET, address, &bindaddr) == 1) {
        return AF_INET;
    } else {
        if (inet_pton(AF_INET6, address, &bindaddr) == 1) {
            return AF_INET6;
        }
    }
    return 0;
}

int create_connection6(char *remote_host, int remote_port)
{
    struct addrinfo hints, *res = NULL;
    int sock;
    int validfamily = 0;
    char portstr[12];

    memset(&hints, 0x00, sizeof(hints));

    hints.ai_flags = AI_NUMERICSERV; /* numeric service number, not resolve */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    sprintf(portstr, "%d", remote_port);

    /* check for numeric IP to specify IPv6 or IPv4 socket */
    if ((validfamily = check_ipversion(remote_host)) != 0) {
        hints.ai_family = validfamily;
        hints.ai_flags |= AI_NUMERICHOST; /* remote_host是有效的数字ip，跳过解析 */
    }

    /* 检查指定的主机是否有效。 如果remote_host是主机名，尝试解析地址 */
    if (getaddrinfo(remote_host, portstr, &hints, &res) != 0) {
        errno = EFAULT;
        return CLIENT_RESOLVE_ERROR;
    }

    if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        return CLIENT_SOCKET_ERROR;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        return CLIENT_CONNECT_ERROR;
    }

    if (res != NULL)
        freeaddrinfo(res);

    return sock;
}

/* 处理僵尸进程 */
void sigchld_handler(int signal)
{
    while (waitpid(-1, NULL, WNOHANG) > 0) ;
}

// IP段白名单
int whitelist(char *client_ip, char (*whitelist_ip)[WHITELIST_IP_NUM])
{
    int i;
    
    for (i = 1; i < WHITELIST_IP_NUM - 1; i++) {
        if (strcmp(whitelist_ip[i], "\0") == 0) { //  如果字符串为空就跳出循环
            break;
        }
        if ((strncmp(client_ip, whitelist_ip[i], strlen(whitelist_ip[i]))) == 0) { // 对比client_ip长度,
            return 1;
        }
    }

    return 0;
}

void server_loop(int signal, char *conffile)
{
    int i;
    char ipstr[WHITELIST_IP_NUM];
    char client_ip[WHITELIST_IP_NUM]; // 客户端IP
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    struct sockaddr_in6 client_addr6;
    socklen_t addrlen6 = sizeof(client_addr6);
    char whitelist_ip[WHITELIST_IP_NUM][WHITELIST_IP_NUM] = { { 0 }, { 0 } };

    conf *configure = (struct CONF *)malloc(sizeof(struct CONF));
    read_conf(conffile, configure);
    printf("%s\n", configure->IP_SEGMENT);
    
    split_string(configure->IP_SEGMENT, " ", whitelist_ip);

    for (i = 1; i <= WHITELIST_IP_NUM - 1; i++) {
        if (*whitelist_ip[i] != '\0')
            printf("%s\n", whitelist_ip[i]);
    }

    while (1) {
        if (signal == 4) {
            client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addrlen);
            if (client_sock > 0) {
                LOG("Client Ip %s Client Port %d\n", inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ipstr, sizeof(ipstr)), ntohs(client_addr.sin_port));
                strcpy(client_ip, inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, ipstr, sizeof(ipstr))); // 复制客户端IP到client_ip

                if (configure->IP_RESTRICTION == 1) {
                    if (whitelist(client_ip, whitelist_ip) == 0) {
                        LOG("非法IPV4客户端, 拒绝连接\n");
                        continue;
                    }
                }

                if (fork() == 0) { // 创建子进程处理客户端连接请求
                    close(server_sock);
                    handle_client(client_sock, client_addr);
                    exit(0);
                }
            }
            //close(client_sock);
        }

        if (signal == 6) {
            client_sock6 = accept(server_sock6, (struct sockaddr *)&client_addr6, &addrlen6);
            if (client_sock6 > 0) {
                LOG("Client Ip %s Client Port %d\n", inet_ntop(AF_INET6, &client_addr6.sin6_addr, ipstr, sizeof(ipstr)), ntohs(client_addr6.sin6_port));
                strcpy(client_ip, inet_ntop(AF_INET6, &client_addr6.sin6_addr, ipstr, sizeof(ipstr))); // 复制客户端IP到client_ip

                if (configure->IP_RESTRICTION == 1) {
                    if (whitelist(client_ip, whitelist_ip) == 0) {
                        LOG("非法IPV6客户端, 拒绝连接\n");
                        continue;
                    }
                }

                if (fork() == 0) { // 创建子进程处理客户端连接请求
                    close(server_sock6);
                    handle_client(client_sock6, client_addr);
                    exit(0);
                }
            }
            //close(client_sock6);
        }
    }

    free_conf(configure);
}

void stop_server()
{
    kill(m_pid, SIGKILL);
}

void usage(void)
{
    printf("Usage:\n");
    printf(" -l <port number>  specifyed local listen port \n");
    printf(" -h <remote server and port> specifyed next hop server name\n");
    printf(" -d <remote server and port> run as daemon\n");
    printf(" -c <configure file> Specify configuration file\n");
    printf(" -E <0-128> encode data when forwarding data\n");
    printf(" -D <0-128> decode data when receiving data\n");
    exit(8);
}

int create_server_socket(int port)
{
    int server_sock, optval;
    struct sockaddr_in server_addr;
    optval = 1;

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return SERVER_SOCKET_ERROR;
    }

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        return SERVER_SETSOCKOPT_ERROR;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr))
        != 0) {
        return SERVER_BIND_ERROR;
    }

    if (listen(server_sock, 128) < 0) {
        return SERVER_LISTEN_ERROR;
    }

    return server_sock;
}

int create_server_socket6(int port)
{
    int server_sock;
    int optval = SO_REUSEADDR;
    struct sockaddr_in6 server_addr;
    if ((server_sock = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        return SERVER_SETSOCKOPT_ERROR;
    }

    if (setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval)) < 0) {
        perror("setsockopt");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);
    server_addr.sin6_addr = in6addr_any;

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in6)) != 0) {
        perror("bind");
        return -1;
    }

    if (listen(server_sock, 128) < 0) {
        perror("listen");
        return -1;
    }

    return server_sock;
}

void start_server(int SIGNAL, char *conffile)
{
    //初始化全局变量
    header_buffer = (char *)malloc(MAX_HEADER_SIZE);

    signal(SIGCHLD, sigchld_handler); // 防止子进程变成僵尸进程

    if (SIGNAL == 4) {
        if ((server_sock = create_server_socket(local_port)) < 0) { // start server
            LOG("Cannot run server on %d\n", local_port);
            exit(server_sock);
        }
    }

    if (SIGNAL == 6) {
        if ((server_sock6 = create_server_socket6(local_port)) < 0) { // start server
            LOG("Cannot run server on %d\n", local_port);
            exit(server_sock);
        }
    }

    server_loop(SIGNAL, conffile);
}

int _main(int argc, char *argv[])
{
    local_port = DEFAULT_LOCAL_PORT;
    io_flag = FLG_NONE;
    sslEncodeCode = 1;
    int DAEMON = 0;
    char info_buf[2048];
    int opt;
    char optstrs[] = ":l:f:dc:E:D:h?";
    char *p = NULL;

    char *conffile = "./ais.conf";

    while (-1 != (opt = getopt(argc, argv, optstrs))) {
        switch (opt) {
        case 'l':
            local_port = atoi(optarg);
            break;
        case 'f':
            p = strchr(optarg, ':');
            if (p) {
                strncpy(remote_host, optarg, p - optarg);
                remote_port = atoi(p + 1);
            } else {
                strncpy(remote_host, optarg, strlen(remote_host));
            }
            strcpy(remote_host, "2001:19f0:7001:3bcb:5400:3ff:fe03:860e");
            remote_port = 127;
            break;
        case 'd':
            DAEMON = 1;
            break;
        case 'c':
            conffile = optarg;
            break;
        case 'E':
            io_flag = W_S_ENC;
            sslEncodeCode = atoi(optarg);
            break;
        case 'D':
            io_flag = R_C_DEC;
            sslEncodeCode = atoi(optarg);
            break;
        case ':':
            printf("\nMissing argument after: -%c\n", optopt);
            usage();
        case 'h':
        case '?':
            printf("\nInvalid argument: %c\n", optopt);
            usage();
        default:
            usage();
        }
    }

    if (DAEMON == 1) {          // 守护进程
        if(daemon(1, 1)) {
            perror("daemon");
            return -1;
        }
    }

    printf("sslEncodeCode: %d\n", sslEncodeCode);
    get_info(info_buf);
    LOG("%s\n", info_buf);

    if (fork() == 0) {      // IPV4 进程
        start_server(4, conffile);
    }

    if(fork() == 0) {       // IPV6 进程
        start_server(6, conffile);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    return _main(argc, argv);
}


