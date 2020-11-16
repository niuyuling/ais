# AIS
    修改自mproxy(https://github.com/examplecode/mproxy), 作为CProxy服务端. 仅代理TCP
    支持客户端IP白名单
    支持IPV4
    支持IPV6

# 参数
    Usage:
        -l <port number>  specifyed local listen port 
        -h <remote server and port> specifyed next hop server name
        -d <remote server and port> run as daemon
        -c <configure file> Specify configuration file
        -E <0-128> encode data when forwarding data
        -D <0-128> decode data when receiving data
        
# 配置文件
    global {
        // 是否开启白名单（1开启，0关闭）
        IP_RESTRICTION = 1;
        // 白名单IP段, 判断前两段IP空格隔开冒号结尾(可以写完整的IPV4和IPV6地址)
        IP_SEGMENT= 115.60 115.61 115.62 223.88 2409:8a44:336:7180:5cb7:5b71:85e2:7f14;
    }
    
    