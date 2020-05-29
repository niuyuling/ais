# AIS
    修改自mproxy(https://github.com/examplecode/mproxy), 作为CProxy服务端. 仅代理TCP
    支持客户端IP白名单

# 参数
    Usage:
        -l <port number>  specifyed local listen port 
        -h <remote server and port> specifyed next hop server name
        -d <remote server and port> run as daemon
        -E <0-128> encode data when forwarding data
        -D <0-128> decode data when receiving data
        
# 配置文件
    global {
        // 白名单IP段, 判断前两段IP空格隔开冒号结尾
        IP_SEGMENT= 115.60 115.61 115.62 223.88;
    }
    
    