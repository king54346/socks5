KeepAlivePeriod时间。Duration //DisablePathMTUDiscovery 禁用路径 MTU 发现 ( RFC 8899 )。// 数据包大小最多为 1252 (IPv4) / 1232 (IPv6) 字节。// 请注意，如果路径 MTU 发现导致您的系统出现问题，请打开一个新问题


SOCKS版本（0x05，表示SOCKS5）
//协商过程
    客户端发送认证方法请求
        版本号：通常是 0x05，表示 SOCKS5。
        方法数量：指明客户端支持的认证方法数量。
        方法列表：列出了客户端支持的一个或多个认证方法，如无需认证（0x00）、用户名/密码认证（0x02）等。
    
    代理服务器回应认证方法
    版本号：通常是 0x05。
    选择的方法：代理服务器所选的认证方法。// 0x00 0x01 0x02 0x03-0x7f iana 0x80-0xfe 私有 0xff 没有支持的

//请求过程
    客户端发送连接请求
    版本号：通常是 0x05。
    命令：通常是 0x01，表示建立 TCP 连接。
        CONNECT (0x01) 用于请求代理服务器与目标服务器建立一个TCP连接
        BIND (0x02) BIND命令用于请求代理服务器在其上打开一个监听端口（对外界而言），用于接受来自某个特定IP地址的入站连接,适合用户多条连接的服务，例如ftp等
        UDP ASSOCIATE (0x03) 这个命令用于建立一个UDP端口，通过代理服务器转发UDP数据包
    保留字段：通常为 0x00。
    地址类型：表示目标服务器的地址类型（IPv4、域名、IPv6）。
    目标地址：目标服务器的地址。
    目标端口：目标服务器的端口。

  
    代理服务器回应连接请求
    版本号：通常是 0x05。
    响应码：表示连接尝试的结果，例如成功（0x00）、服务器失败（0x01）、连接不允许（0x02）-0x09...等。
    保留字段：通常为 0x00。
    地址类型：通常与客户端请求中的相同。
    代理服务器绑定的地址和端口：如果连接成功，这些信息可能用于后续通信



//转发过程
    



内网穿透， 将内网的服务映射到公网上去

公网服务器                  内网服务器
             <--建立连接 
                 
             主动打开tcp-->

              <-- 建立tcp连接

              <--双向连接-->



https://github.com/search?q=RingBuf%3A%3Awith_byte_size&type=code
https://zhuanlan.zhihu.com/p/644885061
https://github.com/vadorovsky/aya-examples
https://www.jianshu.com/p/97873541510f
https://blog.upx8.com/3146
https://github.com/pysrc/portmap/blob/main/pmap.go
https://www.zhihu.com/people/wmproxy
https://github.com/tickbh/wmproxy/blob/main/src/socks5.rs