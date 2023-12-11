use std::error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt, copy_bidirectional, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::broadcast::{channel, Receiver, Sender};
use tokio::try_join;
use webparse::{BinaryMut, Buf, BufMut};

use crate::Command::UDP;

const SOCKS5_VERSION: u8 = 0x05;
const RESERVED_CODE: u8 = 0x00;
const BIND_IP:&str = "127.0.0.1";

#[derive(Debug, Copy, Clone)]
enum ServerReplyType {
    Success = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl From<ServerReplyType> for u8 {
    fn from(reply_type: ServerReplyType) -> Self {
        match reply_type {
            ServerReplyType::Success => 0x00,
            ServerReplyType::GeneralFailure => 0x01,
            ServerReplyType::ConnectionNotAllowed => 0x02,
            ServerReplyType::NetworkUnreachable => 0x03,
            ServerReplyType::HostUnreachable => 0x04,
            ServerReplyType::ConnectionRefused => 0x05,
            ServerReplyType::TtlExpired => 0x06,
            ServerReplyType::CommandNotSupported => 0x07,
            ServerReplyType::AddressTypeNotSupported => 0x08,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    CONNECT = 0x01,
    Bind = 0x02,
    UDP = 0x03,
}

#[derive(Debug)]
enum Address {
    IpV4(Ipv4Addr),
    Domain(String),
    IpV6(Ipv6Addr),
}

enum Socket {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Address {
    fn to_string(&self) -> String {
        match self {
            Address::IpV4(addr) => addr.to_string(),
            Address::Domain(domain) => domain.clone(),
            Address::IpV6(addr) => addr.to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Method {
    NoAuth = 0x00,
    GSSAPI = 0x01,
    MethodPassword = 0x02,
    MethodNoAcceptable = 0xF,
}

// 实现从 u8 到 Method 的转换
impl From<u8> for Method {
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Method::NoAuth,
            0x01 => Method::GSSAPI,
            0x02 => Method::MethodPassword,
            0x0F => Method::MethodNoAcceptable,
            _ => panic!("未知的认证方法"), // 或者可以选择返回一个默认值或错误
        }
    }
}

// 实现从 Method 到 u8 的转换
impl From<Method> for u8 {
    fn from(method: Method) -> Self {
        match method {
            Method::NoAuth => 0x00,
            Method::GSSAPI => 0x01,
            Method::MethodPassword => 0x02,
            Method::MethodNoAcceptable => 0x0F,
        }
    }
}

#[derive(Debug)]
struct ClientAuthMessage {
    version: u8,
    //1
    nmethod: u8,
    //1
    methods: Vec<Method>,   //1-255
}

#[derive(Debug)]
struct ClientRequestMessage {
    cmd: Command,
    address: Address,
    port: u16,
}


fn new_client_auth_message(message: &[u8]) -> io::Result<ClientAuthMessage> {
    if message.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::Other, "缓冲区太小"));
    }

    let version = message[0];
    if version != 5 {
        return Err(io::Error::new(io::ErrorKind::Other, "不是有效的 SOCKS5 请求"));
    }

    let nmethod = message[1] as usize;
    if message.len() < 2 + nmethod {
        return Err(io::Error::new(io::ErrorKind::Other, "缓冲区长度不匹配"));
    }

    let methods = message[2..2 + nmethod]
        .iter()
        .map(|&byte| Method::from(byte))
        .collect();

    Ok(ClientAuthMessage {
        version,
        nmethod: nmethod as u8,
        methods,
    })
}

async fn new_server_auth_message(stream: &mut TcpStream, method: Method) -> io::Result<()> {
    stream.write_all(&[SOCKS5_VERSION, method.into()]).await?;
    Ok(())
}


fn validate_credentials(username: &str, password: &str) -> bool {
    // 在这里实现用户名和密码的验证逻辑
    // 例如，与数据库中存储的凭据进行比较
    // 这里仅作为示例，使用静态用户名和密码
    username == "user" && password == "password"
}

async fn handle_method_password(stream: &mut TcpStream) -> io::Result<()> {
    // 发送确认使用用户名/密码认证的响应
    new_server_auth_message(stream, Method::MethodPassword).await?;
    // 从客户端读取用户名和密码
    // ver 1 ulen 1 uname 1-255 plen 1 passwd 1-255
    let mut credentials = [0u8; 515]; // 最大用户名和密码长度

    let nbytes = stream.read(&mut credentials).await?;

    if nbytes < 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "无效的认证数据"));
    }

    // 解析用户名和密码
    let ulen = credentials[1] as usize;

    let username = std::str::from_utf8(&credentials[2..2 + ulen])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "无效的用户名"))?;

    let plen = credentials[2 + ulen] as usize;

    let password = std::str::from_utf8(&credentials[3 + ulen..3 + ulen + plen])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "无效的密码"))?;

    // 验证用户名和密码
    if validate_credentials(username, password) {
        // 发送认证成功的响应 version 0x01 status 0x00 succ 0x00外的表示错误
        stream.write_all(&[0x01, 0x00]).await?;
    } else {
        // 发送认证失败的响应
        stream.write_all(&[0x01, 0x01]).await?;
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "认证失败"));
    }

    Ok(())
}


async fn auth(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    let auth_message = new_client_auth_message(message)?;
    println!("认证信息: {:?}", auth_message);
    for method in auth_message.methods {
        match method {
            Method::MethodPassword => {
                handle_method_password(stream).await?;
                return Ok(());
            }
            Method::NoAuth => {

            }
            Method::GSSAPI => {
                // ... 其他方法处理
            }

            Method::MethodNoAcceptable => {
                // ... 其他方法处理
                new_server_auth_message(stream, method).await?;
                return Err(io::Error::new(io::ErrorKind::Other, "不支持认证方式"));
            }
            // ... 可能的其他方法
        }
    }

    Err(io::Error::new(io::ErrorKind::Other, "不支持认证方式"))
}



fn new_client_request_message(message: &[u8]) -> io::Result<ClientRequestMessage> {
    if message.len() < 7 || message[0] != SOCKS5_VERSION || message[2] != RESERVED_CODE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "不是有效的 SOCKS5 连接请求"));
    }
    let command = message[1];
    let addtype = message[3];
    let cmd = match command {
        0x01 => Command::CONNECT,
        0x02 => Command::Bind,
        0x03 => Command::UDP,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "无效的命令")),
    };

    let (address, port_pos) = match addtype {
        0x01 => {  // IPv4
            if message.len() < 10 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "地址长度不足"));
            }
            let addr = Ipv4Addr::new(message[4], message[5], message[6], message[7]);
            (Address::IpV4(addr), 8)
        }
        0x03 => {  // 域名

            let addr_len = message[4] as usize;
            if message.len() < (5 + addr_len + 2) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "IPv4的地址长度不足"));
            }
            let addr = std::str::from_utf8(&message[5..5 + addr_len])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "无效的域名"))?
                .to_string();
            (Address::Domain(addr), 5 + addr_len)
        }
        0x04 => {  // IPv6
            if message.len() < 22 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "IPv6的地址长度不足"));
            }
            let addr = Ipv6Addr::new(
                ((message[4] as u16) << 8) | (message[5] as u16),
                ((message[6] as u16) << 8) | (message[7] as u16),
                ((message[8] as u16) << 8) | (message[9] as u16),
                ((message[10] as u16) << 8) | (message[11] as u16),
                ((message[12] as u16) << 8) | (message[13] as u16),
                ((message[14] as u16) << 8) | (message[15] as u16),
                ((message[16] as u16) << 8) | (message[17] as u16),
                ((message[18] as u16) << 8) | (message[19] as u16),
            );
            (Address::IpV6(addr), 20)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "无效的地址类型")),
    };
    if message.len() < port_pos + 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "端口信息不完整"));
    }

    let port = ((message[port_pos] as u16) << 8) | (message[port_pos + 1] as u16);

    Ok(ClientRequestMessage { cmd, address, port })
}


async fn new_server_request_success_message(stream: &mut TcpStream, address: &Address, port: u16) -> io::Result<()> {
    let mut response = Vec::new();
    response.push(SOCKS5_VERSION);
    response.push(ServerReplyType::Success.into());
    response.push(RESERVED_CODE);

    match address {
        Address::IpV4(addr) => {
            response.push(0x01); // 地址类型: IPv4
            response.extend_from_slice(&addr.octets()); // IPv4 地址
        }
        Address::Domain(domain) => {
            response.push(0x03); // 地址类型: 域名
            if domain.len() > 255 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "域名长度超过255"));
            }
            response.push(domain.len() as u8); // 域名长度
            response.extend_from_slice(domain.as_bytes()); // 域名
        }
        Address::IpV6(addr) => {
            response.push(0x04); // 地址类型: IPv6
            for segment in &addr.segments() {
                response.extend_from_slice(&segment.to_be_bytes()); // IPv6 地址的每个段
            }
        }
    }

    response.extend_from_slice(&port.to_be_bytes()); // 端口号（大端表示）

    // 发送响应消息
    stream.write_all(&response).await?;

    Ok(())
}

async fn new_server_request_failure_message(stream: &mut TcpStream, srt: ServerReplyType) -> io::Result<()> {
    stream.write_all(&[SOCKS5_VERSION, srt.into(), RESERVED_CODE, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn request(stream: &mut TcpStream, message: &[u8]) -> io::Result<Socket> {
    let result = match new_client_request_message(message) {
        Ok(r) => {
            r
        }
        Err(e) => {
            new_server_request_failure_message(stream, ServerReplyType::AddressTypeNotSupported).await?;
            return Err(e);
        }
    };

    match result.cmd {
        Command::CONNECT => {
            let addr = result.address.to_string(); // 确保地址是正确的字符串格式
            match TcpStream::connect((addr, result.port)).await {
                Ok(dest_stream) => {
                    new_server_request_success_message(stream, &result.address, result.port).await?;
                    Ok(Socket::Tcp(dest_stream))
                }
                Err(_) => {
                    new_server_request_failure_message(stream, ServerReplyType::ConnectionRefused).await?;
                    Err(io::Error::new(io::ErrorKind::Other, "无法连接到目标地址"))
                }
            }
        }
        Command::Bind => {
            new_server_request_failure_message(stream, ServerReplyType::CommandNotSupported).await?;
            Err(io::Error::new(io::ErrorKind::InvalidInput, "不支持bind连接命令"))
        }

        Command::UDP => {
            // 提供一个服务器上的 UDP 端口和 IP 地址
            // let addr = result.address.to_string();
            // if addr.is_empty() {
            //     return Err(ProxyError::ProtNoSupport);
            // }
            // 执行 UDP ASSOCIATE 命令
            // udp_execute_assoc(stream, Ipv4Addr::new(127, 0, 0, 1)).await?;
            // Ok(Socket::Udp());

            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(peer_sock) => {
                    let port = peer_sock.local_addr()?.port();
                    // bind_ip 代表代理服务器将要告诉客户端用于 UDP 通信的 IP 地址

                    let mut buf = BinaryMut::with_capacity(100);
                    buf.put_slice(&vec![SOCKS5_VERSION, if succ { 0 } else { 1 }, 0x00]);

                    stream.write_all(&buf.chunk()).await?;
                    Ok(Socket::Udp(peer_sock))
                }
                Err(_) => {
                    new_server_request_failure_message(stream, ServerReplyType::CommandNotSupported).await?;
                    Err(io::Error::new(io::ErrorKind::Other, "无法创建UDP socket"))
                }
            }
        }
    }
}

// UDP 关联请求用于在UDP中继进程内建立关联以处理UDP数据报。
// DST.ADDR和DST.PORT字段包含客户端期望用于发送UDP数据报的地址和端口。
// 服务器可以使用此信息来限制对关联的访问。如果客户端在UDP 关联请求时没有掌握此信息，
// 客户端必须使用端口号和地址都为零的地址。
// UDP关联会在随着的TCP连接终止时终止。
// 在UDP 关联请求的回复中，BND.PORT和BND.ADDR字段指示客户端必须发送UDP请求消息以进行中继的端口号/地址。
// UDP 数据包保留字段（0x00 0x00），FRAG 字段（通常为0x00），ATYP 字段（地址类型，IPv4/IPv6/域名），DST.ADDR（目的地址），DST.PORT（目的端口），以及实际的 UDP 数据负载
// bind_ip 是用于告诉客户端向哪里发送数据包的地址，
// UdpSocket::bind("0.0.0.0:0") 是代理服务器实际上用于接收和转发这些数据包的网络端点
pub async fn udp_execute_assoc(bind_ip: Ipv4Addr)->io::Result<()>{
    // 代理服务器创建一个新的 UDP 套接字，并绑定到任意可用的地址和端口
    let peer_sock = UdpSocket::bind("0.0.0.0:0").await?;
    // 查询 UDP 套接字绑定的本地地址，并获取其端口号
    let port = peer_sock.local_addr()?.port();

    // 代理服务器通过 TCP 连接向客户端发送响应，通知客户端其 UDP 套接字的绑定地址（bind_ip）和端口（port）
    // new_server_request_success_message(stream, &Address::IpV4(bind_ip),port).await?;
    // // 启动 UDP 数据转发  inbound 用于接受，outbound 用于发送 UDP 数据
    // udp_transfer(stream, peer_sock).await?;
    Ok(())
}

async fn udp_transfer(stream:&mut TcpStream, inbound: UdpSocket)->io::Result<()>{
    let outbound = UdpSocket::bind("0.0.0.0:0").await?;
    // 使tcp断开的时候通知udp结束关联,结束处理函数
    let (sender, receiver) = channel::<()>(1);
    // 一个套接字用于与客户端通信（接收客户端的数据并发送数据给客户端），另一个套接字用于与外部服务器或目的地通信。
    // in 客户端想通过代理服务器发送 UDP 数据， out 通过代理服务器将客户端的请求转发到最终的目的地
    // 处理upd的接收
    let req_fut =  udp_handle_request(&inbound, &outbound, receiver);
    // 处理upd的发送
    let res_fut =  udp_handle_response(&inbound, &outbound, sender.subscribe());
    // tcp连接
    let tcp_fut =  upd_handle_tcp_block(stream, sender.subscribe(), sender.clone());
    match try_join!(tcp_fut, req_fut, res_fut) {
        Ok(_) => {}
        Err(error) => {
            // 发生错误时不确定是哪个处理函数出错, 通知其它的停止
            let _ = sender.send(());
            return Err(error);
        }
    }
    Ok(())
}


///   +----+------+------+----------+----------+----------+
///   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
///   +----+------+------+----------+----------+----------+
///   | 2  |  1   |  1   | Variable |    2     | Variable |
///   +----+------+------+----------+----------+----------+
///  UDP和本地的通讯的头全部加上这个，因为中间隔了代理，需要转发到正确的地址上
async fn udp_parse_request(buf: &mut BinaryMut) -> io::Result<(u8, SocketAddr)> {
    if buf.remaining() < 3 {
        return Err(io::Error::new(io::ErrorKind::Other, "无法连接到目标地址"));
    }
    let _rsv = buf.get_u16();
    let flag = buf.get_u8();
    let array: Vec<u8> = vec![];
    let addr =SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    return Ok((flag, addr));
}

/// +------+----------+----------+
/// | ATYP | DST.ADDR | DST.PORT |
/// +------+----------+----------+
/// |  1   | Variable |    2     |
/// +------+----------+----------+
/// 读取通用地址格式，包含V4/V6/Doamin三种格式

async fn upd_handle_tcp_block(stream: &mut TcpStream, mut receiver: Receiver<()>, sender: Sender<()>,)->io::Result<()>{
    let mut buf = [0u8; 100];
    loop {
        let n = tokio::select! {
                r = stream.read(&mut buf) => {
                    r?
                },
                _ = receiver.recv() => {
                    return Ok(());
                }
            };
        if n == 0 {
            let _ = sender.send(());
            return Ok(());
        }
    }
}

// 处理收到客户端的消息, 解析发送到远程
async fn udp_handle_request(inbound: &UdpSocket, outbound: &UdpSocket, mut receiver: Receiver<()>, ) -> io::Result<()> {
    let mut buf = BinaryMut::with_capacity(0x10000);
    loop {
        buf.clear();
        let (size, client_addr) = {
            let mut buf = ReadBuf::uninit(buf.chunk_mut());
            tokio::select! {
                    r = inbound.recv_buf_from(&mut buf) => {
                        r?
                    },
                    _ = receiver.recv() => {
                        return Ok(());
                    }
                }
        };
        unsafe {
            buf.advance_mut(size);
        }
        // 代理对内的端口只会跟客户端的通讯, 所以建立connect
        inbound.connect(client_addr).await?;

        let (flag, addr) = udp_parse_request(&mut buf).await?;
        if flag != 0 {
            return Ok(());
        }

        outbound.send_to(buf.chunk(), addr).await?;
    }
}

/// 处理收到远程的消息, 添加头发送到客户端
async fn udp_handle_response(inbound: &UdpSocket, outbound: &UdpSocket, mut receiver: Receiver<()>, ) -> io::Result<()>{
    let mut buf = BinaryMut::with_capacity(0x10000);
    loop {
        buf.clear();
        let (size, client_addr) = {
            let (size, client_addr) = {
                let mut buf = ReadBuf::uninit(buf.chunk_mut());
                tokio::select! {
                        r = outbound.recv_buf_from(&mut buf) => {
                            r?
                        },
                        _ = receiver.recv() => {
                            return Ok(());
                        }
                    }
            };
            (size, client_addr)
        };
        unsafe {
            buf.advance_mut(size);
        }

        let mut buffer = BinaryMut::with_capacity(100);
        buffer.put_slice(&[0, 0, 0]);
        encode_socket_addr(&mut buffer, &client_addr)?;
        buffer.put_slice(buf.chunk());

        // 因为已经建立了绑定, 所以直接发送
        inbound.send(buffer.chunk()).await?;
    }
}
/// +------+----------+----------+
/// | ATYP | DST.ADDR | DST.PORT |
/// +------+----------+----------+
/// |  1   | Variable |    2     |
/// +------+----------+----------+
/// 将地址转化成二进制流
pub fn encode_socket_addr(buf: &mut BinaryMut, addr: &SocketAddr) -> io::Result<()> {
    let (addr_type, mut ip_oct, mut port) = match addr {
        SocketAddr::V4(sock) => (
            0x01,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
        SocketAddr::V6(sock) => (
            0x04,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
    };

    buf.put_u8(addr_type);
    buf.put_slice(&mut ip_oct);
    buf.put_slice(&mut port);
    Ok(())
}


async fn forward(source: &mut TcpStream,dest:Socket)->io::Result<()> {
    match dest {
        Socket::Tcp(mut dest_stream) => {
            // 转发过程
            let _ = copy_bidirectional(source, &mut dest_stream).await?;
        }
        Socket::Udp(Address) => {
            unimplemented!()
        }
    }
    Ok(())
}


async fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0u8; 262]; // 最大可能长度为 2 + 255

    let mut n = stream.read(&mut buffer).await?;

    // 协商过程
    auth(&mut stream, &buffer[..n]).await?;

    // 连接过程
    n = stream.read(&mut buffer).await?;
    let socket = request(&mut stream, &buffer[..n]).await?;

    //转发过程
    forward(&mut stream,socket).await
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:1081").await?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                println!("处理客户端时出错: {}", e);
            }
        });
    }
}
