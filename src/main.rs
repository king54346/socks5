use std::error;
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::Command::UDP;

const SOCKS5_VERSION: u8 = 0x05;
const RESERVED_CODE: u8 = 0x00;


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
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(socket) => {
                    new_server_request_success_message(stream, &result.address, result.port).await?;
                    Ok(Socket::Udp(socket))
                }
                Err(_) => {
                    new_server_request_failure_message(stream, ServerReplyType::CommandNotSupported).await?;
                    Err(io::Error::new(io::ErrorKind::Other, "无法创建UDP socket"))
                }
            }
        }
    }
}


async fn forward(source: &mut TcpStream,dest:Socket)->io::Result<()>{
    match dest {
        Socket::Tcp(mut dest_stream) => {
            // 转发过程
            let (mut ri, mut wi) = source.split();
            let (mut ro, mut wo) = dest_stream.split();
            let client_to_server = tokio::io::copy(&mut ri, &mut wo);
            let server_to_client = tokio::io::copy(&mut ro, &mut wi);

            match tokio::try_join!(client_to_server, server_to_client) {
                Ok((_, _)) => Ok(()),
                Err(e) => Err(e),
            }
        }
        Socket::Udp(_) => {
            unimplemented!()
        }
    }
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
