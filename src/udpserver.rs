use std::any::Any;

use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:8080").await?;
    println!("DNS server running on 0.0.0.0:8080");

    let mut buf = [0u8; 512]; // DNS 消息通常不会超过 512 字节



    let my_string = "Hello, world!".to_string();
    let my_number = 42;

    print_type(&my_string);
    print_type(&my_number);

    loop {
        let (amt, src) = socket.recv_from(&mut buf).await?;
        // 发送响应回客户端
        socket.send_to(&[0xba, 0xe4, 0x81, 0x80, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x5, 0x68, 0x74, 0x74, 0x70, 0x33, 0x3, 0x6f, 0x6f, 0x6f, 0x0, 0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x3c, 0x0, 0x4, 0x89, 0xb8, 0xed, 0x5f], src).await?;
    }

 
}


fn print_type<T: Any>(val: &T) {
    let v_any = val as &dyn Any;
    if let Some(string_value) = v_any.downcast_ref::<String>() {
        println!("String value: {:?}", string_value);
    } else if let Some(int_value) = v_any.downcast_ref::<i32>() {
        println!("Integer value: {:?}", int_value);
    } else {
        println!("Unknown Type");
    }
}