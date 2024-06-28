use rusqlite::Connection;
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::thread::sleep;
use std::time::Duration;
use std::{mem, ptr};
use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO};
use windows::Win32::Networking::WinSock::{
    bind, recv, socket, WSAGetLastError, WSAIoctl, WSAStartup, AF_INET, INVALID_SOCKET, IN_ADDR,
    IPPROTO_IP, RCVALL_IPLEVEL, SEND_RECV_FLAGS, SIO_RCVALL, SOCKADDR, SOCKADDR_IN, SOCKET_ERROR,
    SOCK_RAW, WSADATA,
};

use dns::{parse_dns_packet, DnsPacket};
use mdns::{parse_mdns_packet, MdnsPacket};
use sql::{
    init_db, insert_dns_answer, insert_dns_question, insert_mdns_answer, insert_mdns_question,
};

pub mod dns;
pub mod mdns;
pub mod sql;

fn get_adapters() -> Vec<Ipv4Addr> {
    let mut addrs = vec![];
    let mut buf_size = mem::size_of::<IP_ADAPTER_INFO>() as u32;
    let mut adapter_info = vec![0u8; buf_size as usize];

    let mut rc = unsafe {
        GetAdaptersInfo(
            Some(adapter_info.as_mut_ptr() as *mut IP_ADAPTER_INFO),
            &mut buf_size,
        )
    };

    if rc == ERROR_BUFFER_OVERFLOW.0 {
        adapter_info = vec![0u8; buf_size as usize];
        rc = unsafe {
            GetAdaptersInfo(
                Some(adapter_info.as_mut_ptr() as *mut IP_ADAPTER_INFO),
                &mut buf_size,
            )
        }
    }

    if rc == 0 {
        let mut adapter = adapter_info.as_ptr() as *const IP_ADAPTER_INFO;
        while !adapter.is_null() {
            let adapter_ref = unsafe { &*adapter };
            let ip_addr = adapter_ref.IpAddressList.IpAddress.String;
            let ip_addr_str = unsafe { CStr::from_ptr(ip_addr.as_ptr()).to_str().unwrap() };

            addrs.push(ip_addr_str.parse().unwrap());

            adapter = adapter_ref.Next;
        }
    } else {
        println!("GetAdaptersInfo failed with error: {:?}", rc);
    }

    addrs
}

fn pcap(conn: &Connection, addrs: Vec<Ipv4Addr>) {
    let mut wsa_data: WSADATA = Default::default();
    unsafe { WSAStartup(0x0202, &mut wsa_data) };

    let sd = unsafe { socket(AF_INET.0 as i32, SOCK_RAW, IPPROTO_IP.0) };
    if sd == INVALID_SOCKET {
        panic!("panic at the disco! bad socket: {:?}", unsafe {
            WSAGetLastError()
        });
    }

    println!("[+] socket created successfully: {:?}", sd);

    let mut in_addr: IN_ADDR = unsafe { mem::zeroed() };
    in_addr.S_un.S_addr = u32::from_ne_bytes(addrs[0].octets());
    let port: u16 = 0;

    let addr: SOCKADDR_IN = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: in_addr,
        sin_zero: [0; 8],
    };

    let rc = unsafe {
        bind(
            sd,
            &addr as *const SOCKADDR_IN as *const SOCKADDR,
            mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };
    if rc == SOCKET_ERROR {
        panic!("panic at the disco! failed to bind: {:?}", unsafe {
            WSAGetLastError()
        });
    }

    println!("[+] socket bound successfully: {:?}", rc);

    let value = RCVALL_IPLEVEL;
    let mut out: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            sd,
            SIO_RCVALL,
            Some(&value as *const _ as *const _),
            RCVALL_IPLEVEL.0 as u32,
            Some(ptr::null_mut()),
            0,
            &mut out,
            None,
            None,
        )
    };
    if rc == SOCKET_ERROR {
        panic!("panic at the disco! IOctl failed {:?}", unsafe {
            WSAGetLastError()
        });
    }

    println!("[+] WSAIoctl() successful {:?}", rc);

    sleep(Duration::from_secs(2));

    const BUFFER_SIZE_HDR: usize = 16;
    const BUFFER_SIZE_PKT: usize = 65536;
    const BUFFER_OFFSET_ETH: usize = 0;

    let mut buffer = [0u8; BUFFER_SIZE_HDR + BUFFER_SIZE_PKT];
    buffer[BUFFER_OFFSET_ETH + 12] = 0x08;

    println!("[+] listening...");
    loop {
        let rc = unsafe { recv(sd, &mut buffer, SEND_RECV_FLAGS(0)) };
        if rc == SOCKET_ERROR {
            panic!("recv() failed: {:?}", unsafe { WSAGetLastError() });
        }

        if rc == 0 {
            break;
        }

        let ip_header_start = BUFFER_OFFSET_ETH;
        let ip_header_length = (buffer[ip_header_start] & 0x0F) as usize * 4;

        let ip_packet_length =
            u16::from_be_bytes([buffer[ip_header_start + 2], buffer[ip_header_start + 3]]) as usize;

        let src_ip = Ipv4Addr::new(
            buffer[ip_header_start + 12],
            buffer[ip_header_start + 13],
            buffer[ip_header_start + 14],
            buffer[ip_header_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            buffer[ip_header_start + 16],
            buffer[ip_header_start + 17],
            buffer[ip_header_start + 18],
            buffer[ip_header_start + 19],
        );

        let protocol = buffer[ip_header_start + 9];

        let transport_header_start = ip_header_start + ip_header_length;
        let transport_header_length = match protocol {
            6 => 20, // TCP header length
            17 => 8, // UDP header length
            _ => 0,  // Unsupported protocol
        };

        let src_port = u16::from_be_bytes([
            buffer[transport_header_start],
            buffer[transport_header_start + 1],
        ]);

        let dst_port = u16::from_be_bytes([
            buffer[transport_header_start + 2],
            buffer[transport_header_start + 3],
        ]);

        let data_start = transport_header_start + transport_header_length;
        let data_length = ip_packet_length - ip_header_length - transport_header_length;
        let data = &buffer[data_start..data_start + data_length];

        // udp
        if protocol == 17 {
            match (dst_ip.to_string().as_str(), dst_port) {
                ("224.0.0.251", 5353) => {
                    let packet = parse_mdns_packet(data);
                    parse_mdns(conn, packet, src_ip).unwrap();
                }
                (_, 53) => {
                    let packet = parse_dns_packet(data);
                    parse_dns(conn, packet, src_ip, dst_ip).unwrap();
                }
                _ => {}
            }

            match src_port {
                53 => {
                    let packet = parse_dns_packet(data);
                    parse_dns(conn, packet, src_ip, dst_ip).unwrap();
                }
                _ => {}
            }
        }
    }
}

fn parse_mdns(
    conn: &Connection,
    packet: MdnsPacket,
    src_ip: Ipv4Addr,
) -> Result<usize, rusqlite::Error> {
    if !packet.questions.is_empty() {
        packet.questions.iter().for_each(|x| {
            println!("inserting mdns question");
            insert_mdns_question(conn, x, src_ip).unwrap();
        });
    }

    if !packet.answers.is_empty() {
        packet.answers.iter().for_each(|x| {
            println!("inserting mdns record");
            insert_mdns_answer(conn, x, src_ip).unwrap();
        })
    }

    Ok(1)
}

fn parse_dns(
    conn: &Connection,
    packet: DnsPacket,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Result<usize, rusqlite::Error> {
    if !packet.questions.is_empty() {
        packet.questions.iter().for_each(|x| {
            insert_dns_question(conn, x, src_ip).unwrap();
        })
    }

    if !packet.answers.is_empty() {
        packet.answers.iter().for_each(|x| {
            insert_dns_answer(conn, x, src_ip, dst_ip).unwrap();
        });
    }

    Ok(1)
}

fn main() {
    println!("[+] starting windows raw socket program");

    let conn = init_db().unwrap();
    let addrs = get_adapters();

    pcap(&conn, addrs);
}
