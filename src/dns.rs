use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

pub enum RecordType {
    A,
    AAAA,
    PTR,
}

#[derive(Debug)]
pub struct DnsPacket {
    pub tx_id: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

struct DnsHeader {
    tx_id: u16,
    flags: u16,
    questions: u16,
    answer_rrs: u16,
    authority_rrs: u16,
    additional_rrs: u16,
}

#[derive(Debug)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: String,
    pub class: u16,
    pub ttl: u32,
    pub rdata: String,
}

pub fn parse_dns_packet(packet: &[u8]) -> DnsPacket {
    let mut cursor = Cursor::new(packet);
    let mut records: Vec<DnsRecord> = Vec::new();

    let tx_id = cursor.read_u16::<BigEndian>().unwrap();
    let flags = cursor.read_u16::<BigEndian>().unwrap();
    let questions = cursor.read_u16::<BigEndian>().unwrap();
    let answer_rrs = cursor.read_u16::<BigEndian>().unwrap();
    let authority_rrs = cursor.read_u16::<BigEndian>().unwrap();
    let additional_rrs = cursor.read_u16::<BigEndian>().unwrap();

    let header = DnsHeader {
        tx_id,
        flags,
        questions,
        answer_rrs,
        authority_rrs,
        additional_rrs,
    };

    let mut questions = Vec::new();
    for _ in 0..header.questions {
        let qname = parse_domain_name(&mut cursor, packet).unwrap();
        let qtype = cursor.read_u16::<BigEndian>().unwrap();
        let qclass = cursor.read_u16::<BigEndian>().unwrap();

        questions.push(DnsQuestion {
            qname,
            qtype,
            qclass,
        });
    }

    let mut answers = parse_resource_record(&mut cursor, header.answer_rrs, packet).unwrap();
    let mut authorities = parse_resource_record(&mut cursor, header.authority_rrs, packet).unwrap();
    let mut additionals =
        parse_resource_record(&mut cursor, header.additional_rrs, packet).unwrap();

    println!("{:?}", answers);
    if !answers.is_empty() {
        records.append(&mut answers);
    }
    if !authorities.is_empty() {
        records.append(&mut authorities);
    }

    if !additionals.is_empty() {
        records.append(&mut additionals);
    }

    println!("{:?}", answers);

    DnsPacket {
        tx_id,
        questions,
        answers: records,
    }
}

// idek.. rfc this... rfc that
fn parse_domain_name(
    cursor: &mut Cursor<&[u8]>,
    original_packet: &[u8],
) -> Result<String, std::io::Error> {
    let mut domain_name = String::new();
    let mut label_length = cursor.read_u8()?;
    let mut p_flag = false;

    while label_length != 0 {
        // if the first two sig bits of the packet are 0xc0 (11).. this is a compressed record
        if (label_length & 0xc0) == 0xc0 {
            let pointer = (((label_length as u16) & 0x3F) << 8) | (cursor.read_u8()? as u16);
            let mut pointer_cursor = Cursor::new(&original_packet[pointer as usize..]);
            domain_name.push_str(&parse_domain_name(&mut pointer_cursor, original_packet)?);
            p_flag = true;
            break;
        } else {
            let mut label = vec![0; label_length as usize];
            cursor.read_exact(&mut label)?;
            domain_name.push_str(&String::from_utf8_lossy(&label));
            domain_name.push('.');
            label_length = cursor.read_u8()?;
        }
    }

    if !p_flag && !domain_name.is_empty() {
        domain_name.pop();
    }

    Ok(domain_name)
}

fn parse_resource_record(
    cursor: &mut Cursor<&[u8]>,
    count: u16,
    original_packet: &[u8],
) -> Result<Vec<DnsRecord>, std::io::Error> {
    let mut records = Vec::new();
    for _ in 0..count {
        if cursor.position() as usize >= cursor.get_ref().len() {
            break;
        }

        let name = parse_domain_name(cursor, original_packet)?;
        let rtype = match cursor.read_u16::<BigEndian>()? {
            1 => "A",
            12 => "PTR",
            28 => "AAAA",
            _ => "unknown record type",
        }
        .to_string();

        let class = cursor.read_u16::<BigEndian>()?;
        let ttl = cursor.read_u32::<BigEndian>()?;
        let rdlength = cursor.read_u16::<BigEndian>()?;
        let mut rdata = vec![0; rdlength as usize];

        if rtype != "PTR" {
            cursor.read_exact(&mut rdata)?;
        }

        let rdata_str = match rtype.as_str() {
            "A" => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
            "AAAA" => Ipv6Addr::from([
                ((rdata[0] as u16) << 8) | rdata[1] as u16,
                ((rdata[2] as u16) << 8) | rdata[3] as u16,
                ((rdata[4] as u16) << 8) | rdata[5] as u16,
                ((rdata[6] as u16) << 8) | rdata[7] as u16,
                ((rdata[8] as u16) << 8) | rdata[9] as u16,
                ((rdata[10] as u16) << 8) | rdata[11] as u16,
                ((rdata[12] as u16) << 8) | rdata[13] as u16,
                ((rdata[14] as u16) << 8) | rdata[15] as u16,
            ])
            .to_string(),
            "PTR" => parse_domain_name(cursor, original_packet)?,
            _ => "".to_string(),
        };

        let record = DnsRecord {
            name,
            rtype,
            class,
            ttl,
            rdata: rdata_str,
        };

        records.push(record);
    }

    Ok(records)
}
