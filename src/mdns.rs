use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

pub struct MdnsPacket {
    pub tx_id: u16,
    pub questions: Vec<MdnsQuestion>,
    pub answers: Vec<MdnsRecord>,
}

pub struct MdnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug)]
pub struct MdnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

pub fn parse_mdns_packet(data: &[u8]) -> MdnsPacket {
    let mut cursor = Cursor::new(data);

    let tx_id = cursor.read_u16::<BigEndian>().unwrap();
    let _flags = cursor.read_u16::<BigEndian>().unwrap();
    let question_count = cursor.read_u16::<BigEndian>().unwrap();
    let answer_count = cursor.read_u16::<BigEndian>().unwrap();
    let _ = cursor.read_u16::<BigEndian>().unwrap();
    let _ = cursor.read_u16::<BigEndian>().unwrap();

    let mut questions = Vec::new();
    for _ in 0..question_count {
        let (name, qtype, qclass) = parse_question(&mut cursor);
        questions.push(MdnsQuestion {
            name,
            qtype,
            qclass,
        });
    }

    let mut answers = Vec::new();
    for _ in 0..answer_count {
        let (name, rtype, rclass, ttl, rdata) = parse_record(&mut cursor);
        answers.push(MdnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        });
    }

    MdnsPacket {
        tx_id,
        questions,
        answers,
    }
}

fn parse_question(cursor: &mut Cursor<&[u8]>) -> (String, u16, u16) {
    let name = parse_name(cursor);
    let qtype = cursor.read_u16::<BigEndian>().unwrap();
    let qclass = cursor.read_u16::<BigEndian>().unwrap();
    (name, qtype, qclass)
}

fn parse_record(cursor: &mut Cursor<&[u8]>) -> (String, u16, u16, u32, Vec<u8>) {
    let name = parse_name(cursor);
    let rtype = cursor.read_u16::<BigEndian>().unwrap();
    let rclass = cursor.read_u16::<BigEndian>().unwrap();
    let ttl = cursor.read_u32::<BigEndian>().unwrap();
    let rdlength = cursor.read_u16::<BigEndian>().unwrap();
    let mut rdata = vec![0; rdlength as usize];
    cursor.read_exact(&mut rdata).unwrap();
    (name, rtype, rclass, ttl, rdata)
}

fn parse_name(cursor: &mut Cursor<&[u8]>) -> String {
    let mut name = String::new();
    let mut pos = cursor.position() as usize;
    let data = cursor.get_ref();

    loop {
        let len = data[pos];
        pos += 1;

        if len == 0 {
            break;
        }

        let label = String::from_utf8_lossy(&data[pos..pos + len as usize]).to_string();
        name.push_str(&label);
        name.push('.');

        pos += len as usize;
    }

    cursor.set_position(pos as u64);
    name
}
