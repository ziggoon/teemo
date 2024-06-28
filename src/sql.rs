use std::net::Ipv4Addr;

use rusqlite::{params, Connection};

use crate::{dns::*, mdns::*};

pub fn init_db() -> Result<Connection, rusqlite::Error> {
    println!("[+] creating .db");
    let conn = Connection::open(".db")?;

    create_tables(&conn)?;
    Ok(conn)
}

fn create_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
    println!("[+] creating dns_recrods table");
    conn.execute_batch(
        "begin;
        create table if not exists dns_questions(name text, qtype text, qclass text, src_ip text);
        create table if not exists dns_answers(name text, rtype text, ttl integer, data text, src_ip text, dst_ip text);
        create table if not exists mdns_questions(name text, qtype text, qclass text, src_ip text);
        create table if not exists mdns_answers(name text, rtype text, ttl integer, data text, src_ip text);
        commit;",
    )
}

pub fn insert_dns_question(
    conn: &Connection,
    question: &DnsQuestion,
    src_ip: Ipv4Addr,
) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "insert into mdns_questions (name, qtype, qclass, src_ip) values (?1, ?2, ?3, ?4)",
        params![
            question.qname,
            question.qtype,
            question.qclass,
            src_ip.to_string()
        ],
    )
}

pub fn insert_dns_answer(
    conn: &Connection,
    record: &DnsRecord,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "insert into dns_answers (name, rtype, ttl, data, src_ip, dst_ip) values (?1, ?2, ?3, ?4, ?5, ?6)",
        params![record.name, record.rtype, record.ttl, record.rdata, src_ip.to_string(), dst_ip.to_string()],
    )
}

pub fn insert_mdns_question(
    conn: &Connection,
    question: &MdnsQuestion,
    src_ip: Ipv4Addr,
) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "insert into mdns_questions (name, qtype, qclass, src_ip) values (?1, ?2, ?3, ?4)",
        params![
            question.name,
            question.qtype,
            question.qclass,
            src_ip.to_string()
        ],
    )
}

pub fn insert_mdns_answer(
    conn: &Connection,
    record: &MdnsRecord,
    src_ip: Ipv4Addr,
) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "insert into mdns_answers (name, rtype, ttl, data, src_ip) values (?1, ?2, ?3, ?4, ?5)",
        params![
            record.name,
            record.rtype,
            record.ttl,
            record.rdata,
            src_ip.to_string()
        ],
    )
}
