use std::env;
use std::fs::File;
use std::io::{self, Write};

use sequoia_openpgp as openpgp;
use openpgp::crypto::{Password, SessionKey, S2K};
use openpgp::packet::skesk::SKESK6;
use openpgp::packet::SKESK;
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::serialize::stream::{Compressor, Encryptor, LiteralWriter, Message};
use openpgp::serialize::Serialize;
use openpgp::types::{AEADAlgorithm, CompressionAlgorithm, DataFormat, SymmetricAlgorithm};
use openpgp::Packet;

fn main() -> openpgp::Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, command, key_path, input, output]
            if command == "encrypt" || command == "encrypt-text" || command == "encrypt-compressed" => {
            let (algorithm, key) = read_key(key_path)?;
            let mut source = File::open(input)?;
            let destination = File::create(output)?;
            let message = Message::new(destination);
            let encrypted = Encryptor::with_session_key(message, algorithm, key)?
                .aead_algo(AEADAlgorithm::GCM)
                .build()?;
            let inner = if command == "encrypt-compressed" {
                Compressor::new(encrypted).algo(CompressionAlgorithm::Zlib).build()?
            } else {
                encrypted
            };
            let literal = LiteralWriter::new(inner);
            let literal = if command == "encrypt-text" {
                literal.format(DataFormat::Unicode)
            } else {
                literal
            };
            let mut literal = literal.build()?;
            io::copy(&mut source, &mut literal)?;
            literal.finalize()?;
        }
        [_, command, key_path, input, output] if command == "encrypt-two-literals" => {
            let (algorithm, key) = read_key(key_path)?;
            let mut source = File::open(input)?;
            let destination = File::create(output)?;
            let message = Message::new(destination);
            let encrypted = Encryptor::with_session_key(message, algorithm, key)?
                .aead_algo(AEADAlgorithm::GCM)
                .build()?;
            let mut first = LiteralWriter::new(encrypted).build()?;
            io::copy(&mut source, &mut first)?;
            let encrypted = first
                .finalize_one()?
                .ok_or_else(|| openpgp::anyhow::anyhow!("missing encrypted writer"))?;
            let mut second = LiteralWriter::new(encrypted).build()?;
            second.write_all(b"unexpected second literal")?;
            second.finalize()?;
        }
        [_, command, key_path, input, output] if command == "decrypt" => {
            let (algorithm, key) = read_key(key_path)?;
            let mut packets = PacketParser::from_file(input)?;
            let mut destination = File::create(output)?;
            let mut seip_count = 0;
            let mut literal_count = 0;
            while let PacketParserResult::Some(mut packet) = packets {
                match &packet.packet {
                    Packet::SEIP(_) => {
                        if packet.packet.version() != Some(2) {
                            return Err(openpgp::anyhow::anyhow!("expected SEIPDv2"));
                        }
                        seip_count += 1;
                        packet.decrypt(algorithm, &key)?;
                    }
                    Packet::Literal(_) => {
                        literal_count += 1;
                        io::copy(&mut packet, &mut destination)?;
                    }
                    Packet::CompressedData(_) => {}
                    _ => return Err(openpgp::anyhow::anyhow!("unexpected OpenPGP packet")),
                }
                packets = packet.recurse()?.1;
            }
            if seip_count != 1 || literal_count != 1 {
                return Err(openpgp::anyhow::anyhow!("expected one SEIPDv2 and one literal packet"));
            }
            destination.flush()?;
        }
        [_, command, password_path, input, output] if command == "password-encrypt" => {
            // Sequoia's Encryptor defaults to iterated S2K, so build the Argon2 SKESK v6 here.
            let password = Password::from(std::fs::read(password_path)?);
            let key = SessionKey::new(32)?;
            let mut salt = [0u8; 16];
            openpgp::crypto::random(&mut salt)?;
            // Cheap but multi-lane costs keep the checked-in fixture fast to open.
            let s2k = S2K::Argon2 { salt, t: 2, p: 4, m: 10 };
            let skesk = SKESK6::with_password(SymmetricAlgorithm::AES256, SymmetricAlgorithm::AES256,
                                              AEADAlgorithm::GCM, s2k, &key, &password)?;
            let mut destination = File::create(output)?;
            Packet::SKESK(skesk.into()).serialize(&mut destination)?;
            let encrypted = Encryptor::with_session_key(Message::new(destination), SymmetricAlgorithm::AES256, key)?
                .aead_algo(AEADAlgorithm::GCM)
                .build()?;
            let mut literal = LiteralWriter::new(encrypted).build()?;
            io::copy(&mut File::open(input)?, &mut literal)?;
            literal.finalize()?;
        }
        [_, command, password_path, input, output] if command == "password-decrypt" => {
            let password = Password::from(std::fs::read(password_path)?);
            let mut packets = PacketParser::from_file(input)?;
            let mut destination = File::create(output)?;
            let mut wrappers = Vec::new();
            let mut seip_count = 0;
            let mut literal_count = 0;
            while let PacketParserResult::Some(mut packet) = packets {
                match &packet.packet {
                    Packet::SKESK(SKESK::V6(wrapper)) => {
                        if !matches!(wrapper.s2k(), S2K::Argon2 { .. }) {
                            return Err(openpgp::anyhow::anyhow!("expected Argon2 S2K"));
                        }
                        wrappers.push(wrapper.clone());
                    }
                    Packet::SEIP(_) => {
                        if packet.packet.version() != Some(2) {
                            return Err(openpgp::anyhow::anyhow!("expected SEIPDv2"));
                        }
                        seip_count += 1;
                        let key = wrappers.iter().find_map(|wrapper| wrapper.decrypt(&password).ok())
                            .ok_or_else(|| openpgp::anyhow::anyhow!("password did not unlock a wrapper"))?;
                        packet.decrypt(SymmetricAlgorithm::AES256, &key)?;
                    }
                    Packet::Literal(_) => {
                        literal_count += 1;
                        io::copy(&mut packet, &mut destination)?;
                    }
                    _ => return Err(openpgp::anyhow::anyhow!("unexpected OpenPGP packet")),
                }
                packets = packet.recurse()?.1;
            }
            if wrappers.is_empty() || seip_count != 1 || literal_count != 1 {
                return Err(openpgp::anyhow::anyhow!("expected SKESK v6, one SEIPDv2, and one literal packet"));
            }
            destination.flush()?;
        }
        [_, command, input] if command == "inspect" => {
            let mut packets = PacketParser::from_file(input)?;
            while let PacketParserResult::Some(packet) = packets {
                println!("{:?} version={:?}", packet.packet.tag(), packet.packet.version());
                packets = packet.next()?.1;
            }
        }
        _ => return Err(openpgp::anyhow::anyhow!("usage: encrypt|encrypt-text|encrypt-compressed|encrypt-two-literals|decrypt KEY INPUT OUTPUT; password-encrypt|password-decrypt PASSWORD_FILE INPUT OUTPUT; inspect INPUT")),
    }
    Ok(())
}

fn read_key(path: &str) -> openpgp::Result<(SymmetricAlgorithm, SessionKey)> {
    let bytes = std::fs::read(path)?;
    let algorithm = match bytes.len() {
        16 => SymmetricAlgorithm::AES128,
        32 => SymmetricAlgorithm::AES256,
        _ => return Err(openpgp::anyhow::anyhow!("session key must be 16 or 32 bytes")),
    };
    Ok((algorithm, SessionKey::from(bytes)))
}
