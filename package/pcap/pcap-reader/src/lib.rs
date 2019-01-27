use serde_derive::Deserialize;

use byteorder::{BigEndian, WriteBytesExt};
use genet_derive::Package;
use genet_sdk::{prelude::*, reader::*};
use pcap::Header;

use std::{
    io::{BufRead, BufReader, Cursor, Error, ErrorKind, Read},
    process::{Child, ChildStdout, Command, Stdio},
};

#[derive(Deserialize)]
struct Arg {
    cmd: String,
    args: Vec<String>,
    link: u32,
}

#[derive(Default, Clone)]
struct PcapReader {}

impl Reader for PcapReader {
    fn new_worker(&self, _ctx: &Context, arg: &str) -> Result<Box<Worker>> {
        let arg: Arg = serde_json::from_str(arg)?;
        let mut child = Command::new(&arg.cmd)
            .args(&arg.args)
            .stdout(Stdio::piped())
            .spawn()?;
        let reader = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| Error::new(ErrorKind::Other, "no stdout"))?,
        );
        Ok(Box::new(PcapWorker {
            child,
            reader,
            link: arg.link,
        }))
    }
}

#[derive(Default, Package)]
pub struct DefaultPackage {
    #[reader(id = "app.genet.reader.pcap")]
    reader: PcapReader,
}

struct PcapWorker {
    child: Child,
    reader: BufReader<ChildStdout>,
    link: u32,
}

impl Worker for PcapWorker {
    fn read(&mut self) -> Result<Vec<ByteSlice>> {
        let mut header = String::new();
        self.reader.read_line(&mut header)?;
        let header = header.trim();
        if header.is_empty() {
            return Ok(vec![]);
        }
        let header: Header = serde_json::from_str(header)?;
        let size = header.datalen as usize;

        let metalen = 20;
        let mut data = vec![0u8; size + metalen];
        self.reader.read_exact(&mut data[metalen..])?;

        let mut cur = Cursor::new(data);
        cur.write_u32::<BigEndian>(self.link)?;
        cur.write_u32::<BigEndian>(header.datalen)?;
        cur.write_u32::<BigEndian>(header.actlen)?;
        cur.write_u32::<BigEndian>(header.ts_sec)?;
        cur.write_u32::<BigEndian>(header.ts_usec)?;

        let payload = ByteSlice::from(cur.into_inner());
        Ok(vec![payload])
    }

    fn layer_id(&self) -> Token {
        token!("[pcap]")
    }
}

impl Drop for PcapWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
