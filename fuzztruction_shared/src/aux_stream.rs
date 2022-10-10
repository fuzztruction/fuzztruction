use core::slice;
use std::convert::TryInto;

use crate::aux_messages::{AuxStreamMessage, AuxStreamType};
use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Copy)]
enum ContentType<'a> {
    Str(&'a str),
}

pub struct AuxStreamBuilder<'a> {
    stream_type: AuxStreamType,
    content_type: Option<ContentType<'a>>,
}

impl<'a> AuxStreamBuilder<'a> {
    pub fn new(stream_type: AuxStreamType) -> AuxStreamBuilder<'a> {
        AuxStreamBuilder {
            stream_type,
            content_type: None,
        }
    }

    pub fn from_str(&mut self, s: &'a str) -> &'a mut AuxStreamBuilder {
        self.content_type = Some(ContentType::Str(s));
        self
    }

    fn build_str(&self, s: &str) -> Vec<AuxStreamMessage> {
        let chunk_size = AuxStreamMessage::max_chunk_size() / 2;
        let utf16_iter = s.encode_utf16().collect::<Vec<_>>();
        let chunks = utf16_iter.chunks(chunk_size).collect::<Vec<_>>();
        let mut msgs = Vec::new();

        for c in chunks.iter().enumerate() {
            let u8_chunk =
                unsafe { slice::from_raw_parts(c.1.as_ptr() as *const u8, c.1.len() * 2) };
            let msg =
                AuxStreamMessage::new(self.stream_type, u8_chunk, Some(chunks.len() - c.0 - 1));
            msgs.push(msg);
        }

        msgs
    }

    pub fn build(&self) -> Vec<AuxStreamMessage> {
        let t = self.content_type.unwrap();

        match t {
            ContentType::Str(s) => self.build_str(s),
            #[allow(unreachable_patterns)]
            _ => todo!("Content type not jet implemented: {:#?}", t),
        }
    }
}

pub struct AuxStreamAssemblerResult;

impl AuxStreamAssemblerResult {
    pub fn stream_type() -> AuxStreamType {
        todo!();
    }

    pub fn to_string(&self) -> Result<String> {
        todo!();
    }

    pub fn to_string_lossy(&self) -> Result<String> {
        todo!();
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        todo!();
    }
}

#[derive(Debug)]
pub struct AuxStreamAssembler {
    message_buffer: Vec<AuxStreamMessage>,
}

impl AuxStreamAssembler {
    pub fn new() -> AuxStreamAssembler {
        AuxStreamAssembler {
            message_buffer: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.message_buffer = Vec::new();
    }

    // FIXME: This should return bytes and we leave the task to the caller on
    // how to actually decode the data?
    pub fn process_str_msg(
        &mut self,
        msg: AuxStreamMessage,
    ) -> Result<Option<(AuxStreamType, String)>> {
        if let Some(last) = self.message_buffer.last() {
            if last.stream_type() != msg.stream_type() {
                let err = Err(anyhow!(
                    "Payload type ({:#?}) does not match the last messages type ({:#?})",
                    msg.stream_type(),
                    last.stream_type()
                ));
                self.reset();
                return err;
            }
        }

        let msgs_left = msg.msgs_left();
        let msg_type = msg.stream_type();

        self.message_buffer.push(msg);
        if msgs_left == 0 {
            // This was the last message.
            let mut utf16_values =
                Vec::with_capacity(AuxStreamMessage::max_chunk_size() * self.message_buffer.len());
            for chunk in &self.message_buffer {
                let payload = chunk.chunk_16();
                if let None = payload {
                    let err = Err(anyhow!(
                        "Message length ({}) is not divisible by 2",
                        chunk.chunk_len()
                    ));
                    self.reset();
                    return err;
                }
                payload.unwrap().iter().for_each(|e| utf16_values.push(*e));
            }
            self.reset();
            return Ok(Some((
                msg_type.try_into().unwrap(),
                String::from_utf16_lossy(&utf16_values),
            )));
        }

        // Wating for more messages.
        return Ok(None);
    }
}

#[cfg(test)]
mod test {
    #[allow(unused)]
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    use super::AuxStreamBuilder;
    use crate::{aux_messages::AuxStreamType, aux_stream::AuxStreamAssembler};

    #[allow(unused)]
    fn disassemble_assemble(payload: &str) {
        let mut builder = AuxStreamBuilder::new(AuxStreamType::LogRecord);

        let msgs = builder.from_str(&payload).build();
        assert!(msgs.len() > 0);
        let total_len: usize = msgs.iter().map(|e| e.chunk_len()).sum();
        // We are sending as UTF16, thus this should be twice as large.
        assert_eq!(total_len, payload.chars().count() * 2);

        let mut assembler = AuxStreamAssembler::new();

        let mut result = None;
        for m in msgs {
            let ret = assembler.process_str_msg(m);
            match ret {
                Ok(Some(x)) => {
                    result = Some(x);
                }
                Ok(None) => (),
                Err(..) => unreachable!(),
            }
        }

        let result = result.unwrap();
        assert_eq!(result.0, AuxStreamType::LogRecord);
        assert_eq!(result.1, payload);
    }

    #[test]
    fn test_disassemble_assemble() {
        (0..1000).for_each(|_| {
            let len = rand::thread_rng().gen_range(1..5134);
            let payload: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(len)
                .map(char::from)
                .collect();
            disassemble_assemble(&payload);
        });
    }
}
