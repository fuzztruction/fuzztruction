use libc::{self};
use log::*;
use posixmq::PosixMq;
use std::{env, ffi::CString};

use crate::messages::*;
use anyhow::{Context, Result};

use thiserror::Error;

static ENV_SEND_NAME: &str = "FT_MQ_SEND";
static ENV_RECV_NAME: &str = "FT_MQ_RECV";

#[derive(Error, Debug)]
pub enum CommunicationChannelError {
    #[error("Failed to find required environment variable. Did you export it?")]
    MissingEnvironmentVariables,
    #[error("Error while opening a message queue")]
    FailedToOpenMessageQueues,
    #[error("Failed to send message: {0}")]
    FailedToSend(anyhow::Error),
    #[error("Failed to receive message: {0}")]
    FailedToReceive(anyhow::Error),
    #[error("Malformed message error: {0}")]
    MalformedMessage(anyhow::Error),
}
#[derive(Debug)]
pub struct CommunicationChannel {
    mq_send: Option<PosixMq>,
    mq_receive: Option<PosixMq>,
    recv_name: String,
    send_name: String,
    /// Buffer used during message retrival to store the received bytes.
    buffer: Vec<u8>,
}

impl From<env::VarError> for CommunicationChannelError {
    fn from(_: env::VarError) -> Self {
        CommunicationChannelError::MissingEnvironmentVariables
    }
}

impl CommunicationChannel {
    pub fn from_env() -> Result<CommunicationChannel, CommunicationChannelError> {
        let recv_name = env::var(ENV_RECV_NAME)?;
        let send_name = env::var(ENV_SEND_NAME)?;

        let mq_send = PosixMq::open(&send_name);
        let mq_recv = PosixMq::open(&recv_name);

        for e in [&mq_send, &mq_recv].iter() {
            match e {
                Err(_) => return Err(CommunicationChannelError::FailedToOpenMessageQueues),
                _ => (),
            };
        }

        let buffer = vec![0; mq_recv.as_ref().unwrap().attributes().max_msg_len];

        Ok(CommunicationChannel {
            mq_send: Some(mq_send.unwrap()),
            mq_receive: Some(mq_recv.unwrap()),
            recv_name: recv_name.clone(),
            send_name: send_name.clone(),
            buffer,
        })
    }

    pub fn unlink(&self) {
        unsafe {
            let receive_name = CString::new(self.recv_name.clone()).unwrap();
            libc::mq_unlink(receive_name.as_ptr());
            let send_name = CString::new(self.send_name.clone()).unwrap();
            libc::mq_unlink(send_name.as_ptr());
        }
    }

    pub fn send_message<T>(&self, msg: T, timeout_ms: u64) -> Result<()>
    where
        T: Message + Default,
    {
        let send = self.mq_send.as_ref().unwrap();
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let msg_bytes = msg.to_bytes();

        // trace!("Sending message of type: {:?}", T::message_type());

        if let Err(err) = send.send_timeout(0, msg_bytes, timeout) {
            return Err(CommunicationChannelError::FailedToSend(err.into()))?;
        }

        Ok(())
    }

    pub fn recv_message(&mut self, timeout_ms: u64) -> Result<ReceivableMessages> {
        let recv = self.mq_receive.as_ref().unwrap();
        let timeout = std::time::Duration::from_millis(timeout_ms);

        let buffer = &mut self.buffer;

        let ret = recv.receive_timeout(buffer, timeout);
        if let Err(err) = ret {
            return Err(CommunicationChannelError::FailedToReceive(err.into()))?;
        }

        let header = MsgHeader::try_from_bytes(&buffer).context("Failed to read header")?;
        header
            .sanitize()
            .or_else(|e| Err(CommunicationChannelError::MalformedMessage(e)))?;

        // The header is valid. Lets try to convert the bytes into a concrete message.

        //trace!("Received message of type: {:?}", header.id);

        match header.id {
            MessageType::MsgIdHello => {
                return Ok(ReceivableMessages::HelloMessage(
                    HelloMessage::try_from_bytes(&buffer)?,
                ))
            }
            MessageType::MsgIdRun => {
                return Ok(ReceivableMessages::RunMessage(RunMessage::try_from_bytes(
                    &buffer,
                )?))
            }
            MessageType::MsgIdTerminated => {
                return Ok(ReceivableMessages::TerminatedMessage(
                    TerminatedMessage::try_from_bytes(&buffer)?,
                ))
            }
            MessageType::MsgIdShutdown => {
                return Ok(ReceivableMessages::ShutdownMessage(
                    ShutdownMessage::try_from_bytes(&buffer)?,
                ))
            }
            MessageType::MsgIdTracePointStat => {
                return Ok(ReceivableMessages::TracePointStat(
                    TracePointStat::try_from_bytes(&buffer)?,
                ))
            }
            MessageType::MsgIdSyncMutations => {
                return Ok(ReceivableMessages::SyncMutations(
                    SyncMutations::try_from_bytes(&buffer)?,
                ))
            }
            _ => {
                panic!("Received message with invalid message ID {:#?}", header.id)
            }
        }
    }
}
