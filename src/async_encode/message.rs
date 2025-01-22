use core::iter::FromIterator;
use std::io::Cursor;

use async_trait::async_trait;
use bitcoin::{
    consensus::encode::{self, CheckedData},
    p2p::{
        message::{CommandString, NetworkMessage, RawNetworkMessage},
        message_network::VersionMessage,
        Address, ServiceFlags,
    },
};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::async_encode::encode::{AsyncDecodable, DecodeError};

const MAX_MSG_SIZE: usize = 5_000_000;

#[async_trait]
impl AsyncDecodable for RawNetworkMessage {
    async fn async_consensus_decode_from_finite_reader<R: AsyncRead + Sized + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, DecodeError<Self>> {
        let magic = AsyncDecodable::async_consensus_decode_from_finite_reader(r)
            .await
            .map_err(|err| DecodeError::new(err.into()))?;
        let cmd = CommandString::async_consensus_decode_from_finite_reader(r)
            .await
            .map_err(|err| DecodeError::new(err.into()))?;
        let raw_payload = CheckedData::async_consensus_decode_from_finite_reader(r)
            .await
            .map_err(|err| DecodeError::new(err.into()))?
            .into_data();
        let mut mem_d = Cursor::new(raw_payload);
        let payload = match cmd.as_ref() {
            "version" => NetworkMessage::Version(
                AsyncDecodable::async_consensus_decode_from_finite_reader(&mut mem_d)
                    .await
                    .map_err(|err| DecodeError::new(err.into()))?,
            ),
            "verack" => NetworkMessage::Verack,
            "getdata" => NetworkMessage::GetData(
                AsyncDecodable::async_consensus_decode_from_finite_reader(&mut mem_d)
                    .await
                    .map_err(|err| DecodeError::new(err.into()))?,
            ),
            "ping" => NetworkMessage::Ping(
                AsyncDecodable::async_consensus_decode_from_finite_reader(&mut mem_d)
                    .await
                    .map_err(|err| DecodeError::new(err.into()))?,
            ),
            "alert" => NetworkMessage::Alert(
                AsyncDecodable::async_consensus_decode_from_finite_reader(&mut mem_d)
                    .await
                    .map_err(|err| DecodeError::new(err.into()))?,
            ),
            "wtxidrelay" => NetworkMessage::WtxidRelay,
            "sendaddrv2" => NetworkMessage::SendAddrV2,
            _ => NetworkMessage::Unknown {
                command: cmd,
                payload: mem_d.into_inner(),
            },
        };
        Ok(RawNetworkMessage::new(magic, payload))
    }

    #[inline]
    async fn async_consensus_decode<R: AsyncRead + Sized + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, DecodeError<Self>> {
        Self::async_consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).get_mut()).await
    }
}

#[async_trait]
impl AsyncDecodable for CommandString {
    #[inline]
    async fn async_consensus_decode<R: AsyncRead + Sized + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, DecodeError<Self>> {
        let rawbytes: [u8; 12] = AsyncDecodable::async_consensus_decode(r)
            .await
            .map_err(|err| DecodeError::new(err.into()))?;
        let rv: String = FromIterator::from_iter(rawbytes.iter().filter_map(|&u| {
            if u > 0 {
                Some(u as char)
            } else {
                None
            }
        }));
        Ok(CommandString::try_from(rv)
            .map_err(|_| encode::Error::ParseFailed("Failed to parse CommandString"))?)
    }
}

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (

        #[async_trait]
        impl AsyncDecodable for $thing {

            #[inline]
            async fn async_consensus_decode_from_finite_reader<R: AsyncRead + Sized + Send + Unpin>(
                r: &mut R,
            ) -> Result<$thing, DecodeError<Self>> {
                Ok($thing {
                    $($field: AsyncDecodable::async_consensus_decode_from_finite_reader(r).await.map_err(|err| DecodeError::new(err.into()))?),+
                })
            }

            #[inline]
            async fn async_consensus_decode<R: AsyncRead + Sized + Send + Unpin>(
                r: &mut R,
            ) -> Result<$thing, DecodeError<Self>> {
                use tokio::io::AsyncReadExt as _;
                let mut r = r.take(bitcoin::consensus::encode::MAX_VEC_SIZE as u64);
                Ok($thing {
                    $($field: AsyncDecodable::async_consensus_decode(r.get_mut()).await.map_err(|err| DecodeError::new(err.into()))?),+
                })
            }
        }
    );
}

pub(crate) use impl_consensus_encoding;

impl_consensus_encoding!(
    VersionMessage,
    version,
    services,
    timestamp,
    receiver,
    sender,
    nonce,
    user_agent,
    start_height,
    relay
);

#[async_trait]
impl AsyncDecodable for ServiceFlags {
    #[inline]
    async fn async_consensus_decode<R: AsyncRead + Sized + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, DecodeError<Self>> {
        Ok(ServiceFlags::from(
            u64::async_consensus_decode(r)
                .await
                .map_err(|err| DecodeError::new(err.into()))?,
        ))
    }
}

async fn read_be_address<R: AsyncRead + Sized + Unpin>(
    r: &mut R,
) -> Result<[u16; 8], DecodeError<[u16; 8]>> {
    let mut address = [0u16; 8];
    let mut buf = [0u8; 2];

    for word in &mut address {
        r.read_exact(&mut buf)
            .await
            .map_err(bitcoin::io::Error::from)?;
        *word = u16::from_be_bytes(buf)
    }
    Ok(address)
}

#[async_trait]
impl AsyncDecodable for Address {
    #[inline]
    async fn async_consensus_decode<R: AsyncRead + Sized + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, DecodeError<Self>> {
        Ok(Address {
            services: AsyncDecodable::async_consensus_decode(r)
                .await
                .map_err(|err| DecodeError::new(err.into()))?,
            address: read_be_address(r)
                .await
                .map_err(|err| DecodeError::new(err.into()))?,
            port: u16::swap_bytes(
                AsyncDecodable::async_consensus_decode(r)
                    .await
                    .map_err(|err| DecodeError::new(err.into()))?,
            ),
        })
    }
}
