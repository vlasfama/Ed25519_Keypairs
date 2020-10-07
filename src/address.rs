use ed25519_dalek::PublicKey;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Error, ErrorKind};
use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};
use subtle::{self, ConstantTimeEq};
use subtle_encoding::hex;

/// Size of an  account address in bytes
pub const LENGTH: usize = 20;

/// Account Address
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Address([u8; LENGTH]);

impl Address {
    /// Create a new account address from raw bytes
    pub fn new(bytes: [u8; LENGTH]) -> Address {
        Address(bytes)
    }

    /// Borrow the account address as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl ConstantTimeEq for Address {
    #[inline]
    fn ct_eq(&self, other: &Address) -> subtle::Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "account::address({})", self)
    }
}

// blake3(pb)[:20]
impl From<PublicKey> for Address {
    fn from(pb: PublicKey) -> Address {
        let mut hb = blake3::Hasher::new();
        hb.update(pb.as_bytes());
        hb.finalize();
        let mut bytes = [0u8; LENGTH];
        let mut output_reader = hb.finalize_xof();
        output_reader.fill(&mut bytes);
        Address(bytes)
    }
}

/// Decode account address from hex
impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept either upper or lower case hex
        let bytes = hex::decode_upper(s)
            .or_else(|_| hex::decode(s))
            .map_err(|_| ErrorKind::Other)?;

        if bytes.len() != LENGTH {
            return Err(ErrorKind::Other)?;
        }

        let mut result_bytes = [0u8; LENGTH];
        result_bytes.copy_from_slice(&bytes);
        Ok(Address(result_bytes))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|_| {
            de::Error::custom(format!(
                "expected {}-character hex string, got {:?}",
                LENGTH * 2,
                s
            ))
        })
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}
