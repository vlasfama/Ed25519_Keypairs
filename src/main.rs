extern crate ed25519_dalek;
use bip39::{Language, Mnemonic, MnemonicType};
mod keypairs;
use keypairs::Keypair;
mod address;
use address::Address;

fn main() {
    let (kp, mnemonic) = Keypair::generate_with_seed();
    let pb = kp.public();
    println!("the public key {:?}", pb);
    let address = Address::from(*pb);
    println!("the public key {:?}", address);
}
