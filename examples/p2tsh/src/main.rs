//! P2TSH (Pay To Tap Script Hash) Example
//!
//! This example demonstrates how to create and use P2TSH addresses and scripts
//! in BDK. P2TSH is similar to P2TR but only supports script path spending
//! (no key path spending).

use bdk_chain::bitcoin::{
    key::Secp256k1,
    secp256k1::SecretKey,
    ScriptBuf, 
    Address, 
    Network,
    taproot::TapNodeHash,
    p2tsh::{P2tshBuilder, P2tshScriptBuf}
};
use bdk_chain::{
    spk_txout::SpkTxOutIndex, 
    tx_graph::TxGraph, 
    local_chain::LocalChain,
    ConfirmationBlockTime,
    IndexedTxGraph
};

fn main() {
    println!("🔐 P2TSH (Pay To Tap Script Hash) Example");
    println!("==========================================");
    
    let secp = Secp256k1::new();
    
    // Create some example scripts for our P2TSH TapTree
    let script1 = ScriptBuf::from_hex("76a9140123456789abcdef0123456789abcdef0123456788ac").unwrap();
    let script2 = ScriptBuf::from_hex("76a914fedcba9876543210fedcba9876543210fedcba9888ac").unwrap();
    
    println!("\n📝 Creating P2TSH TapTree with scripts:");
    println!("  Script 1: {}", script1.to_hex_string());
    println!("  Script 2: {}", script2.to_hex_string());
    
    // Build P2TSH script using P2tshBuilder
    let p2tsh_builder = P2tshBuilder::new()
        .add_leaf(0, script1.clone())
        .unwrap();
    
    let p2tsh_spend_info = p2tsh_builder.finalize().unwrap();
    let merkle_root = p2tsh_spend_info.merkle_root.unwrap();
    
    println!("\n🌳 TapTree Merkle Root: {}", merkle_root);
    
    // Create P2TSH script using the merkle root
    let p2tsh_script = P2tshScriptBuf::new_p2tsh(merkle_root);
    let script_buf = p2tsh_script.as_scriptbuf();
    
    println!("\n📜 P2TSH Script:");
    println!("  Script: {}", script_buf.to_hex_string());
    println!("  Length: {} bytes", script_buf.len());
    println!("  Is P2TSH: {}", script_buf.is_p2tsh());
    
    // Verify the script format: OP_2 <32-byte-hash>
    let script_bytes = script_buf.as_bytes();
    println!("  Format: OP_{} OP_PUSHBYTES_{} <32-byte-hash>", script_bytes[0], script_bytes[1]);
    
    // Create P2TSH address
    let address = Address::p2tsh(Some(merkle_root), Network::Regtest);
    println!("\n🏠 P2TSH Address:");
    println!("  Address: {}", address);
    println!("  Network: Regtest");
    
    // Test with BDK's SpkTxOutIndex
    println!("\n🔍 Testing with BDK's SpkTxOutIndex:");
    let mut spk_index = SpkTxOutIndex::<u32>::default();
    
    // Insert the P2TSH script into the index
    spk_index.insert_spk(0, script_buf.clone());
    
    // Verify the script is in the index
    if let Some(indexed_script) = spk_index.spk_at_index(&0) {
        println!("  ✅ P2TSH script successfully indexed");
        println!("  Indexed script: {}", indexed_script.to_hex_string());
        assert_eq!(indexed_script, script_buf);
    } else {
        println!("  ❌ Failed to index P2TSH script");
    }
}

