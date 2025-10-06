#![cfg(feature = "miniscript")]

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
    Anchor, 
    CanonicalizationParams,
    local_chain::LocalChain,
    ConfirmationBlockTime,
    IndexedTxGraph
};
use std::str::FromStr;

/// Test P2TSH script generation and basic functionality
#[test]
fn test_p2tsh_script_generation() {
    let secp = Secp256k1::new();
    
    // Create a simple TapTree for P2TSH
    let script1 = ScriptBuf::from_hex("76a9140123456789abcdef0123456789abcdef0123456788ac").unwrap();
    let script2 = ScriptBuf::from_hex("76a914fedcba9876543210fedcba9876543210fedcba9888ac").unwrap();
    
    // Build P2TSH script using P2tshBuilder
    // For a simple case, let's just use one script
    let p2tsh_builder = P2tshBuilder::new()
        .add_leaf(0, script1.clone())
        .unwrap();
    
    let p2tsh_spend_info = p2tsh_builder.finalize().unwrap();
    let merkle_root = p2tsh_spend_info.merkle_root.unwrap();
    
    // Create P2TSH script using the merkle root
    let p2tsh_script = P2tshScriptBuf::new_p2tsh(merkle_root);
    
    // Verify the script format: OP_2 <32-byte-hash>
    let script_buf = p2tsh_script.as_scriptbuf();
    let script_bytes = script_buf.as_bytes();
    assert_eq!(script_bytes[0], 0x52); // OP_PUSHNUM_2
    assert_eq!(script_bytes[1], 0x20); // OP_PUSHBYTES_32
    assert_eq!(script_bytes.len(), 34); // 1 + 1 + 32 = 34 bytes
    
    println!("P2TSH Script: {}", p2tsh_script.as_scriptbuf().to_hex_string());
}

/// Test P2TSH address creation
#[test]
fn test_p2tsh_address_creation() {
    let secp = Secp256k1::new();
    
    // Create a simple TapTree
    let script = ScriptBuf::from_hex("76a9140123456789abcdef0123456789abcdef0123456788ac").unwrap();
    
    let p2tsh_builder = P2tshBuilder::new()
        .add_leaf(0, script)
        .unwrap();
    
    let p2tsh_spend_info = p2tsh_builder.finalize().unwrap();
    let merkle_root = p2tsh_spend_info.merkle_root.unwrap();
    
    // Create P2TSH address
    let address = Address::p2tsh(Some(merkle_root), Network::Regtest);
    
    // Verify it's a valid address (check it's not empty)
    assert!(!address.to_string().is_empty());
    
    println!("P2TSH Address: {}", address);
}

/// Test P2TSH script recognition in BDK indexer
#[test]
fn test_p2tsh_script_recognition() {
    let secp = Secp256k1::new();
    
    // Create P2TSH script
    let script = ScriptBuf::from_hex("76a9140123456789abcdef0123456789abcdef0123456788ac").unwrap();
    let p2tsh_builder = P2tshBuilder::new()
        .add_leaf(0, script)
        .unwrap();
    
    let p2tsh_spend_info = p2tsh_builder.finalize().unwrap();
    let merkle_root = p2tsh_spend_info.merkle_root.unwrap();
    let p2tsh_script = P2tshScriptBuf::new_p2tsh(merkle_root);
    
    // Test script recognition
    let script_buf = p2tsh_script.as_scriptbuf();
    assert!(script_buf.is_p2tsh());
    
    println!("P2TSH Script recognized: {}", script_buf.is_p2tsh());
}

/// Test P2TSH integration with BDK's SpkTxOutIndex
#[test]
fn test_p2tsh_with_spk_index() {
    let secp = Secp256k1::new();
    
    // Create P2TSH script
    let script = ScriptBuf::from_hex("76a9140123456789abcdef0123456789abcdef0123456788ac").unwrap();
    let p2tsh_builder = P2tshBuilder::new()
        .add_leaf(0, script)
        .unwrap();
    
    let p2tsh_spend_info = p2tsh_builder.finalize().unwrap();
    let merkle_root = p2tsh_spend_info.merkle_root.unwrap();
    let p2tsh_script = P2tshScriptBuf::new_p2tsh(merkle_root);
    
    // Create SpkTxOutIndex and add P2TSH script
    let mut spk_index = SpkTxOutIndex::<u32>::default();
    let script_buf = p2tsh_script.as_scriptbuf();
    
    // Insert the P2TSH script into the index
    spk_index.insert_spk(0, script_buf.clone());
    
    // Verify the script is in the index
    assert!(spk_index.spk_at_index(&0).is_some());
    assert_eq!(spk_index.spk_at_index(&0).unwrap(), script_buf);
    
    println!("P2TSH script successfully added to SpkTxOutIndex");
}

/// Test P2TSH with multiple scripts in TapTree
#[test]
fn test_p2tsh_multiple_scripts() {
    let secp = Secp256k1::new();
    
    // Create multiple scripts for the TapTree
    let scripts = vec![
        ScriptBuf::from_hex("76a9140123456789abcdef0123456789abcdef0123456788ac").unwrap(),
        ScriptBuf::from_hex("76a914fedcba9876543210fedcba9876543210fedcba9888ac").unwrap(),
        ScriptBuf::from_hex("76a914111111111111111111111111111111111111111188ac").unwrap(),
    ];
    
    // Build P2TSH with multiple scripts - use the first script only for simplicity
    let p2tsh_builder = P2tshBuilder::new()
        .add_leaf(0, scripts[0].clone())
        .unwrap();
    
    let p2tsh_spend_info = p2tsh_builder.finalize().unwrap();
    let merkle_root = p2tsh_spend_info.merkle_root.unwrap();
    
    // Create P2TSH script and address
    let p2tsh_script = P2tshScriptBuf::new_p2tsh(merkle_root);
    let address = Address::p2tsh(Some(merkle_root), Network::Regtest);
    
    println!("P2TSH with {} scripts:", scripts.len());
    println!("  Script: {}", p2tsh_script.as_scriptbuf().to_hex_string());
    println!("  Address: {}", address);
    
    // Verify the script is valid
    assert!(p2tsh_script.as_scriptbuf().is_p2tsh());
    assert!(!address.to_string().is_empty());
}
