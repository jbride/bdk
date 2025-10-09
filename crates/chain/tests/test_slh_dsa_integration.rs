#![cfg(feature = "miniscript")]

//! Integration tests for SLH-DSA post-quantum cryptography support in bdk_chain

use bdk_chain::{
    Balance, DescriptorExt, SlhDsaHelper,
    miniscript::{Descriptor, DescriptorPublicKey, Miniscript, Tap},
    indexer::keychain_txout::KeychainTxOutIndex,
};
use bitcoin::Amount;
use std::str::FromStr;

#[test]
fn test_descriptor_ext_has_slh_dsa_keys() {
    // Regular P2WPKH descriptor (no SLH-DSA)
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    assert!(!descriptor.has_slh_dsa_keys(), "P2WPKH should not have SLH-DSA keys");
    assert_eq!(descriptor.slh_dsa_witness_weight(), None, "No SLH-DSA witness weight for P2WPKH");

    // P2TR descriptor (no SLH-DSA)
    let desc_str = "tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    assert!(!descriptor.has_slh_dsa_keys(), "P2TR should not have SLH-DSA keys");
    assert_eq!(descriptor.slh_dsa_witness_weight(), None, "No SLH-DSA witness weight for P2TR");
}

#[test]
fn test_descriptor_ext_max_satisfaction_weight() {
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    let weight = DescriptorExt::max_satisfaction_weight(&descriptor);
    assert!(weight.is_some(), "Should have max satisfaction weight");
    assert!(weight.unwrap() > 0, "Weight should be greater than 0");
}

#[test]
fn test_slh_dsa_helper_fee_comparison() {
    let fee_rate = Amount::from_sat(10); // 10 sat/vB
    
    let (slh_fee, schnorr_fee, diff) = SlhDsaHelper::fee_comparison(1, fee_rate);
    
    // SLH-DSA should be much more expensive
    assert!(slh_fee > schnorr_fee, "SLH-DSA fee should be higher");
    assert_eq!(slh_fee, Amount::from_sat(78_570), "1 SLH-DSA sig @ 10 sat/vB = 78,570 sats");
    assert_eq!(schnorr_fee, Amount::from_sat(640), "1 Schnorr sig @ 10 sat/vB = 640 sats");
    assert_eq!(diff, Amount::from_sat(77_930), "Difference should be 77,930 sats");
    
    // Check ratio
    let ratio = slh_fee.to_sat() / schnorr_fee.to_sat().max(1);
    assert_eq!(ratio, 122, "SLH-DSA should be ~122x more expensive");
}

#[test]
fn test_slh_dsa_helper_weight_breakdown() {
    let desc_str = "tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    let (base, overhead, total) = SlhDsaHelper::weight_breakdown(&descriptor);
    
    // P2TR without SLH-DSA should have no overhead
    assert_eq!(overhead, 0, "No SLH-DSA overhead for regular P2TR");
    assert_eq!(total, base, "Total should equal base for non-SLH-DSA");
    assert!(base > 0, "Base weight should be greater than 0");
}

#[test]
fn test_slh_dsa_helper_count_keys() {
    // Regular descriptors should have 0 SLH-DSA keys
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    let count = SlhDsaHelper::count_slh_dsa_keys(&descriptor);
    assert_eq!(count, 0, "P2WPKH should have 0 SLH-DSA keys");
    
    // P2TR descriptor
    let desc_str = "tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    let count = SlhDsaHelper::count_slh_dsa_keys(&descriptor);
    assert_eq!(count, 0, "P2TR should have 0 SLH-DSA keys");
}

#[test]
fn test_slh_dsa_helper_estimate_fee() {
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    let fee_rate = Amount::from_sat(10);
    let fee = SlhDsaHelper::estimate_fee(&descriptor, fee_rate);
    
    // Should be reasonable fee for P2WPKH
    assert!(fee.to_sat() > 0, "Fee should be greater than 0");
    assert!(fee.to_sat() < 10_000, "Fee for P2WPKH should be less than 10,000 sats @ 10 sat/vB");
}

#[test]
fn test_balance_spendable_with_fee() {
    let balance = Balance {
        confirmed: Amount::from_sat(100_000),
        trusted_pending: Amount::from_sat(0),
        untrusted_pending: Amount::from_sat(0),
        immature: Amount::from_sat(0),
    };
    
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    let fee_rate = Amount::from_sat(10);
    let spendable = balance.spendable_with_fee(&descriptor, fee_rate);
    
    // Should be less than total due to fees
    assert!(spendable < balance.total(), "Spendable should be less than total");
    assert!(spendable > Amount::ZERO, "Should have some spendable balance");
    assert!(spendable.to_sat() > 90_000, "Should have most of balance spendable for P2WPKH");
}

#[test]
fn test_balance_is_economically_spendable() {
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    let fee_rate = Amount::from_sat(10);
    
    // Large balance - should be spendable
    let large_balance = Balance {
        confirmed: Amount::from_sat(100_000),
        ..Default::default()
    };
    assert!(
        large_balance.is_economically_spendable(&descriptor, fee_rate),
        "Large balance should be economically spendable"
    );
    
    // Very small balance - might not be spendable
    let tiny_balance = Balance {
        confirmed: Amount::from_sat(100),
        ..Default::default()
    };
    assert!(
        !tiny_balance.is_economically_spendable(&descriptor, fee_rate),
        "Tiny balance should not be economically spendable"
    );
}

#[test]
fn test_balance_fee_breakdown() {
    let balance = Balance {
        confirmed: Amount::from_sat(100_000),
        trusted_pending: Amount::from_sat(20_000),
        ..Default::default()
    };
    
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    let (total, fee, net) = balance.fee_breakdown(&descriptor, Amount::from_sat(10));
    
    assert_eq!(total, Amount::from_sat(120_000), "Total should be confirmed + trusted_pending");
    assert!(fee > Amount::ZERO, "Fee should be greater than 0");
    assert_eq!(total, fee + net, "Total should equal fee + net");
}

#[test]
fn test_keychain_txout_index_has_slh_dsa_descriptors() {
    let mut index = KeychainTxOutIndex::<String>::default();
    
    // Insert regular descriptor
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    index.insert_descriptor("external".to_string(), descriptor).unwrap();
    
    assert!(!index.has_slh_dsa_descriptors(), "Index should not have SLH-DSA descriptors");
}

#[test]
fn test_keychain_txout_index_multiple_descriptors() {
    let mut index = KeychainTxOutIndex::<String>::default();
    
    // Insert external descriptor
    let ext_desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let ext_descriptor = Descriptor::<DescriptorPublicKey>::from_str(ext_desc_str).unwrap();
    index.insert_descriptor("external".to_string(), ext_descriptor).unwrap();
    
    // Insert internal descriptor
    let int_desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/1/*)";
    let int_descriptor = Descriptor::<DescriptorPublicKey>::from_str(int_desc_str).unwrap();
    index.insert_descriptor("internal".to_string(), int_descriptor).unwrap();
    
    assert!(!index.has_slh_dsa_descriptors(), "Index should not have SLH-DSA descriptors");
}

#[test]
fn test_fee_estimation_high_fee_rate() {
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    // Test with high fee rate
    let high_fee_rate = Amount::from_sat(100); // 100 sat/vB
    let fee = SlhDsaHelper::estimate_fee(&descriptor, high_fee_rate);
    
    assert!(fee.to_sat() > 1000, "High fee rate should result in high fee");
}

#[test]
fn test_balance_with_zero_confirmed() {
    let balance = Balance {
        confirmed: Amount::ZERO,
        trusted_pending: Amount::from_sat(50_000),
        ..Default::default()
    };
    
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    let spendable = balance.spendable_with_fee(&descriptor, Amount::from_sat(10));
    
    // Should still have spendable from trusted_pending
    assert!(spendable > Amount::ZERO, "Should have spendable balance from trusted_pending");
}

#[test]
fn test_slh_dsa_comparison_multiple_signatures() {
    let fee_rate = Amount::from_sat(10);
    
    // Compare 1 vs 2 vs 5 signatures
    let (slh_1, schnorr_1, _) = SlhDsaHelper::fee_comparison(1, fee_rate);
    let (slh_2, schnorr_2, _) = SlhDsaHelper::fee_comparison(2, fee_rate);
    let (slh_5, schnorr_5, _) = SlhDsaHelper::fee_comparison(5, fee_rate);
    
    // Should scale linearly
    assert_eq!(slh_2.to_sat(), slh_1.to_sat() * 2, "2 sigs should cost 2x");
    assert_eq!(slh_5.to_sat(), slh_1.to_sat() * 5, "5 sigs should cost 5x");
    assert_eq!(schnorr_2.to_sat(), schnorr_1.to_sat() * 2, "2 Schnorr sigs should cost 2x");
    assert_eq!(schnorr_5.to_sat(), schnorr_1.to_sat() * 5, "5 Schnorr sigs should cost 5x");
}

#[test]
fn test_descriptor_dust_value() {
    let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
    
    let dust = descriptor.dust_value();
    assert!(dust > Amount::ZERO, "Dust value should be greater than 0");
    assert!(dust.to_sat() < 10_000, "Dust value should be reasonable");
}

#[test]
fn test_balance_operations() {
    let balance1 = Balance {
        confirmed: Amount::from_sat(100_000),
        trusted_pending: Amount::from_sat(20_000),
        untrusted_pending: Amount::from_sat(5_000),
        immature: Amount::from_sat(10_000),
    };
    
    let balance2 = Balance {
        confirmed: Amount::from_sat(50_000),
        trusted_pending: Amount::from_sat(10_000),
        untrusted_pending: Amount::from_sat(0),
        immature: Amount::from_sat(5_000),
    };
    
    let combined = balance1.clone() + balance2;
    
    assert_eq!(combined.confirmed, Amount::from_sat(150_000));
    assert_eq!(combined.trusted_pending, Amount::from_sat(30_000));
    assert_eq!(combined.untrusted_pending, Amount::from_sat(5_000));
    assert_eq!(combined.immature, Amount::from_sat(15_000));
    assert_eq!(combined.total(), Amount::from_sat(200_000));
}

#[test]
fn test_balance_display() {
    let balance = Balance {
        confirmed: Amount::from_sat(100_000),
        trusted_pending: Amount::from_sat(20_000),
        untrusted_pending: Amount::from_sat(5_000),
        immature: Amount::from_sat(10_000),
    };
    
    let display = format!("{}", balance);
    assert!(display.contains("100000"), "Display should contain confirmed amount");
    assert!(display.contains("20000"), "Display should contain trusted_pending amount");
    assert!(display.contains("5000"), "Display should contain untrusted_pending amount");
    assert!(display.contains("10000"), "Display should contain immature amount");
}
