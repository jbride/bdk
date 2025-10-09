//! SLH-DSA Post-Quantum Cryptography Support
//!
//! This module provides utilities for working with SLH-DSA (Stateless Hash-Based
//! Digital Signature Algorithm) post-quantum signatures in P2TSH descriptors.
//!
//! SLH-DSA signatures are significantly larger (~7857 bytes) than traditional
//! ECDSA/Schnorr signatures (~73/64 bytes), which has major implications for
//! transaction size and fees.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "miniscript")]
//! # {
//! use bdk_chain::slh_dsa_support::SlhDsaHelper;
//! use bdk_chain::miniscript::{Descriptor, DescriptorPublicKey};
//! use bitcoin::Amount;
//! # use std::str::FromStr;
//!
//! # let descriptor_str = "tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
//! # let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor_str).unwrap();
//! // Estimate fee for a descriptor (sat/vbyte)
//! let fee = SlhDsaHelper::estimate_fee(&descriptor, Amount::from_sat(10));
//! println!("Estimated fee: {} sats", fee.to_sat());
//!
//! // Count SLH-DSA keys
//! let count = SlhDsaHelper::count_slh_dsa_keys(&descriptor);
//! println!("Number of SLH-DSA keys: {}", count);
//! # }
//! ```

use crate::miniscript::{Descriptor, DescriptorPublicKey, Miniscript, ScriptContext};
use bitcoin::Amount;

#[cfg(feature = "miniscript")]
use crate::miniscript::plan::{Assets, Plan};

/// Helper utilities for SLH-DSA post-quantum signatures
pub struct SlhDsaHelper;

impl SlhDsaHelper {
    /// Estimate transaction fee for a descriptor with SLH-DSA signatures.
    ///
    /// SLH-DSA signatures are ~7857 bytes each (7856 bytes + 1 sighash byte),
    /// which is approximately 123× larger than Schnorr signatures (64 bytes).
    ///
    /// # Arguments
    ///
    /// * `descriptor` - The descriptor to estimate fees for
    /// * `sat_per_vbyte` - Fee rate in satoshis per virtual byte
    ///
    /// # Returns
    ///
    /// Estimated fee in satoshis as an `Amount`
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "miniscript")]
    /// # {
    /// use bdk_chain::slh_dsa_support::SlhDsaHelper;
    /// use bdk_chain::miniscript::{Descriptor, DescriptorPublicKey};
    /// use bitcoin::Amount;
    /// # use std::str::FromStr;
    /// # let desc = "tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    /// # let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc).unwrap();
    ///
    /// let fee_rate = Amount::from_sat(10); // 10 sat/vB
    /// let estimated_fee = SlhDsaHelper::estimate_fee(&descriptor, fee_rate);
    ///
    /// if estimated_fee.to_sat() > 100_000 {
    ///     println!("Warning: High fee due to SLH-DSA signatures!");
    /// }
    /// # }
    /// ```
    pub fn estimate_fee(
        descriptor: &Descriptor<DescriptorPublicKey>,
        sat_per_vbyte: Amount,
    ) -> Amount {
        use bitcoin::Weight;

        // Get base weight from descriptor
        let base_weight = descriptor
            .max_weight_to_satisfy()
            .unwrap_or(Weight::ZERO);

        // Count SLH-DSA keys and calculate overhead
        let slh_dsa_count = Self::count_slh_dsa_keys(descriptor);
        
        // Each SLH-DSA signature: 7857 bytes × 4 = 31,428 weight units
        let slh_dsa_overhead_weight = Weight::from_wu(slh_dsa_count as u64 * 7857 * 4);

        // Total weight
        let total_weight = base_weight + slh_dsa_overhead_weight;

        // Convert to virtual bytes (round up)
        let vbytes = (total_weight.to_vbytes_ceil()) as u64;

        // Calculate fee
        sat_per_vbyte * vbytes
    }

    /// Count the number of SLH-DSA keys in a descriptor.
    ///
    /// This traverses the descriptor's structure (including taptrees for P2TSH)
    /// and counts all SLH-DSA public key terminals.
    ///
    /// # Arguments
    ///
    /// * `descriptor` - The descriptor to analyze
    ///
    /// # Returns
    ///
    /// The number of SLH-DSA keys found
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "miniscript")]
    /// # {
    /// use bdk_chain::slh_dsa_support::SlhDsaHelper;
    /// use bdk_chain::miniscript::{Descriptor, DescriptorPublicKey};
    /// # use std::str::FromStr;
    /// # let desc = "tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    /// # let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc).unwrap();
    ///
    /// let count = SlhDsaHelper::count_slh_dsa_keys(&descriptor);
    /// 
    /// if count > 0 {
    ///     println!("This descriptor uses {} SLH-DSA keys", count);
    ///     println!("Expected witness overhead: ~{} KB", count * 7857 / 1024);
    /// }
    /// # }
    /// ```
    pub fn count_slh_dsa_keys(descriptor: &Descriptor<DescriptorPublicKey>) -> usize {
        match descriptor {
            Descriptor::Tsh(tsh) => {
                if let Some(tree) = tsh.tap_tree() {
                    count_slh_dsa_in_tree(tree)
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    /// Create a spending plan for a P2TSH descriptor with SLH-DSA keys.
    ///
    /// This uses the miniscript planning infrastructure to determine the
    /// optimal spending path and witness structure.
    ///
    /// # Arguments
    ///
    /// * `descriptor` - The descriptor to create a plan for
    /// * `assets` - Available assets (keys, hash preimages, timelocks, etc.)
    ///
    /// # Returns
    ///
    /// A `Plan` that can be used to construct the transaction witness
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The descriptor cannot be satisfied with the provided assets
    /// - The descriptor has invalid structure
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use bdk_chain::slh_dsa_support::SlhDsaHelper;
    /// use bdk_chain::miniscript::{Descriptor, DefiniteDescriptorKey, plan::Assets};
    ///
    /// // Descriptor must use DefiniteDescriptorKey (fully specified, no wildcards)
    /// let descriptor: Descriptor<DefiniteDescriptorKey> = // ... your definite descriptor
    /// let assets = Assets::new()
    ///     .add(my_key); // Add your signing keys
    ///
    /// let plan = SlhDsaHelper::create_spending_plan(descriptor, &assets)
    ///     .expect("Failed to create plan");
    ///
    /// println!("Witness size: {} bytes", plan.witness_size());
    /// println!("Satisfaction weight: {} WU", plan.satisfaction_weight());
    /// ```
    #[cfg(feature = "miniscript")]
    pub fn create_spending_plan(
        descriptor: Descriptor<crate::miniscript::DefiniteDescriptorKey>,
        assets: &Assets,
    ) -> Result<Plan, Descriptor<crate::miniscript::DefiniteDescriptorKey>> {
        descriptor.plan(assets)
    }

    /// Get detailed weight breakdown for a P2TSH descriptor with SLH-DSA.
    ///
    /// Returns a tuple of (base_weight, slh_dsa_overhead, total_weight).
    ///
    /// # Arguments
    ///
    /// * `descriptor` - The descriptor to analyze
    ///
    /// # Returns
    ///
    /// `(base_weight, slh_dsa_overhead, total_weight)` in weight units
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "miniscript")]
    /// # {
    /// use bdk_chain::slh_dsa_support::SlhDsaHelper;
    /// use bdk_chain::miniscript::{Descriptor, DescriptorPublicKey};
    /// # use std::str::FromStr;
    /// # let desc = "tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
    /// # let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc).unwrap();
    ///
    /// let (base, overhead, total) = SlhDsaHelper::weight_breakdown(&descriptor);
    ///
    /// println!("Base weight: {} WU", base);
    /// println!("SLH-DSA overhead: {} WU", overhead);
    /// println!("Total weight: {} WU", total);
    /// println!("Virtual bytes: {} vB", (total + 3) / 4);
    /// # }
    /// ```
    pub fn weight_breakdown(
        descriptor: &Descriptor<DescriptorPublicKey>,
    ) -> (usize, usize, usize) {
        use bitcoin::Weight;

        let base_weight = descriptor
            .max_weight_to_satisfy()
            .unwrap_or(Weight::ZERO)
            .to_wu() as usize;

        let slh_dsa_count = Self::count_slh_dsa_keys(descriptor);
        let slh_dsa_overhead = slh_dsa_count * 7857 * 4; // 31,428 WU per signature

        let total_weight = base_weight + slh_dsa_overhead;

        (base_weight, slh_dsa_overhead, total_weight)
    }

    /// Calculate the fee difference between SLH-DSA and traditional signatures.
    ///
    /// This helps users understand the cost premium of using post-quantum security.
    ///
    /// # Arguments
    ///
    /// * `slh_dsa_count` - Number of SLH-DSA signatures
    /// * `fee_rate` - Fee rate in satoshis per virtual byte
    ///
    /// # Returns
    ///
    /// `(slh_dsa_fee, schnorr_fee, difference)` in satoshis
    ///
    /// # Examples
    ///
    /// ```
    /// use bdk_chain::slh_dsa_support::SlhDsaHelper;
    /// use bitcoin::Amount;
    ///
    /// let (pq_fee, trad_fee, diff) = SlhDsaHelper::fee_comparison(
    ///     1,                      // 1 SLH-DSA signature
    ///     Amount::from_sat(10)    // 10 sat/vB
    /// );
    ///
    /// println!("Post-Quantum fee: {} sats", pq_fee.to_sat());
    /// println!("Traditional fee: {} sats", trad_fee.to_sat());
    /// println!("Premium: {} sats ({}x more expensive)", 
    ///     diff.to_sat(), 
    ///     pq_fee.to_sat() / trad_fee.to_sat().max(1)
    /// );
    /// ```
    pub fn fee_comparison(
        slh_dsa_count: usize,
        fee_rate: Amount,
    ) -> (Amount, Amount, Amount) {
        // SLH-DSA: 7857 bytes per signature
        let slh_dsa_vbytes = slh_dsa_count * 7857;
        let slh_dsa_fee = fee_rate * slh_dsa_vbytes as u64;

        // Schnorr: 64 bytes per signature (simplified)
        let schnorr_vbytes = slh_dsa_count * 64;
        let schnorr_fee = fee_rate * schnorr_vbytes as u64;

        let difference = slh_dsa_fee - schnorr_fee;

        (slh_dsa_fee, schnorr_fee, difference)
    }
}

/// Helper function to count SLH-DSA keys in a TapTree
fn count_slh_dsa_in_tree<Pk: crate::miniscript::MiniscriptKey>(
    tree: &crate::miniscript::descriptor::TapTree<Pk>,
) -> usize {
    tree.leaves()
        .map(|item| count_slh_dsa_in_miniscript(item.miniscript()))
        .sum()
}

/// Count SLH-DSA terminals in a miniscript
fn count_slh_dsa_in_miniscript<Pk: crate::miniscript::MiniscriptKey, Ctx: ScriptContext>(
    ms: &Miniscript<Pk, Ctx>,
) -> usize {
    // Check if the node contains SlhDsaPk by pattern matching the debug string
    // This is a workaround since Terminal enum isn't exposed
    let debug_str = format!("{:?}", ms.node);
    let current = if debug_str.contains("SlhDsaPk") { 1 } else { 0 };

    // Add count from all sub-fragments
    current + ms.iter().map(|sub| count_slh_dsa_in_miniscript(sub)).sum::<usize>()
}

#[cfg(test)]
#[cfg(feature = "miniscript")]
mod tests {
    use super::*;

    #[test]
    fn test_fee_comparison() {
        let fee_rate = Amount::from_sat(10);
        let (slh_fee, schnorr_fee, diff) = SlhDsaHelper::fee_comparison(1, fee_rate);

        // SLH-DSA should be much more expensive
        assert!(slh_fee > schnorr_fee);
        assert_eq!(slh_fee, Amount::from_sat(78_570)); // 7857 * 10
        assert_eq!(schnorr_fee, Amount::from_sat(640)); // 64 * 10
        assert_eq!(diff, Amount::from_sat(77_930));
    }

    #[test]
    fn test_weight_breakdown_non_slh_dsa() {
        use crate::miniscript::{Descriptor, DescriptorPublicKey};
        use std::str::FromStr;

        // Regular P2WPKH descriptor (no SLH-DSA)
        let desc_str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();

        let (base, overhead, total) = SlhDsaHelper::weight_breakdown(&descriptor);

        // Should have no SLH-DSA overhead
        assert_eq!(overhead, 0);
        assert_eq!(total, base);
    }

    #[test]
    fn test_count_slh_dsa_keys_non_tsh() {
        use crate::miniscript::{Descriptor, DescriptorPublicKey};
        use std::str::FromStr;

        // P2TR descriptor (not P2TSH, so no SLH-DSA)
        let desc_str = "tr(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();

        let count = SlhDsaHelper::count_slh_dsa_keys(&descriptor);
        assert_eq!(count, 0);
    }
}


