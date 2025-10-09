use crate::miniscript::{Descriptor, DescriptorPublicKey, Miniscript, ScriptContext};
use bitcoin::hashes::{hash_newtype, sha256, Hash};
use bitcoin::Amount;

hash_newtype! {
    /// Represents the unique ID of a descriptor.
    ///
    /// This is useful for having a fixed-length unique representation of a descriptor,
    /// in particular, we use it to persist application state changes related to the
    /// descriptor without having to re-write the whole descriptor each time.
    ///
    pub struct DescriptorId(pub sha256::Hash);
}

/// A trait to extend the functionality of a miniscript descriptor.
pub trait DescriptorExt {
    /// Returns the minimum [`Amount`] at which an output is broadcast-able.
    /// Panics if the descriptor wildcard is hardened.
    fn dust_value(&self) -> Amount;

    /// Returns the descriptor ID, calculated as the sha256 hash of the spk derived from the
    /// descriptor at index 0.
    fn descriptor_id(&self) -> DescriptorId;

    /// Returns the estimated maximum satisfaction weight in weight units.
    ///
    /// This accounts for SLH-DSA signatures which are much larger (~7857 bytes)
    /// than traditional ECDSA/Schnorr signatures.
    fn max_satisfaction_weight(&self) -> Option<usize>;

    /// Check if descriptor contains SLH-DSA post-quantum keys.
    ///
    /// SLH-DSA keys have significant impact on transaction size and fees,
    /// so wallets should handle them specially.
    fn has_slh_dsa_keys(&self) -> bool;

    /// Get estimated witness weight for SLH-DSA signatures in weight units.
    ///
    /// Returns `Some(weight)` if the descriptor contains SLH-DSA keys,
    /// `None` otherwise.
    fn slh_dsa_witness_weight(&self) -> Option<usize>;
}

impl DescriptorExt for Descriptor<DescriptorPublicKey> {
    fn dust_value(&self) -> Amount {
        self.at_derivation_index(0)
            .expect("descriptor can't have hardened derivation")
            .script_pubkey()
            .minimal_non_dust()
    }

    fn descriptor_id(&self) -> DescriptorId {
        let spk = self.at_derivation_index(0).unwrap().script_pubkey();
        DescriptorId(sha256::Hash::hash(spk.as_bytes()))
    }

    fn max_satisfaction_weight(&self) -> Option<usize> {
        self.max_weight_to_satisfy().ok().map(|w| w.to_wu() as usize)
    }

    fn has_slh_dsa_keys(&self) -> bool {
        match self {
            Descriptor::Tsh(tsh) => {
                // Check if the taptree contains any SLH-DSA keys
                if let Some(tree) = tsh.tap_tree() {
                    has_slh_dsa_in_tree(tree)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn slh_dsa_witness_weight(&self) -> Option<usize> {
        if !self.has_slh_dsa_keys() {
            return None;
        }

        match self {
            Descriptor::Tsh(tsh) => {
                if let Some(tree) = tsh.tap_tree() {
                    let count = count_slh_dsa_in_tree(tree);
                    if count > 0 {
                        // Each SLH-DSA signature is 7856 bytes + 1 sighash byte = 7857 bytes
                        // In weight units: 7857 * 4 = 31,428 WU per signature
                        Some(count * 7857 * 4)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Helper function to check if a TapTree contains SLH-DSA keys
fn has_slh_dsa_in_tree<Pk: crate::miniscript::MiniscriptKey>(
    tree: &crate::miniscript::descriptor::TapTree<Pk>,
) -> bool {
    tree.leaves().any(|item| has_slh_dsa_in_miniscript(item.miniscript()))
}

/// Helper function to count SLH-DSA keys in a TapTree
fn count_slh_dsa_in_tree<Pk: crate::miniscript::MiniscriptKey>(
    tree: &crate::miniscript::descriptor::TapTree<Pk>,
) -> usize {
    tree.leaves()
        .map(|item| count_slh_dsa_in_miniscript(item.miniscript()))
        .sum()
}

/// Check if a miniscript contains SLH-DSA terminals
fn has_slh_dsa_in_miniscript<Pk: crate::miniscript::MiniscriptKey, Ctx: ScriptContext>(
    ms: &Miniscript<Pk, Ctx>,
) -> bool {
    // Check if the node contains SlhDsaPk by pattern matching the debug string
    // This is a workaround since Terminal enum isn't exposed
    let debug_str = format!("{:?}", ms.node);
    if debug_str.contains("SlhDsaPk") {
        return true;
    }
    
    // Recursively check all sub-fragments
    ms.iter().any(|sub| has_slh_dsa_in_miniscript(sub))
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
