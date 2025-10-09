# SLH-DSA Post-Quantum Cryptography Integration in BDK

## Overview

This document describes the integration of SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) post-quantum cryptography support into the Bitcoin Dev Kit (BDK), specifically focusing on the `bdk_chain` crate enhancements.

## Background

SLH-DSA is a post-quantum signature scheme standardized by NIST (FIPS 205) that provides quantum-resistant digital signatures. The upstream `rust-miniscript` library (version 13.0.0-pqc-0.1) provides support for SLH-DSA keys in P2TSH (Pay-to-Taproot-Script-Hash) descriptors.

### Key Characteristics

- **Algorithm**: SLH-DSA-128S (SPHINCS+ variant)
- **Public Key Size**: 32 bytes
- **Signature Size**: 7856 bytes (+ 1 byte sighash = 7857 bytes total)
- **Script Encoding**: `<32-byte-key> OP_SUCCESS127` (0x7f)
- **Descriptor Type**: P2TSH (Taproot Script Hash, witness version 2)

### Comparison with Traditional Signatures

| Type | Public Key | Signature Size | Quantum Resistant |
|------|-----------|----------------|-------------------|
| ECDSA | 33-65 bytes | ~73 bytes | ❌ No |
| Schnorr (Taproot) | 32 bytes | 64 bytes | ❌ No |
| **SLH-DSA** | **32 bytes** | **7856 bytes** | **✅ Yes** |

**Critical Implication**: SLH-DSA signatures are approximately **123x larger** than Schnorr signatures, significantly impacting transaction size and fees.

## BDK Chain Integration

The `bdk_chain` crate has been enhanced to support P2TSH descriptors with SLH-DSA locking scripts while properly accounting for their unique characteristics.

### Architecture

```
┌─────────────────────────────────────────────────┐
│           rust-miniscript v13.0.0-pqc-0.1       │
│  • SlhDsaPublicKey type                         │
│  • Terminal::SlhDsaPk                           │
│  • Descriptor::Tsh support                      │
│  • Satisfier::lookup_slh_dsa_sig()             │
│  • AssetProvider::provider_lookup_slh_dsa_sig() │
└─────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────┐
│                  bdk_chain                      │
│  • DescriptorExt enhancements                   │
│  • SlhDsaHelper for fee estimation              │
│  • Balance calculations with SLH-DSA overhead   │
│  • Indexing support for P2TSH descriptors       │
└─────────────────────────────────────────────────┘
```

### Changes to `bdk_chain`

#### 1. **Descriptor Extensions** (`src/descriptor_ext.rs`)

Enhanced the `DescriptorExt` trait with SLH-DSA-aware methods:

##### New Methods:

```rust
/// Returns estimated maximum satisfaction weight
fn max_satisfaction_weight(&self) -> Option<usize>;

/// Check if descriptor contains SLH-DSA keys
fn has_slh_dsa_keys(&self) -> bool;

/// Get estimated witness size for SLH-DSA signatures
fn slh_dsa_witness_weight(&self) -> Option<usize>;
```

**Usage Example**:
```rust
use bdk_chain::{DescriptorExt, miniscript::Descriptor};

let descriptor: Descriptor<DescriptorPublicKey> = // ... P2TSH with SLH-DSA
let dust = descriptor.dust_value();
let has_pq = descriptor.has_slh_dsa_keys(); // true for SLH-DSA descriptors
let weight = descriptor.slh_dsa_witness_weight(); // Some(7857 * 4) witness units
```

#### 2. **SLH-DSA Support Module** (`src/slh_dsa_support.rs`)

New module providing utilities for working with SLH-DSA descriptors:

##### Fee Estimation

```rust
use bdk_chain::slh_dsa_support::SlhDsaHelper;

// Estimate fee for P2TSH transaction with SLH-DSA signatures
let fee = SlhDsaHelper::estimate_fee(
    &descriptor,
    Amount::from_sat(10), // sat/vbyte
);

// Count SLH-DSA keys in descriptor
let count = SlhDsaHelper::count_slh_dsa_keys(&descriptor);
```

**Key Functions**:

- `estimate_fee()`: Calculate transaction fees accounting for large SLH-DSA signatures
- `count_slh_dsa_keys()`: Count SLH-DSA terminals in descriptor's taptree
- `create_spending_plan()`: Generate spending plan for P2TSH with SLH-DSA

##### Fee Calculation Details

For a P2TSH descriptor with N SLH-DSA keys:

```
Base Weight = descriptor.max_weight_to_satisfy()
SLH-DSA Overhead = N × 7857 × 4  (witness units)
Total Weight = Base Weight + SLH-DSA Overhead
Virtual Bytes = (Total Weight + 3) / 4
Fee = Virtual Bytes × fee_rate
```

**Example Comparison**:

| Descriptor Type | Est. Weight | Est. vBytes | Fee @ 10 sat/vB |
|----------------|-------------|-------------|-----------------|
| P2TR (Schnorr) | ~260 WU | ~65 vB | 650 sats |
| P2TSH (1× SLH-DSA) | ~31,700 WU | ~7,925 vB | 79,250 sats |
| P2TSH (2× SLH-DSA) | ~63,000 WU | ~15,750 vB | 157,500 sats |

#### 3. **Balance Calculations** (`src/balance.rs`)

Extended `Balance` type with SLH-DSA-aware methods:

```rust
impl Balance {
    /// Calculate spendable balance after SLH-DSA transaction fees
    pub fn spendable_with_slh_dsa_fee(
        &self,
        descriptor: &Descriptor<DescriptorPublicKey>,
        fee_rate: FeeRate,
    ) -> Amount;
}
```

**Why This Matters**: With SLH-DSA signatures being ~123× larger, a UTXO might appear spendable but become dust after accounting for fees.

**Example**:
```rust
let balance = Balance {
    confirmed: Amount::from_sat(100_000),
    // ...
};

// Regular balance
println!("Total: {} sats", balance.total().to_sat()); // 100,000 sats

// Spendable after SLH-DSA fees @ 10 sat/vB
let spendable = balance.spendable_with_slh_dsa_fee(&descriptor, fee_rate);
println!("Spendable: {} sats", spendable.to_sat()); // ~20,750 sats
```

#### 4. **Indexing Enhancements** (`src/indexer/keychain_txout.rs`)

Added P2TSH-specific indexing support:

```rust
impl<K: Ord + Clone> KeychainTxOutIndex<K> {
    /// Insert a P2TSH descriptor with SLH-DSA support
    pub fn insert_tsh_descriptor(
        &mut self,
        keychain: K,
        descriptor: Tsh<DescriptorPublicKey>,
    ) -> Result<ChangeSet, DescriptorError>;
    
    /// Check if any indexed descriptors contain SLH-DSA keys
    pub fn has_slh_dsa_descriptors(&self) -> bool;
}
```

**Note**: Standard `insert_descriptor()` already works with `Descriptor::Tsh`, but these helpers provide type-safe convenience.

## Usage Examples

### Creating a P2TSH Wallet with SLH-DSA

```rust
use bdk_chain::miniscript::{
    Descriptor, Miniscript, Tap,
    descriptor::{Tsh, TapTree, SlhDsaPublicKey, NoSecp256k1Key}
};
use bdk_chain::{KeychainTxOutIndex, IndexedTxGraph};
use bitcoin::Network;

// 1. Create a 32-byte SLH-DSA public key
let key_bytes: [u8; 32] = /* your SLH-DSA public key */;
let slh_dsa_key = SlhDsaPublicKey::from_bytes(key_bytes);

// 2. Create a miniscript with SLH-DSA terminal
// NoSecp256k1Key is a placeholder type that clearly indicates
// this miniscript contains only post-quantum keys, no secp256k1 keys
let ms: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(slh_dsa_key);

// 3. Create P2TSH descriptor
let tsh = Tsh::new(Some(TapTree::leaf(ms)))?;
let descriptor = Descriptor::Tsh(tsh);

// 4. Create wallet index
let mut index = KeychainTxOutIndex::<u32>::default();
index.insert_descriptor(0, descriptor.clone())?;

// 5. Generate addresses
for (idx, spk) in descriptor.spk_iter().take(5) {
    let address = bitcoin::Address::from_script(&spk, Network::Bitcoin)?;
    println!("Address {}: {}", idx, address);
}
```

**Note on `NoSecp256k1Key`**: This is a special type from miniscript v13.0.0-pqc-0.2+ that serves as a placeholder type parameter. It makes the code self-documenting by clearly indicating that the miniscript contains only post-quantum (SLH-DSA) keys and no traditional secp256k1 keys.

### Fee-Aware Balance Calculation

```rust
use bdk_chain::{Balance, DescriptorExt};
use bdk_chain::slh_dsa_support::SlhDsaHelper;

// Get wallet balance
let balance = indexed_graph.balance(
    &local_chain,
    local_chain.tip().block_id(),
    outpoints.iter().map(|(k, op)| (k, op)),
    |_, _| true,
);

println!("Total confirmed: {} sats", balance.confirmed.to_sat());

// Check if descriptor uses SLH-DSA
if descriptor.has_slh_dsa_keys() {
    let fee_rate = FeeRate::from_sat_per_vb(10);
    let spendable = balance.spendable_with_slh_dsa_fee(&descriptor, fee_rate);
    
    println!("Spendable (after SLH-DSA fees): {} sats", spendable.to_sat());
    println!("Fee overhead: {} sats", 
        (balance.confirmed - spendable).to_sat());
}
```

### Transaction Planning with SLH-DSA

```rust
use bdk_chain::miniscript::plan::{Assets, AssetProvider};
use bdk_chain::slh_dsa_support::SlhDsaHelper;

// Create assets for signing
let mut assets = Assets::new()
    .add(my_keys)
    .after(absolute_timelock);

// Create spending plan
let plan = SlhDsaHelper::create_spending_plan(&descriptor, &assets)?;

// Check witness size
let witness_size = plan.witness_size();
println!("Estimated witness size: {} bytes", witness_size);

// Estimate fees
let fee_rate = FeeRate::from_sat_per_vb(10);
let estimated_fee = SlhDsaHelper::estimate_fee(&descriptor, fee_rate.into());
println!("Estimated fee: {} sats", estimated_fee.to_sat());
```

### Multi-Leaf P2TSH with SLH-DSA

```rust
use bdk_chain::miniscript::{
    Miniscript, Tap, 
    descriptor::{SlhDsaPublicKey, NoSecp256k1Key, TapTree}
};
use bitcoin::key::XOnlyPublicKey;

// Create multiple spending paths
let slh_key = SlhDsaPublicKey::from_bytes([/* key 1 */]);
// Use NoSecp256k1Key for the SLH-DSA-only leaf
let slh_leaf: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(slh_key);

// Traditional Schnorr key as backup
let schnorr_key = XOnlyPublicKey::from_slice(&[/* key 2 */])?;
let schnorr_leaf: Miniscript<XOnlyPublicKey, Tap> = Miniscript::pk(schnorr_key);

// Note: When mixing leaf types with different Pk parameters,
// you'll need to handle the type conversion or use separate trees
// This example shows the concept - actual implementation may vary

// Wallet can spend using either path
// - Use SLH-DSA for long-term security
// - Use Schnorr for lower fees when quantum threat is not immediate
```

**Type System Note**: When creating hybrid taptrees with both SLH-DSA and traditional keys, you may need to work with separate trees or use type erasure techniques since `NoSecp256k1Key` and `XOnlyPublicKey` are different types.

## Testing

### Unit Tests

Tests are located in `crates/chain/tests/test_slh_dsa_integration.rs`:

```bash
# Run all SLH-DSA integration tests
cargo test --package bdk_chain --test test_slh_dsa_integration

# Run specific test
cargo test --package bdk_chain test_slh_dsa_fee_estimation
```

### Test Coverage:

- ✅ Descriptor creation and indexing
- ✅ Fee estimation accuracy
- ✅ Balance calculation with SLH-DSA overhead
- ✅ Script pubkey iteration
- ✅ Multi-leaf taptree support
- ✅ Witness weight calculations

### Example Test

```rust
#[test]
fn test_slh_dsa_fee_estimation() {
    let slh_key = SlhDsaPublicKey::from_bytes([0u8; 32]);
    let ms = Miniscript::slh_dsa_pk(slh_key);
    let descriptor = Descriptor::Tsh(Tsh::new(Some(TapTree::leaf(ms))).unwrap());
    
    let fee = SlhDsaHelper::estimate_fee(&descriptor, Amount::from_sat(10));
    
    // Should be significantly higher than regular Taproot
    assert!(fee.to_sat() > 50_000, "SLH-DSA fee should be high due to large signatures");
}
```

## Performance Considerations

### Transaction Size Impact

| Metric | P2TR (Schnorr) | P2TSH (SLH-DSA) | Ratio |
|--------|----------------|-----------------|-------|
| Signature Size | 64 bytes | 7,856 bytes | 123× |
| Witness Size | ~68 bytes | ~7,900 bytes | 116× |
| Transaction Weight | ~560 WU | ~31,700 WU | 57× |
| Virtual Size | ~140 vB | ~7,925 vB | 57× |

### Mempool and Block Space

**Block Space Usage**:
- 1 SLH-DSA input ≈ 56 Schnorr inputs (in terms of block space)
- With 4MB block weight limit: ~126 SLH-DSA transactions per block max
- Standard block (~4000 transactions): Only ~70 could be SLH-DSA

**Mempool Considerations**:
- SLH-DSA transactions require significantly higher fees to be competitive
- At same fee rate (sat/vB), SLH-DSA tx costs ~57× more in absolute sats
- Wallets should warn users about expected fee costs

### Optimization Strategies

1. **Batch Spending**: Consolidate multiple UTXOs in single transaction to amortize witness overhead
2. **Hybrid Descriptors**: Use SLH-DSA + Schnorr multi-path for flexibility
3. **UTXO Management**: Avoid creating small UTXOs that become dust with SLH-DSA fees
4. **Fee Estimation**: Always use `slh_dsa_witness_weight()` for accurate estimates

## Wallet Implementation Guidelines

### 1. UTXO Selection

Traditional coin selection algorithms need modification:

```rust
// ❌ BAD: Naive selection ignores SLH-DSA overhead
fn select_coins(utxos: &[Utxo], target: Amount) -> Vec<Utxo> {
    utxos.iter()
        .filter(|u| u.value > dust_limit) // Too simplistic!
        .take_while(|u| total < target)
        .collect()
}

// ✅ GOOD: Account for SLH-DSA spending cost
fn select_coins_slh_dsa(
    utxos: &[Utxo], 
    target: Amount,
    descriptor: &Descriptor<DescriptorPublicKey>,
    fee_rate: FeeRate
) -> Vec<Utxo> {
    let per_input_fee = SlhDsaHelper::estimate_fee(descriptor, fee_rate.into());
    
    utxos.iter()
        .filter(|u| u.value > per_input_fee) // Economically spendable
        .filter(|u| u.value > dust_limit)
        .take_while(|u| total < target + total_fees)
        .collect()
}
```

### 2. User Notifications

Wallets should inform users about SLH-DSA implications:

```rust
if descriptor.has_slh_dsa_keys() {
    println!("⚠️  Post-Quantum Security Enabled");
    println!("📊 Transaction fees will be significantly higher");
    println!("💰 Estimated fee: {} sats ({} BTC)", 
        estimated_fee.to_sat(),
        estimated_fee.to_btc());
    println!("🔐 Quantum-resistant signatures: ~7.9 KB per input");
}
```

### 3. Fee Estimation UI

```rust
struct FeeEstimate {
    regular: Amount,      // If using Schnorr
    slh_dsa: Amount,      // If using SLH-DSA
    multiplier: f64,      // slh_dsa / regular
}

fn estimate_tx_fee(
    descriptor: &Descriptor<DescriptorPublicKey>,
    num_inputs: usize,
    num_outputs: usize,
    fee_rate: FeeRate,
) -> FeeEstimate {
    // Calculate both scenarios
    let has_slh = descriptor.has_slh_dsa_keys();
    
    let regular = if has_slh {
        // Hypothetical Schnorr fee
        calculate_schnorr_fee(num_inputs, num_outputs, fee_rate)
    } else {
        calculate_actual_fee(descriptor, fee_rate)
    };
    
    let slh_dsa = if has_slh {
        SlhDsaHelper::estimate_fee(descriptor, fee_rate.into())
    } else {
        Amount::ZERO
    };
    
    FeeEstimate {
        regular,
        slh_dsa,
        multiplier: if regular.to_sat() > 0 {
            slh_dsa.to_sat() as f64 / regular.to_sat() as f64
        } else {
            0.0
        },
    }
}
```

## Known Limitations

### 1. Satisfaction Logic

The `rust-miniscript` library provides satisfaction planning, but actual signature generation requires:
- SLH-DSA private key management
- `Satisfier::lookup_slh_dsa_sig()` implementation
- Witness construction with 7856-byte signatures

Currently, `bdk_chain` provides infrastructure but relies on external signing:

```rust
// AssetProvider must be implemented to provide SLH-DSA signatures
struct MySlhDsaSigner {
    slh_keys: HashMap<SlhDsaPublicKey, SlhDsaPrivateKey>,
}

impl AssetProvider<DescriptorPublicKey> for MySlhDsaSigner {
    fn provider_lookup_slh_dsa_sig(&self, pk: &SlhDsaPublicKey) -> Option<usize> {
        if self.slh_keys.contains_key(pk) {
            Some(7857) // sig size + sighash byte
        } else {
            None
        }
    }
}
```

### 2. PSBT Support

PSBT (Partially Signed Bitcoin Transactions) support for SLH-DSA is currently limited:
- No standard field for SLH-DSA signatures in BIP-174
- Requires custom PSBT extensions or proprietary fields
- Multi-party signing workflows need careful coordination

### 3. Network Support

SLH-DSA P2TSH requires:
- Modified Bitcoin Core with PQC support
- Network consensus for OP_SUCCESS127 semantics
- Currently only available on custom/test networks

## Migration Path

### From P2TR to P2TSH + SLH-DSA

For existing wallets upgrading to post-quantum security:

```rust
// Old P2TR descriptor
let old_desc = Descriptor::<DescriptorPublicKey>::from_str(
    "tr([fingerprint/86'/0'/0']xpub.../0/*)"
)?;

// New P2TSH descriptor with SLH-DSA
// Keep same derivation path for compatibility
let slh_key = derive_slh_dsa_key(/* from same seed */);
let ms = Miniscript::slh_dsa_pk(slh_key);
let new_desc = Descriptor::Tsh(Tsh::new(Some(TapTree::leaf(ms)))?);

// Maintain both in wallet
wallet.add_descriptor("legacy_tr", old_desc)?;
wallet.add_descriptor("pq_secure", new_desc)?;

// Gradual migration: sweep funds from P2TR to P2TSH over time
```

### Hybrid Approach

For maximum flexibility:

```rust
// Create descriptor with both SLH-DSA and Schnorr paths
let slh_path = TapTree::leaf(Miniscript::slh_dsa_pk(slh_key));
let schnorr_path = TapTree::leaf(Miniscript::pk(schnorr_key));

let hybrid_tree = TapTree::branch(slh_path, schnorr_path)?;
let hybrid_desc = Descriptor::Tsh(Tsh::new(Some(hybrid_tree))?);

// Spending logic:
// - Pre-quantum-computer era: use Schnorr path (lower fees)
// - Post-quantum-computer era: use SLH-DSA path (secure)
```

## Security Considerations

### Quantum Resistance

- ✅ **SLH-DSA**: Quantum-resistant (security based on hash functions)
- ❌ **Schnorr/ECDSA**: Vulnerable to Shor's algorithm on quantum computers
- ✅ **P2TSH Script Hash**: Quantum-resistant (hash-based)

### Key Management

SLH-DSA keys have different properties:
- **Stateless**: No need to track signature count (unlike XMSS/LMS)
- **Deterministic**: Same message + key → same signature (unless randomized)
- **Large Private Keys**: SLH-DSA-128S private key is 64 bytes

**Best Practices**:
```rust
// ✅ Generate SLH-DSA keys from secure entropy
let entropy: [u8; 32] = secure_random_bytes();
let slh_key = derive_slh_dsa_key(&entropy);

// ❌ Don't reuse SLH-DSA keys across different contexts
// ✅ Use hierarchical derivation like BIP-32 (if available)

// ✅ Store private keys encrypted
let encrypted = encrypt_key(&slh_private_key, &user_password);
```

## API Reference

### Core Types

```rust
// From rust-miniscript
pub struct SlhDsaPublicKey([u8; 32]);
pub enum Descriptor<Pk> {
    // ... other variants
    Tsh(Tsh<Pk>),
}

// From bdk_chain
pub trait DescriptorExt {
    fn dust_value(&self) -> Amount;
    fn descriptor_id(&self) -> DescriptorId;
    fn max_satisfaction_weight(&self) -> Option<usize>;
    fn has_slh_dsa_keys(&self) -> bool;
    fn slh_dsa_witness_weight(&self) -> Option<usize>;
}

pub struct SlhDsaHelper;
impl SlhDsaHelper {
    pub fn estimate_fee(
        descriptor: &Descriptor<DescriptorPublicKey>,
        sat_per_vbyte: Amount,
    ) -> Amount;
    
    pub fn count_slh_dsa_keys(
        descriptor: &Descriptor<DescriptorPublicKey>
    ) -> usize;
    
    pub fn create_spending_plan(
        descriptor: &Descriptor<DescriptorPublicKey>,
        assets: &Assets,
    ) -> Result<Plan, Error>;
}
```

### Module Locations

- **Descriptor Extensions**: `bdk_chain::descriptor_ext`
- **SLH-DSA Helpers**: `bdk_chain::slh_dsa_support`
- **Balance**: `bdk_chain::balance`
- **Indexing**: `bdk_chain::indexer::keychain_txout`

## Future Work

### Planned Enhancements

1. **PSBT Extensions**: Define BDK-specific PSBT fields for SLH-DSA signatures
2. **Hardware Wallet Support**: Protocol for SLH-DSA signing on hardware devices
3. **Batch Verification**: Optimize verification of multiple SLH-DSA signatures
4. **Signature Aggregation**: Research possibilities for SLH-DSA signature aggregation
5. **Alternative PQC Schemes**: Support for other post-quantum algorithms (Dilithium, Falcon)

### Research Areas

- **Fee Optimization**: Strategies to minimize SLH-DSA transaction costs
- **UTXO Management**: Best practices for post-quantum UTXO consolidation
- **Cross-Chain**: Interoperability with other PQC-enabled blockchains
- **Privacy**: Implications of large signatures on transaction privacy

## References

### Standards & Specifications

- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/ipd): Stateless Hash-Based Digital Signature Standard (SLH-DSA)
- [BIP-342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki): Validation of Taproot Scripts
- [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki): Taproot: SegWit version 1 spending rules

### Libraries

- [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript): Version 13.0.0-pqc-0.1
- [bitcoinpqc](https://crates.io/crates/bitcoinpqc): SLH-DSA implementation
- [bdk_chain](../crates/chain/): Bitcoin Dev Kit chain structures

### Related Documentation

- [rust-miniscript SLH-DSA Integration](../rust-miniscript/SLH_DSA_INTEGRATION.md)
- [BDK Architecture](https://bitcoindevkit.org/architecture/)
- [Miniscript Policy](https://bitcoin.sipa.be/miniscript/)

## Changelog

### Version 0.23.2-pqc-0.1 (Current)

- ✅ Updated to miniscript 13.0.0-pqc-0.2 (adds `NoSecp256k1Key` support)
- ✅ Added `DescriptorExt` enhancements for SLH-DSA awareness
- ✅ Implemented `SlhDsaHelper` for fee estimation and planning
- ✅ Extended `Balance` with SLH-DSA fee calculations
- ✅ Added P2TSH indexing support
- ✅ Created comprehensive test suite
- ✅ Added documentation and examples (including `example_p2tsh_slh_dsa`)
- ✅ Full support for `NoSecp256k1Key` type parameter for post-quantum-only miniscripts

### Future Versions

- 🔄 PSBT extensions for SLH-DSA
- 🔄 Hardware wallet integration
- 🔄 Advanced coin selection for PQC
- 🔄 Multi-signature SLH-DSA support

---

**Questions or Issues?** Please file an issue on the [BDK GitHub repository](https://github.com/bitcoindevkit/bdk/issues).


