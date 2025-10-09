# Miniscript 13.0.0-pqc-0.2 Update - NoSecp256k1Key Support

## Overview

Updated BDK to support miniscript v13.0.0-pqc-0.2, which introduces the `NoSecp256k1Key` type for clearer post-quantum-only miniscripts.

## What Changed

### 1. **Dependency Update**

**File**: `crates/chain/Cargo.toml`
- ✅ Already at version `13.0.0-pqc-0.2`

### 2. **New Example: `example_p2tsh_slh_dsa`**

**Files Created**:
- `examples/p2tsh_slh_dsa/Cargo.toml`
- `examples/p2tsh_slh_dsa/src/main.rs`
- `examples/p2tsh_slh_dsa/README.md`

**What It Demonstrates**:
- Using `NoSecp256k1Key` type parameter with `Miniscript::slh_dsa_pk()`
- Creating P2TSH descriptors with SLH-DSA keys
- Comprehensive fee estimation and impact analysis
- Real-world economic considerations

**Key Code Pattern**:
```rust
use miniscript::descriptor::NoSecp256k1Key;

// NoSecp256k1Key clearly indicates post-quantum-only miniscript
let ms: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(slh_dsa_key);
```

### 3. **Documentation Updates**

**File**: `docs/SLH_DSA_INTEGRATION.md`

**Updates Made**:
- ✅ Added `NoSecp256k1Key` to usage examples
- ✅ Explained the purpose of `NoSecp256k1Key` placeholder type
- ✅ Updated multi-leaf example with type system notes
- ✅ Updated changelog to v0.23.2-pqc-0.1
- ✅ Added reference to new example

**Key Addition**:
> **Note on `NoSecp256k1Key`**: This is a special type from miniscript v13.0.0-pqc-0.2+ that serves as a placeholder type parameter. It makes the code self-documenting by clearly indicating that the miniscript contains only post-quantum (SLH-DSA) keys and no traditional secp256k1 keys.

### 4. **No Code Changes Required**

The existing `bdk_chain` implementation is **fully compatible** with the new miniscript version because:

1. **Generic Implementation**: Our helper functions work with `Descriptor<DescriptorPublicKey>`, not specific Pk types
2. **Runtime Detection**: We use debug string matching to detect SLH-DSA terminals, which works regardless of the Pk type parameter
3. **Type Agnostic**: Fee estimation and balance calculations don't depend on the Pk type

## Benefits of NoSecp256k1Key

### 1. **Self-Documenting Code**
```rust
// Before: Ambiguous - could this have secp256k1 keys?
let ms: Miniscript<XOnlyPublicKey, Tap> = Miniscript::slh_dsa_pk(key);

// After: Clear - this is post-quantum only
let ms: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(key);
```

### 2. **Type Safety**
```rust
// Prevents accidental mixing in some contexts
let slh_ms: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(key);
let schnorr_ms: Miniscript<XOnlyPublicKey, Tap> = Miniscript::pk(xonly_key);

// Type system can help catch errors when combining these
```

### 3. **Intent Clarity**
- Makes it immediately obvious that the miniscript is designed for post-quantum security
- Helps reviewers understand the code's purpose
- Documents the quantum-resistance requirement

## Running the New Example

```bash
cd /u01/blockchain/bitcoin/rust/bitcoindevkit/bdk

# Run the new example
cargo run --package example_p2tsh_slh_dsa
```

**Expected Output**:
```
🔐 P2TSH with SLH-DSA Post-Quantum Example
============================================

📝 SLH-DSA Public Key:
  Key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  Size: 32 bytes

🔧 Miniscript:
  Fragment: slh_dsa_pk(...)
  Type: Miniscript<NoSecp256k1Key, Tap>
  Note: NoSecp256k1Key indicates no secp256k1 keys, only SLH-DSA

...

📊 Fee Comparison (1 input @ 10 sat/vB):
  SLH-DSA (Post-Quantum):    78,570 sats
  Schnorr (Traditional):        640 sats
  Difference:                77,930 sats
  Multiplier:                  122.8x more expensive

✨ Example completed successfully!
```

## Compatibility

### ✅ **Backward Compatible**
- All existing code continues to work
- No breaking changes in `bdk_chain` API
- Fee estimation works with both old and new patterns

### ✅ **Forward Compatible**
- Ready for future miniscript versions
- Generic implementations don't depend on specific Pk types

## Testing

### Existing Tests
All existing tests in `crates/chain/tests/test_slh_dsa_integration.rs` pass without modification because they work at the `Descriptor` level, not the specific Miniscript Pk type.

### New Example as Test
The new example serves as:
- Integration test for NoSecp256k1Key usage
- Documentation of best practices
- Real-world usage demonstration

## Best Practices

### When to Use NoSecp256k1Key

✅ **Use NoSecp256k1Key when**:
- Creating SLH-DSA-only miniscripts
- You want to make post-quantum intent explicit
- Building pure post-quantum wallets

❌ **Don't use NoSecp256k1Key when**:
- Creating hybrid miniscripts with both SLH-DSA and secp256k1 keys
- Working with traditional keys only
- You need actual secp256k1 key functionality

### Recommended Pattern

```rust
use miniscript::{Miniscript, Tap};
use miniscript::descriptor::{Tsh, TapTree, SlhDsaPublicKey, NoSecp256k1Key};

// Step 1: Create SLH-DSA key
let slh_key = SlhDsaPublicKey::from_bytes(key_bytes);

// Step 2: Create miniscript with NoSecp256k1Key
let ms: Miniscript<NoSecp256k1Key, Tap> = Miniscript::slh_dsa_pk(slh_key);

// Step 3: Create descriptor
let tsh = Tsh::new(Some(TapTree::leaf(ms)))?;
let descriptor = Descriptor::Tsh(tsh);

// Step 4: Use with bdk_chain utilities
use bdk_chain::{DescriptorExt, SlhDsaHelper};

assert!(descriptor.has_slh_dsa_keys());
let fee = SlhDsaHelper::estimate_fee(&descriptor, fee_rate);
```

## Summary

| Item | Status | Notes |
|------|--------|-------|
| Miniscript version | ✅ v13.0.0-pqc-0.2 | Already updated |
| bdk_chain compatibility | ✅ No changes needed | Works as-is |
| New example | ✅ Created | `example_p2tsh_slh_dsa` |
| Documentation | ✅ Updated | Added NoSecp256k1Key notes |
| Tests | ✅ Passing | All existing tests pass |
| Examples | ✅ Working | New example runs successfully |

## Next Steps

1. ✅ **Complete** - All changes implemented
2. 📖 **Optional** - Users can review `example_p2tsh_slh_dsa` for best practices
3. 🔄 **Future** - Monitor for miniscript updates beyond v13.0.0-pqc-0.2

---

**Date**: 2025-10-09  
**Miniscript Version**: 13.0.0-pqc-0.2  
**BDK Chain Version**: 0.23.2-pqc-0.1

