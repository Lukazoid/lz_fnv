//! The lz_fnv crate implements Fowler-Noll-Vo hashing.
//!
//! FNV-0, FNV-1 and FNV-1a hash implementations are supported for various
//! width integers.
//!
//! The FNV implementations for u64 also implement `Hasher`.
#![deny(missing_docs)]

/// A trait for all Fowler-Noll-Vo hash implementations.
///
/// This matches the `std::hash::Hasher` definition but for multiple hash
/// types.
pub trait FnvHasher {
    /// The type of the hash.
    type Hash;

    /// Completes a round of hashing, producing the output hash generated.
    fn finish(&self) -> Self::Hash;

    /// Writes some data into this Hasher.
    fn write(&mut self, bytes: &[u8]);
}

/// The FNV-0 hash.
///
/// This is deprecated except for computing the FNV offset basis for FNV-1 and
/// FNV-1a hashes.
#[derive(Debug, Default)]
pub struct Fnv0<T> {
    hash: T,
}

/// The FNV-1 hash.
#[derive(Debug)]
pub struct Fnv1<T> {
    hash: T,
}

/// The FNV-1a hash.
#[derive(Debug)]
pub struct Fnv1a<T> {
    hash: T,
}

impl<T: Default> Fnv0<T> {
    /// Creates a new `Fnv0<T>`.
    ///
    /// ```
    /// use lz_fnv::Fnv0;
    ///
    /// let fnv_hasher = Fnv0::<u32>::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T> Fnv0<T> {
    /// Creates a new `Fnv0<T>` with the specified key.
    ///
    /// ```
    /// use lz_fnv::Fnv0;
    ///
    /// let fnv_hasher = Fnv0::with_key(872u32);
    /// ```
    pub fn with_key(key: T) -> Self {
        Self { hash: key }
    }
}

impl<T> Fnv1<T> {
    /// Creates a new `Fnv1<T>` with the specified key.
    ///
    /// ```
    /// use lz_fnv::Fnv1;
    ///
    /// let fnv_hasher = Fnv1::with_key(872u32);
    /// ```
    pub fn with_key(key: T) -> Self {
        Self { hash: key }
    }
}

impl<T> Fnv1a<T> {
    /// Creates a new `Fnv1a<T>` with the specified key.
    ///
    /// ```
    /// use lz_fnv::Fnv1a;
    ///
    /// let fnv_hasher = Fnv1a::with_key(872u32);
    /// ```
    pub fn with_key(key: T) -> Self {
        Self { hash: key }
    }
}

macro_rules! fnv0_impl {
    ($type: ty, $prime: expr, $from_byte: ident) => {
        impl FnvHasher for Fnv0<$type> {
            type Hash = $type;

            fn finish(&self) -> Self::Hash {
                self.hash
            }

            fn write(&mut self, bytes: &[u8]) {
                let mut hash = self.hash;

                for byte in bytes {
                    hash = hash.wrapping_mul($prime);
                    hash ^= ($from_byte)(*byte);
                }

                self.hash = hash;
            }
        }
    };
}

macro_rules! fnv1_impl {
    ($type: ty, $offset: expr, $prime: expr, $from_byte: ident) => {
        impl Default for Fnv1<$type> {
            fn default() -> Self {
                Self { hash: $offset }
            }
        }

        impl Fnv1<$type> {
            /// Creates a new `Fnv1<T>`.
            pub fn new() -> Self {
                Self::default()
            }
        }

        impl FnvHasher for Fnv1<$type> {
            type Hash = $type;

            fn finish(&self) -> Self::Hash {
                self.hash
            }

            fn write(&mut self, bytes: &[u8]) {
                let mut hash = self.hash;

                for byte in bytes {
                    hash = hash.wrapping_mul($prime);
                    hash ^= ($from_byte)(*byte);
                }

                self.hash = hash;
            }
        }
    };
}

macro_rules! fnv1a_impl {
    ($type: ty, $offset: expr, $prime: expr, $from_byte: ident) => {
        impl Default for Fnv1a<$type> {
            fn default() -> Self {
                Self { hash: $offset }
            }
        }

        impl Fnv1a<$type> {
            /// Creates a new `Fnv1a<T>`.
            pub fn new() -> Self {
                Self::default()
            }
        }

        impl FnvHasher for Fnv1a<$type> {
            type Hash = $type;

            fn finish(&self) -> Self::Hash {
                self.hash
            }

            fn write(&mut self, bytes: &[u8]) {
                let mut hash = self.hash;

                for byte in bytes {
                    hash ^= ($from_byte)(*byte);
                    hash = hash.wrapping_mul($prime);
                }

                self.hash = hash;
            }
        }
    };
}

macro_rules! fnv_hasher_impl {
    ($type: ty) => {
        impl ::std::hash::Hasher for $type {
            fn finish(&self) -> u64 {
                ::FnvHasher::finish(self)
            }

            fn write(&mut self, bytes: &[u8]) {
                ::FnvHasher::write(self, bytes);
            }
        }
    };
}
macro_rules! fnv_impl {
    (u64, $offset: expr, $prime: expr, $from_byte: ident) => {
        fnv0_impl!(u64, $prime, $from_byte);
        fnv_hasher_impl!(Fnv0<u64>);

        fnv1_impl!(u64, $offset, $prime, $from_byte);
        fnv_hasher_impl!(Fnv1<u64>);

        fnv1a_impl!(u64, $offset, $prime, $from_byte);
        fnv_hasher_impl!(Fnv1a<u64>);
    };
    ($type: ty, $offset: expr, $prime: expr, $from_byte: ident) => {
        fnv0_impl!($type, $prime, $from_byte);
        fnv1_impl!($type, $offset, $prime, $from_byte);
        fnv1a_impl!($type, $offset, $prime, $from_byte);
    };
}

fn u32_from_byte(byte: u8) -> u32 {
    byte.into()
}

fn u64_from_byte(byte: u8) -> u64 {
    byte.into()
}

fn u128_from_byte(byte: u8) -> u128 {
    byte.into()
}

fnv_impl!(u32, 0x811c_9dc5, 0x100_0193, u32_from_byte);
fnv_impl!(u64, 0xcbf2_9ce4_8422_2325, 0x100_0000_01B3, u64_from_byte);
fnv_impl!(
    u128,
    0x6C62_272E_07BB_0142_62B8_2175_6295_C58D,
    0x0000_0000_0100_0000_0000_0000_0000_013B,
    u128_from_byte
);

#[cfg(test)]
mod tests {
    use std::iter;
    use {Fnv0, Fnv1, Fnv1a, FnvHasher};

    macro_rules! fnv0_tests {
        ($($name: ident: $size: ty, $input: expr, $expected_hash: expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let mut fnv0 = Fnv0::<$size>::new();

                    fnv0.write($input);

                    let result = fnv0.finish();

                    assert_eq!(result, $expected_hash);
                }
            )*
        };
    }

    macro_rules! fnv1_tests {
        ($($name: ident: $size: ty, $input: expr, $expected_hash: expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let mut fnv1 = Fnv1::<$size>::new();

                    fnv1.write($input);

                    let result = fnv1.finish();

                    assert_eq!(result, $expected_hash);
                }
            )*
        };
    }
    macro_rules! fnv1a_tests {
        ($($name: ident: $size: ty, $input: expr, $expected_hash: expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let mut fnv1a = Fnv1a::<$size>::new();

                    fnv1a.write($input);

                    let result = fnv1a.finish();

                    assert_eq!(result, $expected_hash);
                }
            )*
        };
    }

    fn repeat(slice: &[u8], times: usize) -> Vec<u8> {
        iter::repeat(slice).take(times).flatten().cloned().collect()
    }

    include!("fnv_test_cases.rs");

    fnv0_tests! {
        fnv0_offset_calculation_128_bit: u128, b"chongo <Landon Curt Noll> /\\../\\", 0x6C62_272E_07BB_0142_62B8_2175_6295_C58D,
    }
}
