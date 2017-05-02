extern crate extprim;
#[macro_use] extern crate extprim_literals;

use extprim::u128::u128;

#[derive(Debug)]
pub struct Fnv128a {
    hash: u128,
}

impl Default for Fnv128a {
    fn default() -> Self{
        Self {
            hash: u128!(0x6C62272E07BB014262B821756295C58D)
        }
    }
}

const prime: u128 = u128!(0x0000000001000000000000000000013B);

impl Fnv128a {
    fn new(key: u128) -> Self {
        Self {
            hash: key
        }
    }
    fn finish(&self) -> u128 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut hash = self.hash;

        for byte in bytes {
            hash ^= u128::new(*byte as u64);
            hash = hash.wrapping_mul(prime);
        }

        self.hash = hash;
    }
}

#[cfg(test)]
mod tests {
    use super::Fnv128a;
    use extprim::u128::u128;

    #[test]
    fn empty_hash() {
        let fnv128a = Fnv128a::default();

        let hash = fnv128a.finish();

        assert_eq!(hash, u128!(0x6C62272E07BB014262B821756295C58D));
    }

    #[test]
    fn test_hash() {
        let mut fnv128a = Fnv128a::default();
        fnv128a.write(b"foobar");

        let hash = fnv128a.finish();

        assert_eq!(hash, u128!(0x343e1662793c64bf6f0d3597ba446f18));
    }
}
