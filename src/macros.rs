// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

macro_rules! impl_pretty_debug {
    ($thing:ident) => {
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "{}(", stringify!($thing))?;
                for i in &self[..] {
                    write!(f, "{:02x}", i)?;
                }
                f.write_str(")")
            }
        }
     }
}

macro_rules! impl_safe_debug {
    ($thing:ident) => {
        #[cfg(feature = "alloc")]
        use alloc::string::String;

        #[cfg(feature = "bitcoin_hashes")]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                const DEBUG_HASH_TAG: &[u8] = &[
                    0x66, 0xa6, 0x77, 0x1b, 0x9b, 0x6d, 0xae, 0xa1, 0xb2, 0xee, 0x4e, 0x07, 0x49,
                    0x4a, 0xac, 0x87, 0xa9, 0xb8, 0x5b, 0x4b, 0x35, 0x02, 0xaa, 0x6d, 0x0f, 0x79,
                    0xcb, 0x63, 0xe6, 0xf8, 0x66, 0x22
                ]; // =SHA256(b"rust-secp256k1DEBUG");
                use ::bitcoin_hashes::{Hash, sha256, HashEngine};

                let mut engine = sha256::HashEngine::default();
                engine.input(DEBUG_HASH_TAG);
                engine.input(DEBUG_HASH_TAG);
                engine.input(&self.0[..]);
                let hash = sha256::Hash::from_engine(engine);

                write!(f, "{}(#", stringify!($thing))?;
                for i in &hash[..4] {
                    write!(f, "{:02x}", i)?;
                }
                f.write_str("...")?;
                for i in &hash[28..] {
                    write!(f, "{:02x}", i)?;
                }
                f.write_str(")")
            }
        }

        #[cfg(all(not(feature = "bitcoin_hashes"), feature = "std"))]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                use ::core::hash::Hasher;
                const DEBUG_HASH_TAG: &[u8] = &[
                    0x66, 0xa6, 0x77, 0x1b, 0x9b, 0x6d, 0xae, 0xa1, 0xb2, 0xee, 0x4e, 0x07, 0x49,
                    0x4a, 0xac, 0x87, 0xa9, 0xb8, 0x5b, 0x4b, 0x35, 0x02, 0xaa, 0x6d, 0x0f, 0x79,
                    0xcb, 0x63, 0xe6, 0xf8, 0x66, 0x22
                ]; // =SHA256(b"rust-secp256k1DEBUG");
                let mut hasher = ::std::collections::hash_map::DefaultHasher::new();

                hasher.write(DEBUG_HASH_TAG);
                hasher.write(DEBUG_HASH_TAG);
                hasher.write(&self.0[..]);
                let hash = hasher.finish();

                write!(f, "{}(#{:016x})", stringify!($thing), hash)
            }
        }

        impl $thing {
            /// Formats the explicit byte value of the secret key kept inside the type as a
            /// little-endian hexadecimal string using the provided formatter.
            ///
            /// This is the only method that outputs the actual secret key value, and, thus,
            /// should be used with extreme precaution.
            #[deprecated(
                note = "Caution: you are explicitly outputting secret key value! This can be done
                only in debug environment and that's why always considered as ``deprecated''"
            )]
            pub fn fmt_secret(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                for i in &self.0[..] {
                    write!(f, "{:02x}", i)?;
                }
                Ok(())
            }
        }
     }
}

macro_rules! impl_from_array_len {
    ($thing:ident, $capacity:tt, ($($N:tt)+)) => {
        $(
            impl From<[u8; $N]> for $thing {
                fn from(arr: [u8; $N]) -> Self {
                    let mut data = [0u8; $capacity];
                    data[..$N].copy_from_slice(&arr);
                    $thing {
                        data,
                        len: $N,
                    }
                }
            }
        )+
    }
}
