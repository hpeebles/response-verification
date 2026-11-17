//! Cache for BLS signatures
//!
//! Built on `lru` rather than `cached`: `cached` depends on `web-time`, which
//! on `wasm32-unknown-unknown` pulls in `js-sys` and with it wasm-bindgen
//! imports, so a canister linking it could not be installed. `lru` needs
//! nothing beyond `core` and `hashbrown`.

use lru::LruCache;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg(test)]
pub struct SignatureCacheStatistics {
    pub size: usize,
    pub hits: u64,
    pub misses: u64,
}

#[cfg(test)]
impl SignatureCacheStatistics {
    pub(super) fn new(size: usize, hits: u64, misses: u64) -> Self {
        Self { size, hits, misses }
    }
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub(crate) struct SignatureCacheEntry {
    hash: [u8; 32],
}

impl SignatureCacheEntry {
    /// Hash the verification inputs to a short string
    ///
    /// This reduces the amount of memory the cache consumes
    pub(crate) fn new(pk: &[u8], sig: &[u8], msg: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut sha256 = Sha256::new();
        sha256.update(pk);
        sha256.update(sig);
        sha256.update(msg);
        let hash = sha256.finalize().into();
        Self { hash }
    }
}

/// A cache for BLS signature verification
pub(crate) struct SignatureCache {
    cache: parking_lot::Mutex<Inner>,
}

struct Inner {
    // Unbounded to `lru`, and held to `max_size` by `insert`: a bounded
    // `LruCache` allocates its whole table up front, which every user would
    // pay on first touch whether or not the cache ever fills.
    entries: LruCache<SignatureCacheEntry, ()>,
    max_size: usize,
    hits: u64,
    misses: u64,
}

lazy_static::lazy_static! {
    static ref GLOBAL_SIGNATURE_CACHE: SignatureCache = SignatureCache::new(SignatureCache::SIZE_OF_GLOBAL_CACHE);
}

impl SignatureCache {
    /// Specify the size of the global signature cache
    ///
    /// Each entry is a 32-byte hash in one of `lru`'s list nodes (the hash
    /// plus two pointers), with a pointer-sized slot for it in the hash
    /// table, so with the currently specified size a full cache consumes
    /// roughly 6 MB of RAM. The table grows as the cache fills.
    pub const SIZE_OF_GLOBAL_CACHE: usize = 100000;

    /// Create a new signature cache with the specified maximum size
    pub(super) fn new(max_size: usize) -> Self {
        let cache = parking_lot::Mutex::new(Inner {
            entries: LruCache::unbounded(),
            max_size,
            hits: 0,
            misses: 0,
        });
        Self { cache }
    }

    /// Return a reference to the global signature cache
    pub(crate) fn global() -> &'static Self {
        &GLOBAL_SIGNATURE_CACHE
    }

    /// Check if a cache entry already exists
    ///
    /// Returns true if found, false otherwise
    pub(crate) fn contains(&self, entry: &SignatureCacheEntry) -> bool {
        let mut cache = self.cache.lock();
        let found = cache.entries.get(entry).is_some();
        if found {
            cache.hits += 1;
        } else {
            cache.misses += 1;
        }
        found
    }

    /// Insert a entry into the signature cache
    ///
    /// # Warning
    /// A signature should only be added to the cache if it has previously
    /// been verified to be valid.
    pub(crate) fn insert(&self, entry: &SignatureCacheEntry) {
        let mut cache = self.cache.lock();
        cache.entries.put(*entry, ());
        while cache.entries.len() > cache.max_size {
            cache.entries.pop_lru();
        }
    }

    /// Return statistics about the cache
    ///
    /// Returns the size of the cache, the number of cache hits, and
    /// the number of cache misses
    #[cfg(test)]
    pub(crate) fn cache_statistics(&self) -> SignatureCacheStatistics {
        let cache = self.cache.lock();

        SignatureCacheStatistics::new(cache.entries.len(), cache.hits, cache.misses)
    }
}
