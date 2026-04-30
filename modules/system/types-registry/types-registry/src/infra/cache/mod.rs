//! Cache infrastructure for the Types Registry module.

#[allow(clippy::module_inception)]
mod cache;

pub use cache::{
    Cache, CacheConfig, DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, HasUuid, InMemoryCache,
    InstanceCache, TypeSchemaCache,
};
