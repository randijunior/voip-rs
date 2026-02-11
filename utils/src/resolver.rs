//! DNS resolve with the `DnsResolver` type.

use std::io;
use std::net::IpAddr;

pub use hickory_resolver::Name;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::lookup_ip::LookupIp;
pub use hickory_resolver::proto::rr::RData;
use hickory_resolver::proto::rr::RecordType;
pub use hickory_resolver::proto::rr::rdata::{NAPTR, SRV};
use hickory_resolver::{IntoName, ResolveError};

/// A DNS resolver backed by [hickory-dns](https://github.com/hickory-dns/hickory-dns).
pub struct DnsResolver {
    dns_resolver: hickory_resolver::TokioResolver,
}

impl DnsResolver {
    /// NATPTR Lookup
    pub async fn naptr_lookup<N: IntoName>(&self, name: N) -> Result<Lookup, io::Error> {
        self.dns_resolver
            .lookup(name, RecordType::NAPTR)
            .await
            .map_err(|err| io::Error::other(format!("Failed to lookup NAPTR: {}", err)))
    }

    /// SRV Lookup
    pub async fn srv_lookup<N: IntoName>(&self, name: N) -> Result<Lookup, io::Error> {
        self.dns_resolver
            .lookup(name, RecordType::SRV)
            .await
            .map_err(|err| io::Error::other(format!("Failed to lookup SRV: {}", err)))
    }
    /// Lookup IP addresses for a host.
    pub async fn lookup_ip(
        &self,
        host: impl IntoName,
    ) -> std::result::Result<LookupIp, ResolveError> {
        self.dns_resolver.lookup_ip(host).await
    }

    /// Resolve a single.
    pub async fn resolve(&self, host: &str) -> Result<IpAddr, io::Error> {
        Ok(self
            .lookup_ip(host)
            .await
            .map_err(|err| io::Error::other(format!("Failed to lookup DNS: {}", err)))?
            .iter()
            .next()
            .unwrap())
    }

    /// Resolve a all.
    pub async fn resolve_all(&self, host: &str) -> Result<Vec<IpAddr>, io::Error> {
        let result = self
            .lookup_ip(host)
            .await
            .map_err(|err| io::Error::other(format!("Failed to lookup dns: {}", err)))?;

        let addresses = result.iter().collect();

        Ok(addresses)
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self {
            dns_resolver: hickory_resolver::Resolver::builder_tokio().unwrap().build(),
        }
    }
}
