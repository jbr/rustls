use crate::client;
use crate::enums::SignatureScheme;
use crate::error::Error;
use crate::key;
use crate::limited_cache;
use crate::msgs::persist;
use crate::sign;
use crate::NamedGroup;
use crate::ServerName;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// An implementer of `StoresClientSessions` which does nothing.
pub struct NoClientSessionStorage {}

impl client::StoresClientSessions for NoClientSessionStorage {
    fn put_kx_hint(&self, _: &ServerName, _: NamedGroup) {}

    fn get_kx_hint(&self, _: &ServerName) -> Option<NamedGroup> {
        None
    }

    fn put_tls12_session(&self, _: &ServerName, _: persist::Tls12ClientSessionValue) {}

    fn get_tls12_session(&self, _: &ServerName) -> Option<persist::Tls12ClientSessionValue> {
        None
    }

    fn forget_tls12_session(&self, _: &ServerName) {}

    fn add_tls13_ticket(&self, _: &ServerName, _: persist::Tls13ClientSessionValue) {}

    fn take_tls13_ticket(&self, _: &ServerName) -> Option<persist::Tls13ClientSessionValue> {
        None
    }
}

const MAX_TLS13_TICKETS_PER_SERVER: usize = 8;

struct ServerData {
    kx_hint: Option<NamedGroup>,

    // Zero or one TLS1.2 sessions.
    tls12: Option<persist::Tls12ClientSessionValue>,

    // Up to MAX_TLS13_TICKETS_PER_SERVER TLS1.3 tickets, most recent first.
    tls13: VecDeque<persist::Tls13ClientSessionValue>,
}

impl ServerData {
    fn new() -> Self {
        Self {
            kx_hint: None,
            tls12: None,
            tls13: VecDeque::with_capacity(MAX_TLS13_TICKETS_PER_SERVER),
        }
    }
}

/// An implementer of `StoresClientSessions` that stores everything
/// in memory.  It enforces a limit on the number of entries
/// to bound memory usage.
pub struct ClientSessionMemoryCache {
    servers: Mutex<limited_cache::LimitedCache<ServerName, ServerData>>,
}

impl ClientSessionMemoryCache {
    /// Make a new ClientSessionMemoryCache.  `size` is the
    /// maximum number of stored sessions.
    pub fn new(size: usize) -> Arc<Self> {
        let max_servers =
            size.saturating_add(MAX_TLS13_TICKETS_PER_SERVER - 1) / MAX_TLS13_TICKETS_PER_SERVER;
        Arc::new(Self {
            servers: Mutex::new(limited_cache::LimitedCache::new(max_servers)),
        })
    }
}

impl client::StoresClientSessions for ClientSessionMemoryCache {
    fn put_kx_hint(&self, server_name: &ServerName, group: NamedGroup) {
        self.servers
            .lock()
            .unwrap()
            .get_or_insert_and_edit(server_name.clone(), ServerData::new, |data| {
                data.kx_hint = Some(group)
            });
    }

    fn get_kx_hint(&self, server_name: &ServerName) -> Option<NamedGroup> {
        self.servers
            .lock()
            .unwrap()
            .get(server_name)
            .and_then(|sd| sd.kx_hint)
    }

    fn put_tls12_session(&self, server_name: &ServerName, value: persist::Tls12ClientSessionValue) {
        self.servers
            .lock()
            .unwrap()
            .get_or_insert_and_edit(server_name.clone(), ServerData::new, |data| {
                data.tls12 = Some(value)
            });
    }

    fn get_tls12_session(
        &self,
        server_name: &ServerName,
    ) -> Option<persist::Tls12ClientSessionValue> {
        self.servers
            .lock()
            .unwrap()
            .get(server_name)
            .and_then(|sd| sd.tls12.as_ref().cloned())
    }

    fn forget_tls12_session(&self, server_name: &ServerName) {
        self.servers
            .lock()
            .unwrap()
            .get_mut(server_name)
            .and_then(|data| data.tls12.take());
    }

    fn add_tls13_ticket(&self, server_name: &ServerName, value: persist::Tls13ClientSessionValue) {
        self.servers
            .lock()
            .unwrap()
            .get_or_insert_and_edit(server_name.clone(), ServerData::new, |data| {
                if data.tls13.len() == data.tls13.capacity() {
                    data.tls13.pop_back();
                }
                data.tls13.push_front(value);
            })
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName,
    ) -> Option<persist::Tls13ClientSessionValue> {
        self.servers
            .lock()
            .unwrap()
            .get_mut(server_name)
            .and_then(|data| data.tls13.pop_back())
    }
}

pub(super) struct FailResolveClientCert {}

impl client::ResolvesClientCert for FailResolveClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

pub(super) struct AlwaysResolvesClientCert(Arc<sign::CertifiedKey>);

impl AlwaysResolvesClientCert {
    pub(super) fn new(
        chain: Vec<key::Certificate>,
        priv_key: &key::PrivateKey,
    ) -> Result<Self, Error> {
        let key = sign::any_supported_type(priv_key)
            .map_err(|_| Error::General("invalid private key".into()))?;
        Ok(Self(Arc::new(sign::CertifiedKey::new(chain, key))))
    }
}

impl client::ResolvesClientCert for AlwaysResolvesClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::client::StoresClientSessions;
    use std::convert::TryInto;

    #[test]
    fn test_noclientsessionstorage_does_nothing() {
        let c = NoClientSessionStorage {};
        assert_eq!(None, c.get_kx_hint(&"example.com".try_into().unwrap()));
    }

    /*
    #[test]
    fn test_clientsessionmemorycache_accepts_put() {
        let c = ClientSessionMemoryCache::new(4);
        assert!(c.put(vec![0x01], vec![0x02]));
    }

    #[test]
    fn test_clientsessionmemorycache_persists_put() {
        let c = ClientSessionMemoryCache::new(4);
        assert!(c.put(vec![0x01], vec![0x02]));
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
        assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
    }

    #[test]
    fn test_clientsessionmemorycache_overwrites_put() {
        let c = ClientSessionMemoryCache::new(4);
        assert!(c.put(vec![0x01], vec![0x02]));
        assert!(c.put(vec![0x01], vec![0x04]));
        assert_eq!(c.get(&[0x01]), Some(vec![0x04]));
    }

    #[test]
    fn test_clientsessionmemorycache_drops_to_maintain_size_invariant() {
        let c = ClientSessionMemoryCache::new(2);
        assert!(c.put(vec![0x01], vec![0x02]));
        assert!(c.put(vec![0x03], vec![0x04]));
        assert!(c.put(vec![0x05], vec![0x06]));
        assert!(c.put(vec![0x07], vec![0x08]));
        assert!(c.put(vec![0x09], vec![0x0a]));

        let count = c.get(&[0x01]).iter().count()
            + c.get(&[0x03]).iter().count()
            + c.get(&[0x05]).iter().count()
            + c.get(&[0x07]).iter().count()
            + c.get(&[0x09]).iter().count();

        assert!(count < 5);
    }
    */
}
