//! Session demultiplexer.
use std::{
    collections::{BTreeSet, HashMap},
    hash::Hash,
    io::Write,
    sync::Arc,
};

use anyhow::Result;
use rand::{rngs::OsRng, Rng};
use tokio::sync::OwnedMutexGuard;

use super::{
    session::{Builder, Session, SessionInfo},
    types::{Message, SessionID},
};
use crate::common::time::insecure_posix_time;

/// Shared pointer to a multiplexed session.
pub type SharedSession<PeerID> = Arc<tokio::sync::Mutex<MultiplexedSession<PeerID>>>;

/// Key for use in the by-idle-time index.
pub type SessionByTimeKey<PeerID> = (i64, PeerID, SessionID);

/// Sessions error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("max concurrent sessions reached")]
    MaxConcurrentSessions,
}

/// A multiplexed session.
pub struct MultiplexedSession<PeerID> {
    /// Peer identifier (needed for resolution when only given the shared pointer).
    peer_id: PeerID,
    /// Session identifier (needed for resolution when only given the shared pointer).
    session_id: SessionID,
    /// The actual session.
    inner: Session,
}

impl<PeerID> MultiplexedSession<PeerID> {
    /// Session information.
    pub fn info(&self) -> Option<Arc<SessionInfo>> {
        self.inner.session_info()
    }

    /// Whether the session is in closed state.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Process incoming session data.
    pub async fn process_data<W: Write>(
        &mut self,
        data: Vec<u8>,
        writer: W,
    ) -> Result<Option<Message>> {
        self.inner.process_data(data, writer).await
    }

    /// Write message to session and generate a response.
    pub fn write_message<W: Write>(&mut self, msg: Message, mut writer: W) -> Result<()> {
        self.inner.write_message(msg, &mut writer)
    }
}

/// Structure used for session accounting.
pub struct SessionMeta<PeerID: Clone + Ord + Hash> {
    /// Peer identifier.
    peer_id: PeerID,
    /// Session identifier.
    session_id: SessionID,
    /// Timestamp when the session was last accessed.
    last_access_time: i64,
    /// The shared session pointer that needs to be locked for access.
    inner: SharedSession<PeerID>,
}

impl<PeerID> SessionMeta<PeerID>
where
    PeerID: Clone + Ord + Hash,
{
    /// Key for ordering in the by-idle-time index.
    fn by_time_key(&self) -> SessionByTimeKey<PeerID> {
        (self.last_access_time, self.peer_id.clone(), self.session_id)
    }
}

/// Session indices and management operations.
pub struct Sessions<PeerID: Clone + Ord + Hash> {
    /// Session builder.
    builder: Builder,
    /// Maximum number of sessions.
    max_sessions: usize,
    /// Maximum number of sessions per peer.
    max_sessions_per_peer: usize,
    /// Stale session timeout (in seconds).
    stale_session_timeout: i64,

    /// A map of sessions for each peer.
    by_peer: HashMap<PeerID, HashMap<SessionID, SessionMeta<PeerID>>>,
    /// A set of all sessions, ordered by idle time.
    by_idle_time: BTreeSet<SessionByTimeKey<PeerID>>,
}

impl<PeerID> Sessions<PeerID>
where
    PeerID: Clone + Ord + Hash,
{
    /// Create a new session management instance.
    pub fn new(
        builder: Builder,
        max_sessions: usize,
        max_sessions_per_peer: usize,
        stale_session_timeout: i64,
    ) -> Self {
        Self {
            builder,
            max_sessions,
            max_sessions_per_peer,
            stale_session_timeout,
            by_peer: HashMap::new(),
            by_idle_time: BTreeSet::new(),
        }
    }

    /// Create a new multiplexed session.
    pub fn create_session(
        mut builder: Builder,
        peer_id: PeerID,
        session_id: SessionID,
        now: i64,
    ) -> SessionMeta<PeerID> {
        // If no quote policy is set, use the local one.
        if builder.get_quote_policy().is_none() {
            let policy = builder
                .get_local_identity()
                .as_ref()
                .and_then(|id| id.quote_policy());
            builder = builder.quote_policy(policy);
        }

        SessionMeta {
            inner: Arc::new(tokio::sync::Mutex::new(MultiplexedSession {
                peer_id: peer_id.clone(),
                session_id,
                inner: builder.build_responder(),
            })),
            peer_id,
            session_id,
            last_access_time: now,
        }
    }

    /// Fetch an existing session given its identifier.
    pub fn get(
        &mut self,
        peer_id: &PeerID,
        session_id: &SessionID,
    ) -> Option<SharedSession<PeerID>> {
        // Check if peer exists.
        let sessions = match self.by_peer.get_mut(peer_id) {
            Some(sessions) => sessions,
            None => return None,
        };

        // Check if the session exists. If so, return it.
        let session = match sessions.get_mut(session_id) {
            Some(session) => session,
            None => return None,
        };

        Self::update_access_time(session, &mut self.by_idle_time);

        Some(session.inner.clone())
    }

    /// Fetch an existing session from one of the given peers. If no peers
    /// are provided, a session from any peer will be returned.
    pub fn find(&mut self, peer_ids: &[PeerID]) -> Option<SharedSession<PeerID>> {
        match peer_ids.is_empty() {
            true => self.find_any(),
            false => self.find_one(peer_ids),
        }
    }

    /// Fetch an existing session from any peer.
    pub fn find_any(&mut self) -> Option<SharedSession<PeerID>> {
        if self.by_idle_time.is_empty() {
            return None;
        }

        // Check if there is a session that is not currently in use.
        for (_, peer_id, session_id) in self.by_idle_time.iter() {
            let session = self
                .by_peer
                .get_mut(peer_id)
                .unwrap()
                .get_mut(session_id)
                .unwrap();

            if session.inner.clone().try_lock_owned().is_ok() {
                Self::update_access_time(session, &mut self.by_idle_time);
                return Some(session.inner.clone());
            }
        }

        // If all sessions are in use, return a random one.
        let n = OsRng.gen_range(0..self.by_idle_time.len());
        let (_, peer_id, session_id) = self.by_idle_time.iter().nth(n).unwrap();
        let session = self
            .by_peer
            .get_mut(peer_id)
            .unwrap()
            .get_mut(session_id)
            .unwrap();

        Self::update_access_time(session, &mut self.by_idle_time);

        Some(session.inner.clone())
    }

    /// Fetch an existing session from one of the given peers.
    pub fn find_one(&mut self, peer_ids: &[PeerID]) -> Option<SharedSession<PeerID>> {
        let mut all_sessions = vec![];

        for peer_id in peer_ids.iter() {
            let sessions = match self.by_peer.get_mut(peer_id) {
                Some(sessions) => sessions,
                None => return None,
            };

            // Check if peer has a session that is not currently in use.
            let session = sessions
                .values_mut()
                .filter(|s| s.inner.clone().try_lock_owned().is_ok())
                .min_by_key(|s| s.last_access_time);

            if let Some(session) = session {
                Self::update_access_time(session, &mut self.by_idle_time);
                return Some(session.inner.clone());
            }

            for session in sessions.values() {
                all_sessions.push((session.peer_id.clone(), session.session_id));
            }
        }

        if all_sessions.is_empty() {
            return None;
        }

        // If all sessions are in use, return a random one.
        let n = OsRng.gen_range(0..all_sessions.len());
        let (peer_id, session_id) = all_sessions.get(n).unwrap();
        let session = self
            .by_peer
            .get_mut(peer_id)
            .unwrap()
            .get_mut(session_id)
            .unwrap();

        Self::update_access_time(session, &mut self.by_idle_time);

        Some(session.inner.clone())
    }

    /// Remove one existing session from the given peer if the peer has reached
    /// the maximum number of sessions or if the total number of sessions exceeds
    /// the global session limit.
    pub fn remove_from(
        &mut self,
        peer_id: &PeerID,
    ) -> Result<Option<OwnedMutexGuard<MultiplexedSession<PeerID>>>, Error> {
        // Check if peer exists.
        let sessions = match self.by_peer.get_mut(peer_id) {
            Some(sessions) => sessions,
            None => return Ok(None),
        };

        // Check if the peer has max sessions or if no more sessions are available globally.
        // If so, remove the oldest or return an error.
        if sessions.len() < self.max_sessions_per_peer
            && self.by_idle_time.len() < self.max_sessions
        {
            return Ok(None);
        }

        // Force close the oldest idle session.
        let remove_session = sessions
            .iter()
            .min_by_key(|(_, s)| {
                if let Ok(_inner) = s.inner.try_lock() {
                    s.last_access_time
                } else {
                    i64::MAX // Session is currently in use.
                }
            })
            .map(|(_, s)| s.inner.clone())
            .ok_or(Error::MaxConcurrentSessions)?;

        let session = match remove_session.try_lock_owned() {
            Ok(inner) => inner,
            Err(_) => return Err(Error::MaxConcurrentSessions), // All sessions are in use.
        };

        self.remove(&session);

        Ok(Some(session))
    }

    /// Remove one stale session if the total number of sessions exceeds
    /// the global session limit.
    pub fn remove_one(
        &mut self,
        now: i64,
    ) -> Result<Option<OwnedMutexGuard<MultiplexedSession<PeerID>>>, Error> {
        // Check if there are too many sessions. If so, remove one or return an error.
        if self.by_idle_time.len() < self.max_sessions {
            return Ok(None);
        }

        // Attempt to prune stale sessions, starting with the oldest ones.
        let mut remove_session: Option<OwnedMutexGuard<MultiplexedSession<PeerID>>> = None;

        for (last_process_frame_time, peer_id, session_id) in self.by_idle_time.iter() {
            if now.saturating_sub(*last_process_frame_time) < self.stale_session_timeout {
                // This is the oldest session, all next ones will be more fresh.
                return Err(Error::MaxConcurrentSessions);
            }

            // Fetch session and attempt to lock it.
            if let Some(sessions) = self.by_peer.get(peer_id) {
                if let Some(session) = sessions.get(session_id) {
                    if let Ok(session) = session.inner.clone().try_lock_owned() {
                        remove_session = Some(session);
                        break;
                    }
                }
            }
        }

        // Check if we found a session that can be removed.
        let session = match remove_session {
            Some(session) => session,
            None => return Err(Error::MaxConcurrentSessions), // All stale sessions are in use.
        };

        self.remove(&session);

        Ok(Some(session))
    }

    /// Create a new session if there is an available spot.
    pub fn create(
        &mut self,
        peer_id: PeerID,
        session_id: SessionID,
        now: i64,
    ) -> Result<SharedSession<PeerID>, Error> {
        if self.by_idle_time.len() >= self.max_sessions {
            return Err(Error::MaxConcurrentSessions);
        }

        let sessions = self.by_peer.entry(peer_id.clone()).or_default();
        if sessions.len() >= self.max_sessions_per_peer {
            return Err(Error::MaxConcurrentSessions);
        }

        let session = Self::create_session(self.builder.clone(), peer_id.clone(), session_id, now);
        let inner = session.inner.clone();
        sessions.insert(session_id, session);
        self.by_idle_time.insert((now, peer_id, session_id));

        Ok(inner)
    }

    /// Remove a session that must be currently owned by the caller.
    pub fn remove(&mut self, session: &OwnedMutexGuard<MultiplexedSession<PeerID>>) {
        let sessions = self.by_peer.get_mut(&session.peer_id).unwrap();
        let session_meta = sessions.get(&session.session_id).unwrap();
        let key = session_meta.by_time_key();
        sessions.remove(&session.session_id);
        self.by_idle_time.remove(&key);

        // If peer doesn't have any more sessions, remove the peer.
        if sessions.is_empty() {
            self.by_peer.remove(&session.peer_id);
        }
    }

    /// Clear all sessions.
    pub fn clear(&mut self) {
        self.by_peer.clear();
        self.by_idle_time.clear();
    }

    fn update_access_time(
        session: &mut SessionMeta<PeerID>,
        by_idle_time: &mut BTreeSet<SessionByTimeKey<PeerID>>,
    ) {
        // Remove old idle time.
        by_idle_time.remove(&session.by_time_key());

        // Update idle time.
        session.last_access_time = insecure_posix_time();
        by_idle_time.insert(session.by_time_key());
    }

    /// Number of all sessions.
    #[cfg(test)]
    fn session_count(&self) -> usize {
        self.by_idle_time.len()
    }

    /// Number of all peers.
    #[cfg(test)]
    fn peer_count(&self) -> usize {
        self.by_peer.len()
    }
}

#[cfg(test)]
mod test {
    use crate::enclave_rpc::{session::Builder, types::SessionID};

    use super::{Error, Sessions};

    fn ids() -> (Vec<Vec<u8>>, Vec<SessionID>) {
        let peer_ids: Vec<Vec<u8>> = (1..8).map(|x| vec![x]).collect();
        let session_ids: Vec<SessionID> = (1..8).map(|_| SessionID::random()).collect();

        (peer_ids, session_ids)
    }

    #[test]
    fn test_create() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 4, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0], 1, 1, true),
            (&peer_ids[0], &session_ids[1], 2, 1, true), // Different session ID.
            (&peer_ids[0], &session_ids[2], 2, 1, false), // Too many sessions per peer.
            (&peer_ids[1], &session_ids[0], 3, 2, true), // Different peer ID.
            (&peer_ids[2], &session_ids[2], 4, 3, true), // Different peer ID and session ID.
            (&peer_ids[3], &session_ids[3], 4, 3, false), // Too many sessions.
        ];

        let now = 0;
        for (peer_id, session_id, num_sessions, num_peers, created) in test_vector {
            let res = sessions.create(peer_id.clone(), session_id.clone(), now);
            match created {
                true => {
                    assert!(res.is_ok(), "session should be created");
                    let s = res.unwrap();
                    let s_owned = s.try_lock().unwrap();
                    assert_eq!(&s_owned.peer_id, peer_id);
                    assert_eq!(&s_owned.session_id, session_id);
                }
                false => {
                    assert!(res.is_err(), "session should not be created");
                    assert!(matches!(res, Err(Error::MaxConcurrentSessions)));
                }
            };
            assert_eq!(sessions.session_count(), num_sessions);
            assert_eq!(sessions.peer_count(), num_peers);
        }
    }

    #[test]
    fn test_get() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 8, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0], true),
            (&peer_ids[0], &session_ids[1], false), // Different peer ID.
            (&peer_ids[1], &session_ids[0], false), // Different session ID.
            (&peer_ids[1], &session_ids[1], false), // Different peer ID and session ID.
        ];

        let now = 0;
        for (peer_id, session_id, create) in test_vector {
            if create {
                let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
            }

            let maybe_s = sessions.get(peer_id, session_id);
            match create {
                true => {
                    assert!(maybe_s.is_some(), "session should exist");
                    let s = maybe_s.unwrap();
                    let s_owned = s.try_lock_owned().unwrap();
                    assert_eq!(&s_owned.peer_id, peer_id);
                    assert_eq!(&s_owned.session_id, session_id);
                }
                false => assert!(maybe_s.is_none(), "session should not exist"),
            }
        }
    }

    #[test]
    fn test_find_any() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 8, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0]),
            (&peer_ids[0], &session_ids[1]),
            (&peer_ids[1], &session_ids[2]),
        ];

        // No sessions.
        let maybe_s = sessions.find_any();
        assert!(maybe_s.is_none(), "session should not be found");

        let mut now = 0;
        for (peer_id, session_id) in test_vector {
            let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
            now += 1
        }

        // No sessions in use.
        let maybe_s = sessions.find_any();
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let s1_owned = s.try_lock_owned().unwrap(); // Session now in use.
        assert_eq!(&s1_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s1_owned.session_id, &session_ids[0]);

        // One session in use.
        let maybe_s = sessions.find_any();
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let s2_owned = s.try_lock_owned().unwrap(); // Session now in use.
        assert_eq!(&s2_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s2_owned.session_id, &session_ids[1]); // Different session found.

        // Two sessions in use.
        let maybe_s = sessions.find_any();
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let s3_owned = s.try_lock_owned().unwrap(); // Session now in use.
        assert_eq!(&s3_owned.peer_id, &peer_ids[1]);
        assert_eq!(&s3_owned.session_id, &session_ids[2]); // Different session found.

        // All sessions in use.
        let maybe_s = sessions.find_any();
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let res = s.try_lock_owned(); // Session now in use.
        assert!(res.is_err(), "session should be in use");

        // Free one session.
        drop(s2_owned);

        // Two sessions in use.
        let maybe_s = sessions.find_any();
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let s_owned = s.try_lock_owned().unwrap(); // Session now in use.
        assert_eq!(&s_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s_owned.session_id, &session_ids[1]);
    }

    #[test]
    fn test_find_one() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 8, 2, 60);

        let test_vector = vec![
            (&peer_ids[2], &session_ids[0]), // Incorrect peer.
            (&peer_ids[0], &session_ids[0]),
            (&peer_ids[3], &session_ids[1]), // Incorrect peer.
            (&peer_ids[0], &session_ids[1]),
            (&peer_ids[3], &session_ids[2]), // Incorrect peer.
            (&peer_ids[1], &session_ids[2]),
            (&peer_ids[2], &session_ids[2]), // Incorrect peer.
        ];

        // No sessions.
        let maybe_s = sessions.find_one(&peer_ids[0..2]);
        assert!(maybe_s.is_none(), "session should not be found");

        let mut now = 0;
        for (peer_id, session_id) in test_vector {
            let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
            now += 1
        }

        // Peers without sessions.
        let maybe_s = sessions.find_one(&peer_ids[4..]);
        assert!(maybe_s.is_none(), "session should not be found");

        // No sessions in use.
        let maybe_s = sessions.find_one(&peer_ids[0..2]);
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let s1_owned = s.try_lock_owned().unwrap(); // Session now in use.
        assert_eq!(&s1_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s1_owned.session_id, &session_ids[0]);

        // One session in use.
        let maybe_s = sessions.find_one(&peer_ids[0..2]);
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let s2_owned = s.try_lock_owned().unwrap(); // Session now in use.
        assert_eq!(&s2_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s2_owned.session_id, &session_ids[1]); // Different session found.

        // Two sessions in use.
        let maybe_s = sessions.find_one(&peer_ids[0..2]);
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let s3_owned = s.try_lock_owned().unwrap(); // Session now in use.
        assert_eq!(&s3_owned.peer_id, &peer_ids[1]);
        assert_eq!(&s3_owned.session_id, &session_ids[2]); // Different session found.

        // All sessions in use.
        let maybe_s = sessions.find_one(&peer_ids[0..2]);
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let res = s.try_lock_owned(); // Session now in use.
        assert!(res.is_err(), "session should be in use");

        // Free one session.
        drop(s2_owned);

        // Two sessions in use.
        let maybe_s = sessions.find_one(&peer_ids[0..2]);
        assert!(maybe_s.is_some(), "session should be found");
        let s = maybe_s.unwrap();
        let s_owned = s.try_lock_owned().unwrap(); // Session now in use.
        assert_eq!(&s_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s_owned.session_id, &session_ids[1]);
    }

    #[test]
    fn test_remove_from() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 4, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0]),
            (&peer_ids[1], &session_ids[1]),
            (&peer_ids[2], &session_ids[2]),
            (&peer_ids[2], &session_ids[3]), // Max sessions per peer reached.
                                             // Max sessions reached.
        ];

        let mut now = 0;
        for (peer_id, session_id) in test_vector.clone() {
            let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
            now += 1;
        }

        // Removing one session from an unknown peer should have no effect,
        // even if all global session slots are occupied.
        let res = sessions.remove_from(&peer_ids[3]);
        assert!(res.is_ok(), "remove_from should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_none(), "no sessions should be removed");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 3);

        // Removing one session for one of the existing peers should work
        // as it should force evict an old session.
        // Note that each peer has 2 available slots, but globally there are
        // only 4 slots so if global slots are full this should trigger peer
        // session eviction.
        let res = sessions.remove_from(&peer_ids[0]);
        assert!(res.is_ok(), "remove_from should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_some(), "one session should be removed");
        let s_owned = maybe_s_owned.unwrap();
        assert_eq!(&s_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s_owned.session_id, &session_ids[0]);
        assert_eq!(sessions.session_count(), 3);
        assert_eq!(sessions.peer_count(), 2);

        // Removing another session should fail as one global session slot
        // is available.
        for peer_id in vec![&peer_ids[0], &peer_ids[1]] {
            let res = sessions.remove_from(peer_id);
            assert!(res.is_ok(), "remove_from should succeed");
            let maybe_s_owned = res.unwrap();
            assert!(maybe_s_owned.is_none(), "no sessions should be removed");
            assert_eq!(sessions.session_count(), 3);
            assert_eq!(sessions.peer_count(), 2);
        }

        // Removing one session from a peer with max sessions should succeed
        // even if one global slot is available.
        let res = sessions.remove_from(&peer_ids[2]);
        assert!(res.is_ok(), "remove_from should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_some(), "one session should be removed");
        let s_owned = maybe_s_owned.unwrap();
        assert_eq!(&s_owned.peer_id, &peer_ids[2]);
        assert_eq!(&s_owned.session_id, &session_ids[2]);
        assert_eq!(sessions.session_count(), 2);
        assert_eq!(sessions.peer_count(), 2);
    }

    #[test]
    fn test_remove_one() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 4, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0]),
            (&peer_ids[1], &session_ids[1]),
            (&peer_ids[2], &session_ids[2]),
            (&peer_ids[2], &session_ids[3]), // Max sessions reached.
        ];

        let mut now = 0;
        for (peer_id, session_id) in test_vector.clone() {
            let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
            now += 1;
        }

        // Forward time (stale_session_timeout - test_vector.len() - 1).
        now += 60 - 4 - 1;

        // Removing one session should fail as there are none stale sessions.
        let res = sessions.remove_one(now);
        assert!(res.is_err(), "remove_one should fail");
        assert!(matches!(res, Err(Error::MaxConcurrentSessions)));
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 3);

        // Forward time.
        now += 1;

        // Removing one session should succeed as no session slots
        // are available and there is one stale session.
        let res = sessions.remove_one(now);
        assert!(res.is_ok(), "remove_one should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_some(), "one session should be removed");
        let s_owned = maybe_s_owned.unwrap();
        assert_eq!(&s_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s_owned.session_id, &session_ids[0]);
        assert_eq!(sessions.session_count(), 3);
        assert_eq!(sessions.peer_count(), 2);

        // Forward time.
        now += 100;

        // Removing one session should fail even though there are stale sessions
        // because there is one session slot available.
        let res = sessions.remove_one(now);
        assert!(res.is_ok(), "remove_one should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_none(), "no sessions should be removed");
        assert_eq!(sessions.session_count(), 3);
        assert_eq!(sessions.peer_count(), 2);
    }

    #[test]
    fn test_remove() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 8, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0], 3, 2),
            (&peer_ids[1], &session_ids[1], 2, 1),
            (&peer_ids[2], &session_ids[2], 1, 1),
            (&peer_ids[2], &session_ids[3], 0, 0),
        ];

        let now = 0;
        for (peer_id, session_id, _, _) in test_vector.clone() {
            let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
        }

        for (peer_id, session_id, num_sessions, num_peers) in test_vector {
            let maybe_s = sessions.get(peer_id, session_id);
            assert!(maybe_s.is_some(), "session should exist");
            let s = maybe_s.unwrap();
            let s_owned = s.try_lock_owned().unwrap();

            sessions.remove(&s_owned);
            assert_eq!(sessions.session_count(), num_sessions);
            assert_eq!(sessions.peer_count(), num_peers);
        }
    }
}
