use tendermint_light_client::{components, types::Time};

use crate::common::time;

pub struct InsecureClock;

impl components::clock::Clock for InsecureClock {
    fn now(&self) -> Time {
        Time::from_unix_timestamp(time::insecure_posix_time(), 0).unwrap()
    }
}
