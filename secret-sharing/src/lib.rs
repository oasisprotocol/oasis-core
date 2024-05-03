//! # Secret Sharing
//!
//! This library provides functionality for secret sharing, a technique used
//! to distribute a secret among a group of participants in such a way that
//! only a threshold number of participants can reconstruct the secret.
//!
//! ## Supported Schemes
//!
//! - CHURP (CHUrn-Robust Proactive secret sharing)

#![feature(test)]

pub mod churp;
pub mod suites;
pub mod vss;
