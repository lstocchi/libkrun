// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Safe wrappers around the Windows Hypervisor Platform (WHP) API.
//!
//! This crate mirrors the `hvf` crate's role for macOS: all unsafe FFI
//! calls to `WHv*` functions are confined here, so the VMM layer above
//! never touches unsafe code directly.

#[cfg(target_os = "windows")]
mod platform;

#[cfg(target_os = "windows")]
pub use platform::*;
