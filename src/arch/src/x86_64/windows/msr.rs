// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use arch_gen::x86::msr_index::*;

use super::super::msr::{boot_msr_entries, Error};
use windows_sys::Win32::System::Hypervisor::*;

type Result<T> = std::result::Result<T, Error>;

/// Maps a CPU MSR index to the corresponding `WHV_REGISTER_NAME`.
///
/// Returns `None` for MSRs we don't need to map (e.g., `MSR_IA32_MISC_ENABLE`).
fn msr_to_whp_register(index: u32) -> Option<WHV_REGISTER_NAME> {
    let name = match index {
        MSR_IA32_SYSENTER_CS  => WHvX64RegisterSysenterCs,
        MSR_IA32_SYSENTER_ESP => WHvX64RegisterSysenterEsp,
        MSR_IA32_SYSENTER_EIP => WHvX64RegisterSysenterEip,
        MSR_STAR              => WHvX64RegisterStar,
        MSR_CSTAR             => WHvX64RegisterCstar,
        MSR_KERNEL_GS_BASE    => WHvX64RegisterKernelGsBase,
        MSR_SYSCALL_MASK      => WHvX64RegisterSfmask,
        MSR_LSTAR             => WHvX64RegisterLstar,
        MSR_IA32_TSC          => WHvX64RegisterTsc,
        MSR_MTRRdefType       => WHvX64RegisterMsrMtrrDefType,
        _ => return None,
    };
    Some(name)
}

/// Configure MSRs via the WHP API.
pub fn setup_msrs(vcpu: &whp::WhpVcpu) -> Result<()> {
    for (index, data) in boot_msr_entries() {
        if let Some(name) = msr_to_whp_register(index) {
            if let Err(e) = vcpu.set_reg64(name, data) {
                return Err(Error::SetMsrsWhp(e));
            }
        }
    }
    Ok(())
}
