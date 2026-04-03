// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Model Specific Registers (MSRs) related functionality.
use std::result;

use arch_gen::x86::msr_index::*;

#[derive(Debug)]
/// MSR related errors.
pub enum Error {
    #[cfg(target_os = "linux")]
    /// Getting supported MSRs failed.
    GetSupportedModelSpecificRegisters(kvm_ioctls::Error),
    #[cfg(target_os = "linux")]
    /// Setting up MSRs failed.
    SetModelSpecificRegisters(kvm_ioctls::Error),
    /// Failed to set all MSRs.
    SetModelSpecificRegistersCount,
    #[cfg(target_os = "windows")]
    /// Setting up MSRs via WHP failed.
    SetMsrsWhp(whp::Error),
}

type Result<T> = result::Result<T, Error>;

// Re-export platform-specific MSR setup functions.
#[cfg(target_os = "linux")]
pub use super::linux::msr::*;
#[cfg(target_os = "windows")]
pub use super::windows::msr::*;

/// MSR range
struct MsrRange {
    /// Base MSR address
    base: u32,
    /// Number of MSRs
    nmsrs: u32,
}

impl MsrRange {
    /// Returns whether `msr` is contained in this MSR range.
    fn contains(&self, msr: u32) -> bool {
        self.base <= msr && msr < self.base + self.nmsrs
    }
}

/// Base MSR for APIC
const APIC_BASE_MSR: u32 = 0x800;

/// Number of APIC MSR indexes
const APIC_MSR_INDEXES: u32 = 0x400;

/// Custom MSRs fall in the range 0x4b564d00-0x4b564dff
const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b56_4d00;
const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;
const MSR_KVM_ASYNC_PF_EN: u32 = 0x4b56_4d02;
const MSR_KVM_STEAL_TIME: u32 = 0x4b56_4d03;
const MSR_KVM_PV_EOI_EN: u32 = 0x4b56_4d04;

/// Taken from arch/x86/include/asm/msr-index.h
const MSR_IA32_SPEC_CTRL: u32 = 0x0000_0048;
const MSR_IA32_PRED_CMD: u32 = 0x0000_0049;

// Creates a MsrRange of one msr given as argument.
macro_rules! SINGLE_MSR {
    ($msr:expr) => {
        MsrRange {
            base: $msr,
            nmsrs: 1,
        }
    };
}

// Creates a MsrRange of with msr base and count given as arguments.
macro_rules! MSR_RANGE {
    ($first:expr, $count:expr) => {
        MsrRange {
            base: $first,
            nmsrs: $count,
        }
    };
}

// List of MSRs that can be serialized. List is sorted in ascending order of MSRs addresses.
static WHITELISTED_MSR_RANGES: &[MsrRange] = &[
    SINGLE_MSR!(MSR_IA32_P5_MC_ADDR),
    SINGLE_MSR!(MSR_IA32_P5_MC_TYPE),
    SINGLE_MSR!(MSR_IA32_TSC),
    SINGLE_MSR!(MSR_IA32_PLATFORM_ID),
    SINGLE_MSR!(MSR_IA32_APICBASE),
    SINGLE_MSR!(MSR_IA32_EBL_CR_POWERON),
    SINGLE_MSR!(MSR_EBC_FREQUENCY_ID),
    SINGLE_MSR!(MSR_SMI_COUNT),
    SINGLE_MSR!(MSR_IA32_FEATURE_CONTROL),
    SINGLE_MSR!(MSR_IA32_TSC_ADJUST),
    SINGLE_MSR!(MSR_IA32_SPEC_CTRL),
    SINGLE_MSR!(MSR_IA32_PRED_CMD),
    SINGLE_MSR!(MSR_IA32_UCODE_WRITE),
    SINGLE_MSR!(MSR_IA32_UCODE_REV),
    SINGLE_MSR!(MSR_IA32_SMBASE),
    SINGLE_MSR!(MSR_FSB_FREQ),
    SINGLE_MSR!(MSR_PLATFORM_INFO),
    SINGLE_MSR!(MSR_PKG_CST_CONFIG_CONTROL),
    SINGLE_MSR!(MSR_IA32_MPERF),
    SINGLE_MSR!(MSR_IA32_APERF),
    SINGLE_MSR!(MSR_MTRRcap),
    SINGLE_MSR!(MSR_IA32_BBL_CR_CTL3),
    SINGLE_MSR!(MSR_IA32_SYSENTER_CS),
    SINGLE_MSR!(MSR_IA32_SYSENTER_ESP),
    SINGLE_MSR!(MSR_IA32_SYSENTER_EIP),
    SINGLE_MSR!(MSR_IA32_MCG_CAP),
    SINGLE_MSR!(MSR_IA32_MCG_STATUS),
    SINGLE_MSR!(MSR_IA32_MCG_CTL),
    SINGLE_MSR!(MSR_IA32_PERF_STATUS),
    SINGLE_MSR!(MSR_IA32_MISC_ENABLE),
    SINGLE_MSR!(MSR_MISC_FEATURE_CONTROL),
    SINGLE_MSR!(MSR_MISC_PWR_MGMT),
    SINGLE_MSR!(MSR_TURBO_RATIO_LIMIT),
    SINGLE_MSR!(MSR_TURBO_RATIO_LIMIT1),
    SINGLE_MSR!(MSR_IA32_DEBUGCTLMSR),
    SINGLE_MSR!(MSR_IA32_LASTBRANCHFROMIP),
    SINGLE_MSR!(MSR_IA32_LASTBRANCHTOIP),
    SINGLE_MSR!(MSR_IA32_LASTINTFROMIP),
    SINGLE_MSR!(MSR_IA32_LASTINTTOIP),
    SINGLE_MSR!(MSR_IA32_POWER_CTL),
    MSR_RANGE!(
        // IA32_MTRR_PHYSBASE0
        0x200, 0x100
    ),
    MSR_RANGE!(
        // MSR_CORE_C3_RESIDENCY
        // MSR_CORE_C6_RESIDENCY
        // MSR_CORE_C7_RESIDENCY
        MSR_CORE_C3_RESIDENCY,
        3
    ),
    MSR_RANGE!(MSR_IA32_MC0_CTL, 0x80),
    SINGLE_MSR!(MSR_RAPL_POWER_UNIT),
    MSR_RANGE!(
        // MSR_PKGC3_IRTL
        // MSR_PKGC6_IRTL
        // MSR_PKGC7_IRTL
        MSR_PKGC3_IRTL,
        3
    ),
    SINGLE_MSR!(MSR_PKG_POWER_LIMIT),
    SINGLE_MSR!(MSR_PKG_ENERGY_STATUS),
    SINGLE_MSR!(MSR_PKG_PERF_STATUS),
    SINGLE_MSR!(MSR_PKG_POWER_INFO),
    SINGLE_MSR!(MSR_DRAM_POWER_LIMIT),
    SINGLE_MSR!(MSR_DRAM_ENERGY_STATUS),
    SINGLE_MSR!(MSR_DRAM_PERF_STATUS),
    SINGLE_MSR!(MSR_DRAM_POWER_INFO),
    SINGLE_MSR!(MSR_CONFIG_TDP_NOMINAL),
    SINGLE_MSR!(MSR_CONFIG_TDP_LEVEL_1),
    SINGLE_MSR!(MSR_CONFIG_TDP_LEVEL_2),
    SINGLE_MSR!(MSR_CONFIG_TDP_CONTROL),
    SINGLE_MSR!(MSR_TURBO_ACTIVATION_RATIO),
    SINGLE_MSR!(MSR_IA32_TSCDEADLINE),
    MSR_RANGE!(APIC_BASE_MSR, APIC_MSR_INDEXES),
    SINGLE_MSR!(MSR_IA32_BNDCFGS),
    SINGLE_MSR!(MSR_KVM_WALL_CLOCK_NEW),
    SINGLE_MSR!(MSR_KVM_SYSTEM_TIME_NEW),
    SINGLE_MSR!(MSR_KVM_ASYNC_PF_EN),
    SINGLE_MSR!(MSR_KVM_STEAL_TIME),
    SINGLE_MSR!(MSR_KVM_PV_EOI_EN),
    SINGLE_MSR!(MSR_EFER),
    SINGLE_MSR!(MSR_STAR),
    SINGLE_MSR!(MSR_LSTAR),
    SINGLE_MSR!(MSR_CSTAR),
    SINGLE_MSR!(MSR_SYSCALL_MASK),
    SINGLE_MSR!(MSR_FS_BASE),
    SINGLE_MSR!(MSR_GS_BASE),
    SINGLE_MSR!(MSR_KERNEL_GS_BASE),
    SINGLE_MSR!(MSR_TSC_AUX),
];

/// Specifies whether a particular MSR should be included in vcpu serialization.
///
/// # Arguments
///
/// * `index` - The index of the MSR that is checked whether it's needed for serialization.
pub fn msr_should_serialize(index: u32) -> bool {
    // Blacklisted MSRs not exported by Linux: IA32_FEATURE_CONTROL and IA32_MCG_CTL
    if index == MSR_IA32_FEATURE_CONTROL || index == MSR_IA32_MCG_CTL {
        return false;
    };
    WHITELISTED_MSR_RANGES
        .iter()
        .any(|range| range.contains(index))
}

/// IA32_MTRR_DEF_TYPE MSR: E (MTRRs enabled) flag, bit 11
pub const MTRR_ENABLE: u64 = 0x800;
/// Mem type WB
pub const MTRR_MEM_TYPE_WB: u64 = 0x6;

/// Returns the boot MSR entries as hypervisor-agnostic (index, value) pairs.
pub fn boot_msr_entries() -> Vec<(u32, u64)> {
    vec![
        (MSR_IA32_SYSENTER_CS, 0x0),
        (MSR_IA32_SYSENTER_ESP, 0x0),
        (MSR_IA32_SYSENTER_EIP, 0x0),
        // x86_64 specific msrs, we only run on x86_64 not x86.
        (MSR_STAR, 0x0),
        (MSR_CSTAR, 0x0),
        (MSR_KERNEL_GS_BASE, 0x0),
        (MSR_SYSCALL_MASK, 0x0),
        (MSR_LSTAR, 0x0),
        // end of x86_64 specific code
        (MSR_IA32_TSC, 0x0),
        (MSR_IA32_MISC_ENABLE, u64::from(MSR_IA32_MISC_ENABLE_FAST_STRING)),
        (MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msr_whitelist() {
        for range in WHITELISTED_MSR_RANGES.iter() {
            for msr in range.base..(range.base + range.nmsrs) {
                let should = !matches!(msr, MSR_IA32_FEATURE_CONTROL | MSR_IA32_MCG_CTL);
                assert_eq!(msr_should_serialize(msr), should);
            }
        }
    }
}
