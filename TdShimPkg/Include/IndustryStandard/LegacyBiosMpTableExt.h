/*++
  Define MP table extension for TDX shim.

  Add MP wakeup structure.

  It is for non-ACPI platform only. ACPI platform should use MADT extension for MP wakeup structure.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

--*/

#ifndef _LEGACY_BIOS_MPTABLE_EXT_H_
#define _LEGACY_BIOS_MPTABLE_EXT_H_

#include <IndustryStandard/LegacyBiosMpTable.h>

#define EFI_LEGACY_MP_TABLE_REV_1_5 0x05

#pragma pack(1)

//
// Entry Type 5: MP Wakeup structure.
//
#define EFI_LEGACY_MP_TABLE_ENTRY_TYPE_MP_WAKEUP 0x05

typedef struct {
  UINT8  EntryType;
  UINT8  EntryLength;
  UINT16 MailBoxVersion;
  UINT32 Reserved;
  //
  // Physical address of the mailbox.
  // It must be in ACPINvs.
  // It must be 4K bytes aligned.
  //
  UINT64 MailBoxAddress;
} EFI_LEGACY_MP_TABLE_ENTRY_MP_WAKEUP;

#define EFI_LEGACY_MP_TABLE_ENTRY_MP_WAKEUP_MAILBOX_VERSION    0

typedef struct {
  UINT16 Command;
  UINT16 Reserved;
  UINT32 ApicId;
  //
  // The wakeup address for application processor(s).
  // For Intel processor, the execution environment is:
  // * Interrupts must be disabled.
  // * RFLAGES.IF set to 0.
  // * Long mode enabled.
  // * Paging mode is enabled and physical memory for waking vector is identity mapped
  //   (virtual address equals physical address).
  // * Waking vector must be contained within one physical page.
  // * Selectors are set to flat and otherwise not used.
  //
  UINT64 WakeupVector;
  UINT8  ReservedForOs[2032];
  UINT8  ReservedForFirmware[2048];
} EFI_LEGACY_MP_TABLE_ENTRY_MP_WAKEUP_MAILBOX;

#define EFI_LEGACY_MP_TABLE_ENTRY_MP_WAKEUP_MAILBOX_COMMAND_NOOP    0
#define EFI_LEGACY_MP_TABLE_ENTRY_MP_WAKEUP_MAILBOX_COMMAND_WAKEUP  1

#pragma pack()

#endif
