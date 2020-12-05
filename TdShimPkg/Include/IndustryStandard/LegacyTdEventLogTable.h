/*++
  Define TD event log table for TDX shim.

  It is for non-ACPI platform only. ACPI platform should use ACPI TDEL table.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

--*/

#ifndef _LEGACY_TD_EVENT_LOG_TABLE_H_
#define _LEGACY_TD_EVENT_LOG_TABLE_H_

#pragma pack(1)

#define EFI_LEGACY_TD_EVENT_LOG_TABLE_FLOATING_POINTER_SIGNATURE  SIGNATURE_32 ('_', 'T', 'D', '_')
typedef struct {
  UINT32  Signature;
  UINT8   Length;
  // Revision for this structure
  UINT8   Revision;
  UINT8   Checksum;
  // Revision for the TD Event Log (specified by LAML/LASA)
  UINT8   SpecRevision;
  UINT32  Reserved;
  // Log Area Minimum Length
  UINT32  Laml;
  // Log Area Start Address
  // It must be in ACPI NVS area.
  UINT64  Lasa;
} EFI_LEGACY_TD_EVENT_LOG_TABLE_FLOATING_POINTER;

#define EFI_LEGACY_TD_EVENT_LOG_TABLE_FLOATING_POINTER_REVISION 0

#define EFI_LEGACY_TD_EVENT_LOG_TABLE_FLOATING_POINTER_SPEC_REVISION 1

#pragma pack()

#endif
