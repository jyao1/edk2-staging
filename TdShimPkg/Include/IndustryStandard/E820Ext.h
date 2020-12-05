/*++
  Define E820 table extension.

  Add Unaccepted memory.

  It is for non-UEFI platform only. UEFI platform should use UEFI memory map.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

--*/

#ifndef __E820_EXT_H__
#define __E820_EXT_H__

#include <IndustryStandard/E820.h>

#pragma pack(1)

typedef enum {
  //
  // A memory region that represents unaccepted memory, that must
  // be accepted by the guest before it can be used.
  // Unless otherwise noted, all other EFI memory types are accepted. 
  //
  AddressRangeUnaccepted       = 8
} EFI_ACPI_MEMORY_EXT_TYPE;

#define EFI_LEGACY_E820_TABLE_FLOATING_POINTER_SIGNATURE  SIGNATURE_32 ('_', 'E', '8', '_')
typedef struct {
  UINT32  Signature;
  UINT8   Length;
  // Revision for this structure
  UINT8   Revision;
  UINT8   Checksum;
  // Revision for the E820 table (specified by E820Length/E820Address)
  UINT8   SpecRevision;
  UINT32  Reserved;
  UINT32  E820Length;
  // It must be in ACPI NVS area.
  UINT64  E820Address;
} EFI_LEGACY_E820_TABLE_FLOATING_POINTER;

#define EFI_LEGACY_E820_TABLE_FLOATING_POINTER_REVISION 0

#define EFI_LEGACY_E820_TABLE_FLOATING_POINTER_SPEC_REVISION 1

#pragma pack()

#endif
