/** @file

  Stateless fw_cfg library implementation.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseLib.h>
#include <Uefi/UefiBaseType.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Uefi/UefiMultiPhase.h>
#include <Pi/PiBootMode.h>
#include <Pi/PiHob.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/TdvfPlatformLib.h>

#ifdef TODO

static UINT8
EFIAPI
CmosRead8 (
  IN      UINTN                     Index
  )
{
  IoWrite8 (0x70, (UINT8) Index);
  return IoRead8 (0x71);
}

static UINT32
GetSystemMemorySizeBelow4gb (
  VOID
  )
{
  UINT8 Cmos0x34;
  UINT8 Cmos0x35;
  Cmos0x34 = (UINT8) CmosRead8 (0x34);
  Cmos0x35 = (UINT8) CmosRead8 (0x35);
  return (UINT32) (((UINTN)((Cmos0x35 << 8) + Cmos0x34) << 16) + SIZE_16MB);
}

UINT8
GetPhysicalAddressBits (
  VOID
  )
{
  UINT32                        RegEax;
  UINT8                         PhysicalAddressBits;

  //
  // Get physical address bits supported.
  //
  AsmCpuid (0x80000000, &RegEax, NULL, NULL, NULL);
  if (RegEax >= 0x80000008) {
    AsmCpuid (0x80000008, &RegEax, NULL, NULL, NULL);
    PhysicalAddressBits = (UINT8) RegEax;
  } else {
    PhysicalAddressBits = 36;
  }

  //
  // IA-32e paging translates 48-bit linear addresses to 52-bit physical addresses.
  //
  ASSERT (PhysicalAddressBits <= 52);
  if (PhysicalAddressBits > 48) {
    PhysicalAddressBits = 48;
  }
  return PhysicalAddressBits;
}

#endif

VOID
EFIAPI
TdvfPlatformInitialize(
  IN OUT EFI_HOB_PLATFORM_INFO *PlatformInfo
)
{
#ifdef TODO
  EFI_PHYSICAL_ADDRESS TdxSharedPage;
  UINT32 LowerMemorySize = GetSystemMemorySizeBelow4gb ();
  DEBUG((DEBUG_INFO, "LowerMemorySize : %llx \n", LowerMemorySize - BASE_1MB));
  BuildCpuHob (GetPhysicalAddressBits(), 0x10);

  BuildResourceDescriptorHob (
    EFI_RESOURCE_SYSTEM_MEMORY,
    EFI_RESOURCE_ATTRIBUTE_PRESENT |
    EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
    EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE |
    EFI_RESOURCE_ATTRIBUTE_TESTED,
    BASE_1MB, 
    (UINT64)(LowerMemorySize - BASE_1MB));

  BuildResourceDescriptorHob (
    EFI_RESOURCE_SYSTEM_MEMORY,
    EFI_RESOURCE_ATTRIBUTE_PRESENT |
    EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
    EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE |
    EFI_RESOURCE_ATTRIBUTE_TESTED,
    0,
    BASE_512KB + BASE_128KB);

  TdxSharedPage = (EFI_PHYSICAL_ADDRESS)AllocatePages(1);
  BuildMemoryAllocationHob(TdxSharedPage, EFI_PAGE_SIZE, EfiACPIMemoryNVS);
#endif
}

