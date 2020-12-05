/** @file
  Linux Boot Payload

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

/**
  Main entry point to DXE Core.

  @param  HobStart               Pointer to the beginning of the HOB List from PEI.

  @return This function should never return.

**/
VOID
EFIAPI
PayloadMain (
  IN  VOID *HobStart
  )
{
  DEBUG ((DEBUG_INFO, "Linux PayloadMain enter\n"));

  //
  // 1. Prepare MP table
  // 2. Parepare TD Event Log
  // 3. Prepare E820 Table
  //
  // 4. Prepare BootParameter
  // 5. Jump to kernel EFI_HANDOVER
  //

  CpuDeadLoop();
  return ;
}