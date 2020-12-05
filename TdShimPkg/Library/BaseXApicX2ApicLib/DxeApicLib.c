/** @file
  Local APIC Library.

  This local APIC library instance supports x2APIC capable processors
  which have xAPIC and x2APIC modes.

  Copyright (c) 2010 - 2019, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2017, AMD Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Register/Intel/Cpuid.h>
#include <Register/Amd/Cpuid.h>
#include <Register/Intel/Msr.h>
#include <Register/Intel/LocalApic.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/LocalApicLib.h>
#include <Library/IoLib.h>
#include <Library/TimerLib.h>
#include <Library/PcdLib.h>

#include <PiDxe.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Cpu.h>

BOOLEAN mUseTdvmcall = FALSE;
BOOLEAN mMsrAccessInitialized = FALSE;


BOOLEAN
EFIAPI
InitializeMsrAccess (
  VOID
  )
{
  EFI_STATUS                         Status;
  EFI_CPU_ARCH_PROTOCOL             *Cpu;

  //
  // We can't handle #ve until after the Cpu Arch Protocol has been installed
  // When using the performance counters, it can cause apic access before this
  // protocol is enabled.
  // 
  if (!mMsrAccessInitialized) {
    mUseTdvmcall = PcdGetBool (PcdUseTdxMsr);
    if (mUseTdvmcall) {
        mMsrAccessInitialized = TRUE;
    } else {
      Status = gBS->LocateProtocol (&gEfiCpuArchProtocolGuid, NULL, (VOID **) &Cpu);
      if (!EFI_ERROR (Status)) {
        mMsrAccessInitialized = TRUE;
      } else {
        mUseTdvmcall = TRUE;
      }
    }
  }
  return mUseTdvmcall;
}
