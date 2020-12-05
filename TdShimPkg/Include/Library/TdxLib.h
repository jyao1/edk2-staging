/** @file
  Processor or Compiler specific defines and types x64 (Intel 64, AMD64).

  Copyright (c) 2006 - 2020, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials                          
  are licensed and made available under the terms and conditions of the BSD License         
  which accompanies this distribution.  The full text of the license may be found at        
  http://opensource.org/licenses/bsd-license.php                                            

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

**/

#ifndef _TDX_LIB_H_
#define _TDX_LIB_H_

#include <Library/BaseLib.h>
#include <Uefi/UefiBaseType.h>
#include <Library/DebugLib.h>
#include <Protocol/DebugSupport.h>

#define TDVMCALL_CHECK(NR,P1,P2,P3,P4,VAL, STATUS, FATAL) do { \
    (STATUS) = TdVmCall((NR), (P1), (P2), (P3), (P4), (VAL)); \
    if ((STATUS)) { \
        DEBUG((DEBUG_VERBOSE, "%a:%d: TDVMCALL (0x%x) (0x%x) received error (0x%x) from host\n", \
          __func__, __LINE__, (NR), (P3), (STATUS))); \
        if (FATAL) { \
          TdVmPanic(); \
        } \
    } \
} while(0)

#define TD_ACCEPT_PAGES(A,P) do { \
  TdAcceptPages ((A), (P)); \
  ZeroMem ((VOID *)((A)+1), ((P) * EFI_PAGE_SIZE)-1); \
} while(0)

VOID
EFIAPI
TdVmPanic (
  VOID
  );

UINT64
EFIAPI
TdVmCall (
  UINT64  Nr,
  UINT64  P1,
  UINT64  P2,
  UINT64  P3,
  UINT64  P4,
  UINT64  *Val
  );


UINT64
EFIAPI
TdInfo (
  UINT64  *Gpaw,
  UINT64  *TdAttributes,
  UINT64  *Vcpus,
  UINT64  *VcpuIndex,
  UINT64  *Dummy1,
  UINT64  *Dummy2
  );

UINT64
EFIAPI
TdExtendRtmr (
  UINT64  *Address,
  UINT64  RegisterIndex
  );

UINT64
EFIAPI
TdGetVeInfo (
  UINT64  *ExitReason,  // Rcx
  UINT64  *ExitQualification,  // Rdx
  UINT64  *GuestLinearAddress,  // R8
  UINT64  *GuestHostAddress,  // R9
  UINT64  *InstructionInfo  // R10
  );

UINT64
EFIAPI
TdVmCall_cpuid (
  UINT64  EaxIn,  // Rcx
  UINT64  EcxIn,  // Rdx
  UINT64  *Eax,  // R8
  UINT64  *Ebx,  // R9
  UINT64  *Ecx,  // R10
  UINT64  *Edx  // R10
  );

UINT64
EFIAPI
TdReport (
  UINT64  Report,  // Rcx
  UINT64  AdditionalData  // Rdx
  );

UINT64
EFIAPI
TdSetCpuidVe (
  UINT64  Flags  // Rcx
  );

UINT64
EFIAPI
TdAcceptPages (
  UINT64  PhysicalAddress,  // Rcx
  UINT64  NumberOfPages  // Rdx
  );

UINT64
EFIAPI
TdAddSharedPages (
  UINT64  PhysicalAddress,  // Rcx
  UINT64  NumberOfPages  // Rdx
  );

UINT64
EFIAPI
TdAddPrivatePages (
  UINT64  PhysicalAddress,  // Rcx
  UINT64  NumberOfPages  // Rdx
  );

/**
  Reads an 8-bit I/O port.

  Reads the 8-bit I/O port specified by Port. The 8-bit read value is returned.
  This function must guarantee that all I/O read and write operations are
  serialized.

  If 8-bit I/O port operations are not supported, then ASSERT().

  @param  Port  The I/O port to read.

  @return The value read.

**/
UINT8
EFIAPI
TdVmCall_inb (
  IN      UINTN                     Port
  );

/**
  Writes an 8-bit I/O port.

  Writes the 8-bit I/O port specified by Port with the value specified by Value
  and returns Value. This function must guarantee that all I/O read and write
  operations are serialized.

  If 8-bit I/O port operations are not supported, then ASSERT().

  @param  Port  The I/O port to write.
  @param  Value The value to write to the I/O port.

  @return The value written the I/O port.

**/
UINT8
EFIAPI
TdVmCall_outb (
  IN      UINTN                     Port,
  IN      UINT64                    Value
  );

/**
  Reads a 16-bit I/O port.

  Reads the 16-bit I/O port specified by Port. The 16-bit read value is returned.
  This function must guarantee that all I/O read and write operations are
  serialized.

  If 16-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 16-bit boundary, then ASSERT().

  @param  Port  The I/O port to read.

  @return The value read.

**/
UINT16
EFIAPI
TdVmCall_inw (
  IN      UINTN                     Port
  );

/**
  Writes a 16-bit I/O port.

  Writes the 16-bit I/O port specified by Port with the value specified by Value
  and returns Value. This function must guarantee that all I/O read and write
  operations are serialized.

  If 16-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 16-bit boundary, then ASSERT().

  @param  Port  The I/O port to write.
  @param  Value The value to write to the I/O port.

  @return The value written the I/O port.

**/
UINT16
EFIAPI
TdVmCall_outw (
  IN      UINTN                     Port,
  IN      UINT64                    Value
  );

/**
  Reads a 32-bit I/O port.

  Reads the 32-bit I/O port specified by Port. The 32-bit read value is returned.
  This function must guarantee that all I/O read and write operations are
  serialized.

  If 32-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 32-bit boundary, then ASSERT().

  @param  Port  The I/O port to read.

  @return The value read.

**/
UINT32
EFIAPI
TdVmCall_inl (
  IN      UINTN                     Port
  );

/**
  Writes a 32-bit I/O port.

  Writes the 32-bit I/O port specified by Port with the value specified by Value
  and returns Value. This function must guarantee that all I/O read and write
  operations are serialized.

  If 32-bit I/O port operations are not supported, then ASSERT().
  If Port is not aligned on a 32-bit boundary, then ASSERT().

  @param  Port  The I/O port to write.
  @param  Value The value to write to the I/O port.

  @return The value written the I/O port.

**/
UINT32
EFIAPI
TdVmCall_outl (
  IN      UINTN                     Port,
  IN      UINT64                    Value
  );

VOID
EFIAPI
TdxVirtualizationExceptionHandler(
  IN EFI_EXCEPTION_TYPE   InterruptType,
  IN EFI_SYSTEM_CONTEXT   SystemContext
  );


#endif

