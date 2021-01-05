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

UINT64
EFIAPI
TdReport (
  UINT64  Report,  // Rcx
  UINT64  AdditionalData  // Rdx
  );

UINT64
EFIAPI
TdAcceptPages (
  UINT64  PhysicalAddress,  // Rcx
  UINT64  NumberOfPages  // Rdx
  );

EFI_STATUS
EFIAPI
TdCall(
  IN UINT64           Leaf,
  IN UINT64           Arg1,
  IN UINT64           Arg2,
  IN UINT64           Arg3,
  IN VOID             *Results
  );

EFI_STATUS
EFIAPI
TdVmCall (
  IN UINT64          Leaf,
  IN UINT64          Arg1,
  IN UINT64          Arg2,
  IN UINT64          Arg3,
  IN UINT64          Arg4,
  IN VOID           *Results
  );

EFI_STATUS
EFIAPI
TdVmCall_cpuid (
  IN UINT64         Eax,
  IN UINT64         Ecx,
  VOID              *Results
  );

#endif

