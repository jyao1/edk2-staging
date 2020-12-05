/** @file
  I/O Library. This file has compiler specifics for GCC as there is no
  ANSI C standard for doing IO.

  Copyright (c) 2006 - 2020, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include "TdxIoLibIntrinsicInternal.h"

STATIC BOOLEAN mIoTdxEnable = FALSE;
STATIC BOOLEAN mMmioTdxEnable = FALSE;
STATIC BOOLEAN mInitialized = FALSE;


BOOLEAN
EFIAPI
TdxSupported (
  BOOLEAN Mmio
  )
{

  if (!mInitialized) {
    mMmioTdxEnable = FixedPcdGetBool(PcdUseTdxMmio);
    mIoTdxEnable = FixedPcdGetBool(PcdUseTdxIo);
    mInitialized = TRUE;
  }

  if (Mmio) {
    return mMmioTdxEnable;
  }
  return mIoTdxEnable;
}
