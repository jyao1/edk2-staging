/** @file
  Main SEC MetaData

  Copyright (c) 2008, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TdShimIpl.h"

tdvf_metadata_t  mTdShimMetadata = {
   .guid                = EFI_METADATA_GUID,
   .mailbox_base_address = (UINTN)FixedPcdGet64(PcdTdMailboxBase),
   .mailbox_size        = (UINTN)FixedPcdGet64(PcdTdMailboxSize),
   .hob_base_address    = (UINTN)FixedPcdGet64(PcdTdHobBase),
   .hob_size            = (UINTN)FixedPcdGet64(PcdTdHobSize),
   .stack_base_address  = (UINTN)FixedPcdGet64(PcdTempStackBase),
   .stack_size          = (UINTN)FixedPcdGet64(PcdTempStackSize),
   .heap_base_address   = (UINTN)FixedPcdGet64(PcdTempRamBase),
   .heap_size           = (UINTN)FixedPcdGet64(PcdTempRamSize),
   .bfv_base_address    = (UINTN)FixedPcdGet32(PcdBfvBase),
   .bfv_size            = (UINT32)FixedPcdGet32(PcdBfvSize),
   .rsvd                = 0,
   .sig                 = SIGNATURE_32('T','D','V','F')
 };

/**
  Make any runtime modifications to the metadata structure
**/
tdvf_metadata_t *
EFIAPI
InitializeMetaData(
  VOID  
  )
{
  // 
  // mTdShimMetadata stores the fixed information
  // Referenced here to make sure it is not optimized
  if(mTdShimMetadata.rsvd == 0)
    mTdShimMetadata.rsvd = 1;

  return &mTdShimMetadata;
}

