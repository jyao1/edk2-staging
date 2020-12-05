/** @file
  EFI Memory Encryption Library.

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/


#ifndef __MEMORY_ENCRYPT_H__
#define __MEMORY_ENCRYPT_H__

/**
  Returns a boolean to indicate whether memory encryption is enabled

  @retval TRUE           Memory Encryption is enabled
  @retval FALSE          Memory Encryption is not enabled
**/
BOOLEAN
EFIAPI
MemEncryptIsEnabled (
  VOID
  );

/**
  This function sets memory encryption for the memory region specified by
  BaseAddress and NumPages from the current page table context.

  @param[in]  Cr3BaseAddress          Cr3 Base Address (if zero then use
                                      current CR3)
  @param[in]  BaseAddress             The physical address that is the start
                                      address of a memory region.
  @param[in]  NumPages                The number of pages from start memory
                                      region.
  @param[in]  Flush                   Flush the caches before setting encryption
  @param[in]  ShouldZero              Address range should be zero-ed after
  	  	  	  	  	  	  	  	  	  enabling encryption, if not handled
  	  	  	  	  	  	  	  	  	  automatically

  @retval RETURN_SUCCESS              The attributes were set for the
                                      memory region.
  @retval RETURN_INVALID_PARAMETER    Number of pages is zero.
  @retval RETURN_UNSUPPORTED          Setting the memory encryption attribute
                                      is not supported
**/
RETURN_STATUS
EFIAPI
SetMemoryEncryption (
  IN PHYSICAL_ADDRESS                          Cr3BaseAddress,
  IN PHYSICAL_ADDRESS                          BaseAddress,
  IN UINTN                                     NumPages,
  IN BOOLEAN                                   Flush,
  IN BOOLEAN                                   ShouldZero
  );

/**
  This function clears memory encryption for the memory region specified by
  BaseAddress and NumPages from the current page table context.

  @param[in]  Cr3BaseAddress          Cr3 Base Address (if zero then use
                                      current CR3)
  @param[in]  BaseAddress             The physical address that is the start
                                      address of a memory region.
  @param[in]  NumPages                The number of pages from start memory
                                      region.
  @param[in]  Flush                   Flush the caches before clearing encryption

  @retval RETURN_SUCCESS              The attributes were cleared for the
                                      memory region.
  @retval RETURN_INVALID_PARAMETER    Number of pages is zero.
  @retval RETURN_UNSUPPORTED          Clearing the memory encryption attribute
                                      is not supported
**/
RETURN_STATUS
EFIAPI
ClearMemoryEncryption (
  IN PHYSICAL_ADDRESS                          Cr3BaseAddress,
  IN PHYSICAL_ADDRESS                          BaseAddress,
  IN UINTN                                     NumPages,
  IN BOOLEAN                                   Flush
  );

#endif
