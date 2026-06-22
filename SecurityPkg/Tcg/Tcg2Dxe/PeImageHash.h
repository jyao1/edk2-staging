/** @file
  Authenticode PE/COFF image hashing helper.

  Declares PeCoffImageHashData(), a crypto-library-agnostic, callback-based
  traversal of a PE/COFF image in Authenticode order. The caller supplies the
  hash sink, so the same file is shared byte-identically between consumers that
  hash with different back ends (DxeImageVerificationLib, Tcg2Dxe). See
  PeImageHash.c for details.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef PE_IMAGE_HASH_H_
#define PE_IMAGE_HASH_H_

#include <Uefi.h>

/**
  Callback invoked by PeCoffImageHashData() on each PE/COFF region that
  participates in the image hash, in Authenticode order.

  @param[in]  HashContext  Opaque context supplied to PeCoffImageHashData().
  @param[in]  Data         Pointer to the region to hash.
  @param[in]  DataSize     Size of Data in bytes.

  @retval EFI_SUCCESS  The region was consumed; continue the traversal.
  @retval Other        Abort the traversal; the status is returned to the caller.

**/
typedef
EFI_STATUS
(EFIAPI *PE_COFF_HASH_UPDATE) (
  IN VOID   *HashContext,
  IN UINT8  *Data,
  IN UINTN  DataSize
  );

/**
  Walk a PE/COFF image in Authenticode order (PE/COFF Specification 8.0,
  Appendix A) and invoke HashUpdate() on each region that participates in the
  image hash, in order. The caller owns the hash sink; this function performs no
  cryptography and does not initialize or finalize the hash.

  @param[in]  ImageBase     Pointer to the start of the PE/COFF image buffer.
  @param[in]  ImageSize     Size of the image buffer in bytes.
  @param[in]  HashUpdate    Callback invoked on each region to be hashed.
  @param[in]  HashContext   Opaque context passed through to HashUpdate().

  @retval EFI_SUCCESS            All regions were enumerated to HashUpdate().
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL or ImageSize is 0.
  @retval EFI_UNSUPPORTED        The image is not a valid PE/COFF image, or its
                                 layout is inconsistent.
  @retval EFI_OUT_OF_RESOURCES   A temporary allocation failed.
  @retval Other                  HashUpdate() returned an error; returned verbatim.

**/
EFI_STATUS
PeCoffImageHashData (
  IN  UINT8                *ImageBase,
  IN  UINTN                ImageSize,
  IN  PE_COFF_HASH_UPDATE  HashUpdate,
  IN  VOID                 *HashContext
  );

#endif // PE_IMAGE_HASH_H_
