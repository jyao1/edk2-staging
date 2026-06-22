/** @file
  This module implements measuring PeCoff image for Tcg2 Protocol.

  Caution: This file requires additional review when modified.
  This driver will have external input - PE/COFF image.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.

Copyright (c) 2015 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PeCoffLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/HashLib.h>

#include "PeImageHash.h"

UINTN  mTcg2DxeImageSize = 0;

/**
  PeCoffImageHashData() callback that feeds a HashLib hash handle.

  @param[in]  HashContext  Pointer to the HASH_HANDLE to update.
  @param[in]  Data         Pointer to the data region to hash.
  @param[in]  DataSize     Size of Data in bytes.

  @retval EFI_SUCCESS  The region was added to the hash sequence.
  @retval Other        The HashLib update failed; status returned verbatim.

**/
STATIC
EFI_STATUS
EFIAPI
HashPeImageRegion (
  IN VOID   *HashContext,
  IN UINT8  *Data,
  IN UINTN  DataSize
  )
{
  return HashUpdate (*(HASH_HANDLE *)HashContext, Data, DataSize);
}

/**
  Reads contents of a PE/COFF image in memory buffer.

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will make sure the PE/COFF image content
  read is within the image buffer.

  @param  FileHandle      Pointer to the file handle to read the PE/COFF image.
  @param  FileOffset      Offset into the PE/COFF image to begin the read operation.
  @param  ReadSize        On input, the size in bytes of the requested read operation.
                          On output, the number of bytes actually read.
  @param  Buffer          Output buffer that contains the data read from the PE/COFF image.

  @retval EFI_SUCCESS     The specified portion of the PE/COFF image was read and the size
**/
EFI_STATUS
EFIAPI
Tcg2DxeImageRead (
  IN     VOID   *FileHandle,
  IN     UINTN  FileOffset,
  IN OUT UINTN  *ReadSize,
  OUT    VOID   *Buffer
  )
{
  UINTN  EndPosition;

  if ((FileHandle == NULL) || (ReadSize == NULL) || (Buffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (MAX_ADDRESS - FileOffset < *ReadSize) {
    return EFI_INVALID_PARAMETER;
  }

  EndPosition = FileOffset + *ReadSize;
  if (EndPosition > mTcg2DxeImageSize) {
    *ReadSize = (UINT32)(mTcg2DxeImageSize - FileOffset);
  }

  if (FileOffset >= mTcg2DxeImageSize) {
    *ReadSize = 0;
  }

  CopyMem (Buffer, (UINT8 *)((UINTN)FileHandle + FileOffset), *ReadSize);

  return EFI_SUCCESS;
}

/**
  Measure PE image into TPM log based on the authenticode image hashing in
  PE/COFF Specification 8.0 Appendix A.

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will validate its data structure
  within this image buffer before use.

  Notes: PE/COFF image is checked by BasePeCoffLib PeCoffLoaderGetImageInfo().

  @param[in]  PCRIndex       TPM PCR index
  @param[in]  ImageAddress   Start address of image buffer.
  @param[in]  ImageSize      Image size
  @param[out] DigestList     Digest list of this image.

  @retval EFI_SUCCESS            Successfully measure image.
  @retval EFI_OUT_OF_RESOURCES   No enough resource to measure image.
  @retval other error value
**/
EFI_STATUS
MeasurePeImageAndExtend (
  IN  UINT32                PCRIndex,
  IN  EFI_PHYSICAL_ADDRESS  ImageAddress,
  IN  UINTN                 ImageSize,
  OUT TPML_DIGEST_VALUES    *DigestList
  )
{
  EFI_STATUS                           Status;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  UINT32                               PeCoffHeaderOffset;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  HASH_HANDLE                          HashHandle;
  PE_COFF_LOADER_IMAGE_CONTEXT         ImageContext;

  HashHandle = 0xFFFFFFFF; // Know bad value

  //
  // Check PE/COFF image
  //
  ZeroMem (&ImageContext, sizeof (ImageContext));
  ImageContext.Handle    = (VOID *)(UINTN)ImageAddress;
  mTcg2DxeImageSize      = ImageSize;
  ImageContext.ImageRead = (PE_COFF_LOADER_READ_FILE)Tcg2DxeImageRead;

  //
  // Get information about the image being loaded
  //
  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    //
    // The information can't be got from the invalid PeImage
    //
    DEBUG ((DEBUG_INFO, "Tcg2Dxe: PeImage invalid. Cannot retrieve image information.\n"));
    goto Finish;
  }

  DosHdr             = (EFI_IMAGE_DOS_HEADER *)(UINTN)ImageAddress;
  PeCoffHeaderOffset = 0;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  }

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINT8 *)(UINTN)ImageAddress + PeCoffHeaderOffset);
  if (Hdr.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    Status = EFI_UNSUPPORTED;
    goto Finish;
  }

  //
  // PE/COFF Image Measurement
  //
  //    NOTE: The image hashing follows the authenticode image hashing in PE/COFF
  //      Specification 8.0 Appendix A. The image traversal lives in the shared
  //      PeCoffImageHashData() (PeImageHash.c, byte-identical with
  //      DxeImageVerificationLib); here it is driven through HashLib so the
  //      bytes are hashed into every active PCR bank and extended to the TPM.
  //

  // 1.  Load the image header into memory.
  // 2.  Initialize a SHA hash context.
  Status = HashStart (&HashHandle);
  if (EFI_ERROR (Status)) {
    goto Finish;
  }

  //
  // 3 - 16. Hash the image regions in Authenticode order via the shared
  //         traversal, feeding each region to HashLib (HashPeImageRegion).
  //
  Status = PeCoffImageHashData (
             (UINT8 *)(UINTN)ImageAddress,
             ImageSize,
             HashPeImageRegion,
             &HashHandle
             );
  if (EFI_ERROR (Status)) {
    goto Finish;
  }

  //
  // 17. Finalize the hash and extend the result to PCRIndex.
  //
  Status = HashCompleteAndExtend (HashHandle, PCRIndex, NULL, 0, DigestList);
  if (EFI_ERROR (Status)) {
    goto Finish;
  }

Finish:
  return Status;
}
