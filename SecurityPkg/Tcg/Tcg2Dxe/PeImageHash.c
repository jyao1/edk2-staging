/** @file
  Authenticode PE/COFF image hashing, factored out of DxeImageVerificationLib.

  PeCoffImageHashData() walks a PE/COFF image in the order defined by the
  Authenticode image hashing rules (PE/COFF Specification 8.0, Appendix A) and
  invokes a caller-supplied callback on each region that participates in the
  hash, in order. The caller owns the hash sink (a BaseCryptLib context, a TPM
  HashLib handle, ...), so the identical traversal can serve image-signature
  verification and image measurement alike.

  The traversal here performs no cryptography itself - it depends only on
  PE/COFF parsing and the caller's callback - so this file is crypto-library
  agnostic and can be shared byte-identically between consumers that hash with
  different back ends (e.g. DxeImageVerificationLib via BaseCryptLib and Tcg2Dxe
  via HashLib). It does not modify PeCoffLib.

  Caution: This file requires additional review when modified.
  PE/COFF image is external input, so this code validates its data structure
  within the image buffer before use.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <IndustryStandard/PeImage.h>

#include "PeImageHash.h"

/**
  Walk a PE/COFF image in Authenticode order (PE/COFF Specification 8.0,
  Appendix A) and invoke HashUpdate() on each region that participates in the
  image hash, in order.

  The regions, in order, are:
    - the image header from its base to the CheckSum field (CheckSum excluded);
    - the header from the end of CheckSum to the start of the Certificate Table
      data directory, then from the end of that directory entry to the end of
      the headers (the Certificate Table directory entry itself excluded);
    - every section, sorted ascending by PointerToRawData, hashing SizeOfRawData
      bytes each (sections with SizeOfRawData == 0 skipped);
    - any trailing data after the last hashed byte, excluding the Certificate
      Table (attribute certificate) region.

  The caller supplies HashUpdate()/HashContext as the hash sink; this function
  performs no cryptography itself and does not initialize or finalize the hash.

  Caution: ImageBase points to external input. The PE/COFF structure is parsed
  and bounds-checked here before any region is passed to HashUpdate().

  @param[in]  ImageBase     Pointer to the start of the PE/COFF image buffer.
  @param[in]  ImageSize     Size of the image buffer in bytes.
  @param[in]  HashUpdate    Callback invoked on each region to be hashed.
  @param[in]  HashContext   Opaque context passed through to HashUpdate().

  @retval EFI_SUCCESS            All regions were enumerated to HashUpdate().
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL or ImageSize is 0.
  @retval EFI_UNSUPPORTED        The image is not a valid PE/COFF image, or its
                                 layout is inconsistent (e.g. the certificate
                                 region extends past the end of the image).
  @retval EFI_OUT_OF_RESOURCES   A temporary allocation failed.
  @retval Other                  HashUpdate() returned an error; returned verbatim.

**/
EFI_STATUS
PeCoffImageHashData (
  IN  UINT8                  *ImageBase,
  IN  UINTN                  ImageSize,
  IN  PE_COFF_HASH_UPDATE    HashUpdate,
  IN  VOID                   *HashContext
  )
{
  EFI_STATUS                           Status;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  UINT32                               PeCoffHeaderOffset;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  EFI_IMAGE_SECTION_HEADER             *Section;
  EFI_IMAGE_SECTION_HEADER             *SectionHeader;
  UINT8                                *HashBase;
  UINTN                                HashSize;
  UINTN                                SumOfBytesHashed;
  UINTN                                Index;
  UINTN                                Pos;
  UINT32                               NumberOfRvaAndSizes;
  UINT32                               CertSize;

  if ((ImageBase == NULL) || (ImageSize == 0) || (HashUpdate == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  SectionHeader = NULL;

  //
  // Locate the PE/COFF header.
  //
  DosHdr             = (EFI_IMAGE_DOS_HEADER *)ImageBase;
  PeCoffHeaderOffset = 0;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  }

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)(ImageBase + PeCoffHeaderOffset);
  if (Hdr.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    return EFI_UNSUPPORTED;
  }

  //
  // PE/COFF Image Hashing, per the Authenticode rules in PE/COFF Specification
  // 8.0 Appendix A. The numbered steps below follow that appendix.
  //

  //
  // 3.  Calculate the distance from the base of the image header to the image
  //     checksum address.
  // 4.  Hash the image header from its base to beginning of the image checksum.
  //
  HashBase = ImageBase;
  if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset.
    //
    HashSize            = (UINTN)(&Hdr.Pe32->OptionalHeader.CheckSum) - (UINTN)HashBase;
    NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
  } else if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    //
    // Use PE32+ offset.
    //
    HashSize            = (UINTN)(&Hdr.Pe32Plus->OptionalHeader.CheckSum) - (UINTN)HashBase;
    NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
  } else {
    //
    // Invalid header magic number.
    //
    return EFI_UNSUPPORTED;
  }

  Status = HashUpdate (HashContext, HashBase, HashSize);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  //
  // 5.  Skip over the image checksum (it occupies a single ULONG).
  //
  if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
    //
    // 6.  Since there is no Cert Directory in optional header, hash everything
    //     from the end of the checksum to the end of image header.
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset.
      //
      HashBase = (UINT8 *)&Hdr.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - ((UINTN)HashBase - (UINTN)ImageBase);
    } else {
      //
      // Use PE32+ offset.
      //
      HashBase = (UINT8 *)&Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - ((UINTN)HashBase - (UINTN)ImageBase);
    }

    if (HashSize != 0) {
      Status = HashUpdate (HashContext, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Done;
      }
    }
  } else {
    //
    // 7.  Hash everything from the end of the checksum to the start of the Cert
    //     Directory.
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset.
      //
      HashBase = (UINT8 *)&Hdr.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN)(&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - (UINTN)HashBase;
    } else {
      //
      // Use PE32+ offset.
      //
      HashBase = (UINT8 *)&Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN)(&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - (UINTN)HashBase;
    }

    if (HashSize != 0) {
      Status = HashUpdate (HashContext, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Done;
      }
    }

    //
    // 8.  Skip over the Cert Directory. (It is sizeof(IMAGE_DATA_DIRECTORY) bytes.)
    // 9.  Hash everything from the end of the Cert Directory to the end of image
    //     header.
    //
    if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset.
      //
      HashBase = (UINT8 *)&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - ((UINTN)HashBase - (UINTN)ImageBase);
    } else {
      //
      // Use PE32+ offset.
      //
      HashBase = (UINT8 *)&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - ((UINTN)HashBase - (UINTN)ImageBase);
    }

    if (HashSize != 0) {
      Status = HashUpdate (HashContext, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Done;
      }
    }
  }

  //
  // 10. Set the SUM_OF_BYTES_HASHED to the size of the header.
  //
  if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset.
    //
    SumOfBytesHashed = Hdr.Pe32->OptionalHeader.SizeOfHeaders;
  } else {
    //
    // Use PE32+ offset.
    //
    SumOfBytesHashed = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders;
  }

  //
  // 11. Build a temporary table of pointers to all the IMAGE_SECTION_HEADER
  //     structures in the image. The 'NumberOfSections' field of the image
  //     header indicates how big the table should be.
  //
  Section = (EFI_IMAGE_SECTION_HEADER *)(
                                         ImageBase +
                                         PeCoffHeaderOffset +
                                         sizeof (UINT32) +
                                         sizeof (EFI_IMAGE_FILE_HEADER) +
                                         Hdr.Pe32->FileHeader.SizeOfOptionalHeader
                                         );

  SectionHeader = (EFI_IMAGE_SECTION_HEADER *)AllocateZeroPool (sizeof (EFI_IMAGE_SECTION_HEADER) * Hdr.Pe32->FileHeader.NumberOfSections);
  if (SectionHeader == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  //
  // 12. Using the 'PointerToRawData' in the referenced section headers as a key,
  //     arrange the elements in the table in ascending order. In other words,
  //     sort the section headers according to the disk-file offset of the
  //     section.
  //
  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Pos = Index;
    while ((Pos > 0) && (Section->PointerToRawData < SectionHeader[Pos - 1].PointerToRawData)) {
      CopyMem (&SectionHeader[Pos], &SectionHeader[Pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
      Pos--;
    }

    CopyMem (&SectionHeader[Pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
    Section += 1;
  }

  //
  // 13. Walk through the sorted table, bring the corresponding section into
  //     memory, and hash the entire section (using the 'SizeOfRawData' field in
  //     the section header to determine the amount of data to hash).
  // 14. Add the section's 'SizeOfRawData' to SUM_OF_BYTES_HASHED.
  // 15. Repeat steps 13 and 14 for all the sections in the sorted table.
  //
  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Section = &SectionHeader[Index];
    if (Section->SizeOfRawData == 0) {
      continue;
    }

    HashBase = ImageBase + Section->PointerToRawData;
    HashSize = (UINTN)Section->SizeOfRawData;

    Status = HashUpdate (HashContext, HashBase, HashSize);
    if (EFI_ERROR (Status)) {
      goto Done;
    }

    SumOfBytesHashed += HashSize;
  }

  //
  // 16. If the file size is greater than SUM_OF_BYTES_HASHED, there is extra
  //     data in the file that needs to be added to the hash. This data begins
  //     at file offset SUM_OF_BYTES_HASHED and its length is:
  //            FileSize - (CertDirectory->Size)
  //
  if (ImageSize > SumOfBytesHashed) {
    HashBase = ImageBase + SumOfBytesHashed;

    if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
      CertSize = 0;
    } else {
      if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        //
        // Use PE32 offset.
        //
        CertSize = Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      } else {
        //
        // Use PE32+ offset.
        //
        CertSize = Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      }
    }

    if (ImageSize > CertSize + SumOfBytesHashed) {
      HashSize = (UINTN)(ImageSize - CertSize - SumOfBytesHashed);

      Status = HashUpdate (HashContext, HashBase, HashSize);
      if (EFI_ERROR (Status)) {
        goto Done;
      }
    } else if (ImageSize < CertSize + SumOfBytesHashed) {
      Status = EFI_UNSUPPORTED;
      goto Done;
    }
  }

  Status = EFI_SUCCESS;

Done:
  if (SectionHeader != NULL) {
    FreePool (SectionHeader);
  }

  return Status;
}
