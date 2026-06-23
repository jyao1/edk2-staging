/** @file
  Implement image verification services for secure boot service

  Caution: This file requires additional review when modified.
  This library will have external input - PE/COFF image.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.

  DxeImageVerificationLibImageRead() function will make sure the PE/COFF image content
  read is within the image buffer.

  DxeImageVerificationHandler(), HashPeImageByType(), HashPeImage() function will accept
  untrusted PE/COFF image and validate its data structure within this image buffer before use.

Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
(C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "DxeImageVerificationLib.h"
#include "ContentValidation.h"

//
// Caution: This is used by a function which may receive untrusted input.
// These global variables hold PE/COFF image data, and they should be validated before use.
//
EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  mNtHeader;
UINT32                               mPeCoffHeaderOffset;
EFI_GUID                             mCertType;

//
// Information on current PE/COFF image
//
UINTN  mImageSize;
UINT8  *mImageBase = NULL;
UINT8    mImageDigest[MAX_DIGEST_SIZE];
UINTN    mImageDigestSize;
UINT8    mImageDigestCache[HASHALG_MAX][MAX_DIGEST_SIZE];
BOOLEAN  mImageDigestCached[HASHALG_MAX];

//
// Notify string for authorization UI.
//
CHAR16  mNotifyString1[MAX_NOTIFY_STRING_LEN] = L"Image verification pass but not found in authorized database!";
CHAR16  mNotifyString2[MAX_NOTIFY_STRING_LEN] = L"Launch this image anyway? (Yes/Defer/No)";
//
// Public Exponent of RSA Key.
//
CONST UINT8  mRsaE[] = { 0x01, 0x00, 0x01 };

//
// OID ASN.1 Value for Hash Algorithms
//
UINT8  mHashOidValue[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, // OBJ_sha224
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // OBJ_sha256
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, // OBJ_sha384
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, // OBJ_sha512
};

HASH_TABLE  mHash[] = {
  { L"SHA224", 28, &mHashOidValue[0],  9, NULL,                 NULL,       NULL,         NULL        },
  { L"SHA256", 32, &mHashOidValue[9],  9, Sha256GetContextSize, Sha256Init, Sha256Update, Sha256Final },
  { L"SHA384", 48, &mHashOidValue[18], 9, Sha384GetContextSize, Sha384Init, Sha384Update, Sha384Final },
  { L"SHA512", 64, &mHashOidValue[27], 9, Sha512GetContextSize, Sha512Init, Sha512Update, Sha512Final }
};

EFI_STRING  mHashTypeStr;

/**
  SecureBoot Hook for processing image verification.

  @param[in] VariableName                 Name of Variable to be found.
  @param[in] VendorGuid                   Variable vendor GUID.
  @param[in] DataSize                     Size of Data found. If size is less than the
                                          data, this value contains the required size.
  @param[in] Data                         Data pointer.

**/
VOID
EFIAPI
SecureBootHook (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN UINTN     DataSize,
  IN VOID      *Data
  );

//
// Forward declaration for the static helper used by
// DxeImageVerificationHandler() (Step A/B) before its definition below.
//
STATIC
EFI_SIGNATURE_LIST **
SigListRegionToArray (
  IN UINT8  *Region,
  IN UINTN  RegionSize
  );

/**
  Free the image-hash db/dbx arrays and their backing variable regions that
  DxeImageVerificationHandler() reads once for Step A/B and reuses for Step C.
  Any NULL argument is ignored.

  @param[in]  Db       db pointer array from SigListRegionToArray(), or NULL.
  @param[in]  Dbx      dbx pointer array from SigListRegionToArray(), or NULL.
  @param[in]  DbData   db variable region, or NULL.
  @param[in]  DbxData  dbx variable region, or NULL.

**/
STATIC
VOID
FreeHashDb (
  IN EFI_SIGNATURE_LIST  **Db,
  IN EFI_SIGNATURE_LIST  **Dbx,
  IN UINT8               *DbData,
  IN UINT8               *DbxData
  )
{
  if (Db != NULL) {
    FreePool (Db);
  }

  if (Dbx != NULL) {
    FreePool (Dbx);
  }

  if (DbData != NULL) {
    FreePool (DbData);
  }

  if (DbxData != NULL) {
    FreePool (DbxData);
  }
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
DxeImageVerificationLibImageRead (
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
  if (EndPosition > mImageSize) {
    *ReadSize = (UINT32)(mImageSize - FileOffset);
  }

  if (FileOffset >= mImageSize) {
    *ReadSize = 0;
  }

  CopyMem (Buffer, (UINT8 *)((UINTN)FileHandle + FileOffset), *ReadSize);

  return EFI_SUCCESS;
}

/**
  Get the image type.

  @param[in]    File       This is a pointer to the device path of the file that is
                           being dispatched.

  @return UINT32           Image Type

**/
UINT32
GetImageType (
  IN  CONST EFI_DEVICE_PATH_PROTOCOL  *File
  )
{
  EFI_STATUS                Status;
  EFI_HANDLE                DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL  *TempDevicePath;
  EFI_BLOCK_IO_PROTOCOL     *BlockIo;

  if (File == NULL) {
    return IMAGE_UNKNOWN;
  }

  //
  // First check to see if File is from a Firmware Volume
  //
  DeviceHandle   = NULL;
  TempDevicePath = (EFI_DEVICE_PATH_PROTOCOL *)File;
  Status         = gBS->LocateDevicePath (
                          &gEfiFirmwareVolume2ProtocolGuid,
                          &TempDevicePath,
                          &DeviceHandle
                          );
  if (!EFI_ERROR (Status)) {
    Status = gBS->OpenProtocol (
                    DeviceHandle,
                    &gEfiFirmwareVolume2ProtocolGuid,
                    NULL,
                    NULL,
                    NULL,
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL
                    );
    if (!EFI_ERROR (Status)) {
      return IMAGE_FROM_FV;
    }
  }

  //
  // Next check to see if File is from a Block I/O device
  //
  DeviceHandle   = NULL;
  TempDevicePath = (EFI_DEVICE_PATH_PROTOCOL *)File;
  Status         = gBS->LocateDevicePath (
                          &gEfiBlockIoProtocolGuid,
                          &TempDevicePath,
                          &DeviceHandle
                          );
  if (!EFI_ERROR (Status)) {
    BlockIo = NULL;
    Status  = gBS->OpenProtocol (
                     DeviceHandle,
                     &gEfiBlockIoProtocolGuid,
                     (VOID **)&BlockIo,
                     NULL,
                     NULL,
                     EFI_OPEN_PROTOCOL_GET_PROTOCOL
                     );
    if (!EFI_ERROR (Status) && (BlockIo != NULL)) {
      if (BlockIo->Media != NULL) {
        if (BlockIo->Media->RemovableMedia) {
          //
          // Block I/O is present and specifies the media is removable
          //
          return IMAGE_FROM_REMOVABLE_MEDIA;
        } else {
          //
          // Block I/O is present and specifies the media is not removable
          //
          return IMAGE_FROM_FIXED_MEDIA;
        }
      }
    }
  }

  //
  // File is not in a Firmware Volume or on a Block I/O device, so check to see if
  // the device path supports the Simple File System Protocol.
  //
  DeviceHandle   = NULL;
  TempDevicePath = (EFI_DEVICE_PATH_PROTOCOL *)File;
  Status         = gBS->LocateDevicePath (
                          &gEfiSimpleFileSystemProtocolGuid,
                          &TempDevicePath,
                          &DeviceHandle
                          );
  if (!EFI_ERROR (Status)) {
    //
    // Simple File System is present without Block I/O, so assume media is fixed.
    //
    return IMAGE_FROM_FIXED_MEDIA;
  }

  //
  // File is not from an FV, Block I/O or Simple File System, so the only options
  // left are a PCI Option ROM and a Load File Protocol such as a PXE Boot from a NIC.
  //
  TempDevicePath = (EFI_DEVICE_PATH_PROTOCOL *)File;
  while (!IsDevicePathEndType (TempDevicePath)) {
    switch (DevicePathType (TempDevicePath)) {
      case MEDIA_DEVICE_PATH:
        if (DevicePathSubType (TempDevicePath) == MEDIA_RELATIVE_OFFSET_RANGE_DP) {
          return IMAGE_FROM_OPTION_ROM;
        }

        break;

      case MESSAGING_DEVICE_PATH:
        if (DevicePathSubType (TempDevicePath) == MSG_MAC_ADDR_DP) {
          return IMAGE_FROM_REMOVABLE_MEDIA;
        }

        break;

      default:
        break;
    }

    TempDevicePath = NextDevicePathNode (TempDevicePath);
  }

  return IMAGE_UNKNOWN;
}

/**
  Calculate hash of Pe/Coff image based on the authenticode image hashing in
  PE/COFF Specification 8.0 Appendix A

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will validate its data structure
  within this image buffer before use.

  Notes: PE/COFF image has been checked by BasePeCoffLib PeCoffLoaderGetImageInfo() in
  its caller function DxeImageVerificationHandler().

  @param[in]    HashAlg   Hash algorithm type.

  @retval TRUE            Successfully hash image.
  @retval FALSE           Fail in hash image.

**/
BOOLEAN
HashPeImage (
  IN  UINT32  HashAlg
  )
{
  BOOLEAN                   Status;
  EFI_IMAGE_SECTION_HEADER  *Section;
  VOID                      *HashCtx;
  UINTN                     CtxSize;
  UINT8                     *HashBase;
  UINTN                     HashSize;
  UINTN                     SumOfBytesHashed;
  EFI_IMAGE_SECTION_HEADER  *SectionHeader;
  UINTN                     Index;
  UINTN                     Pos;
  UINT32                    CertSize;
  UINT32                    NumberOfRvaAndSizes;

  HashCtx       = NULL;
  SectionHeader = NULL;
  Status        = FALSE;

  if ((HashAlg >= HASHALG_MAX)) {
    return FALSE;
  }

  //
  // Initialize context of hash.
  //
  ZeroMem (mImageDigest, MAX_DIGEST_SIZE);

  switch (HashAlg) {
    case HASHALG_SHA256:
      mImageDigestSize = SHA256_DIGEST_SIZE;
      mCertType        = gEfiCertSha256Guid;
      break;

    case HASHALG_SHA384:
      mImageDigestSize = SHA384_DIGEST_SIZE;
      mCertType        = gEfiCertSha384Guid;
      break;

    case HASHALG_SHA512:
      mImageDigestSize = SHA512_DIGEST_SIZE;
      mCertType        = gEfiCertSha512Guid;
      break;

    default:
      return FALSE;
  }

  mHashTypeStr = mHash[HashAlg].Name;
  CtxSize      = mHash[HashAlg].GetContextSize ();

  HashCtx = AllocatePool (CtxSize);
  if (HashCtx == NULL) {
    return FALSE;
  }

  // 1.  Load the image header into memory.

  // 2.  Initialize a SHA hash context.
  Status = mHash[HashAlg].HashInit (HashCtx);

  if (!Status) {
    goto Done;
  }

  //
  // Measuring PE/COFF Image Header;
  // But CheckSum field and SECURITY data directory (certificate) are excluded
  //

  //
  // 3.  Calculate the distance from the base of the image header to the image checksum address.
  // 4.  Hash the image header from its base to beginning of the image checksum.
  //
  HashBase = mImageBase;
  if (mNtHeader.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset.
    //
    HashSize            = (UINTN)(&mNtHeader.Pe32->OptionalHeader.CheckSum) - (UINTN)HashBase;
    NumberOfRvaAndSizes = mNtHeader.Pe32->OptionalHeader.NumberOfRvaAndSizes;
  } else if (mNtHeader.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    //
    // Use PE32+ offset.
    //
    HashSize            = (UINTN)(&mNtHeader.Pe32Plus->OptionalHeader.CheckSum) - (UINTN)HashBase;
    NumberOfRvaAndSizes = mNtHeader.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
  } else {
    //
    // Invalid header magic number.
    //
    Status = FALSE;
    goto Done;
  }

  Status = mHash[HashAlg].HashUpdate (HashCtx, HashBase, HashSize);
  if (!Status) {
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
    if (mNtHeader.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset.
      //
      HashBase = (UINT8 *)&mNtHeader.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = mNtHeader.Pe32->OptionalHeader.SizeOfHeaders - ((UINTN)HashBase - (UINTN)mImageBase);
    } else {
      //
      // Use PE32+ offset.
      //
      HashBase = (UINT8 *)&mNtHeader.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = mNtHeader.Pe32Plus->OptionalHeader.SizeOfHeaders - ((UINTN)HashBase - (UINTN)mImageBase);
    }

    if (HashSize != 0) {
      Status = mHash[HashAlg].HashUpdate (HashCtx, HashBase, HashSize);
      if (!Status) {
        goto Done;
      }
    }
  } else {
    //
    // 7.  Hash everything from the end of the checksum to the start of the Cert Directory.
    //
    if (mNtHeader.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset.
      //
      HashBase = (UINT8 *)&mNtHeader.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN)(&mNtHeader.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - (UINTN)HashBase;
    } else {
      //
      // Use PE32+ offset.
      //
      HashBase = (UINT8 *)&mNtHeader.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN)(&mNtHeader.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - (UINTN)HashBase;
    }

    if (HashSize != 0) {
      Status = mHash[HashAlg].HashUpdate (HashCtx, HashBase, HashSize);
      if (!Status) {
        goto Done;
      }
    }

    //
    // 8.  Skip over the Cert Directory. (It is sizeof(IMAGE_DATA_DIRECTORY) bytes.)
    // 9.  Hash everything from the end of the Cert Directory to the end of image header.
    //
    if (mNtHeader.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      HashBase = (UINT8 *)&mNtHeader.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = mNtHeader.Pe32->OptionalHeader.SizeOfHeaders - ((UINTN)HashBase - (UINTN)mImageBase);
    } else {
      //
      // Use PE32+ offset.
      //
      HashBase = (UINT8 *)&mNtHeader.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = mNtHeader.Pe32Plus->OptionalHeader.SizeOfHeaders - ((UINTN)HashBase - (UINTN)mImageBase);
    }

    if (HashSize != 0) {
      Status = mHash[HashAlg].HashUpdate (HashCtx, HashBase, HashSize);
      if (!Status) {
        goto Done;
      }
    }
  }

  //
  // 10. Set the SUM_OF_BYTES_HASHED to the size of the header.
  //
  if (mNtHeader.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset.
    //
    SumOfBytesHashed = mNtHeader.Pe32->OptionalHeader.SizeOfHeaders;
  } else {
    //
    // Use PE32+ offset
    //
    SumOfBytesHashed = mNtHeader.Pe32Plus->OptionalHeader.SizeOfHeaders;
  }

  Section = (EFI_IMAGE_SECTION_HEADER *)(
                                         mImageBase +
                                         mPeCoffHeaderOffset +
                                         sizeof (UINT32) +
                                         sizeof (EFI_IMAGE_FILE_HEADER) +
                                         mNtHeader.Pe32->FileHeader.SizeOfOptionalHeader
                                         );

  //
  // 11. Build a temporary table of pointers to all the IMAGE_SECTION_HEADER
  //     structures in the image. The 'NumberOfSections' field of the image
  //     header indicates how big the table should be. Do not include any
  //     IMAGE_SECTION_HEADERs in the table whose 'SizeOfRawData' field is zero.
  //
  SectionHeader = (EFI_IMAGE_SECTION_HEADER *)AllocateZeroPool (sizeof (EFI_IMAGE_SECTION_HEADER) * mNtHeader.Pe32->FileHeader.NumberOfSections);
  if (SectionHeader == NULL) {
    Status = FALSE;
    goto Done;
  }

  //
  // 12.  Using the 'PointerToRawData' in the referenced section headers as
  //      a key, arrange the elements in the table in ascending order. In other
  //      words, sort the section headers according to the disk-file offset of
  //      the section.
  //
  for (Index = 0; Index < mNtHeader.Pe32->FileHeader.NumberOfSections; Index++) {
    Pos = Index;
    while ((Pos > 0) && (Section->PointerToRawData < SectionHeader[Pos - 1].PointerToRawData)) {
      CopyMem (&SectionHeader[Pos], &SectionHeader[Pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
      Pos--;
    }

    CopyMem (&SectionHeader[Pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
    Section += 1;
  }

  //
  // 13.  Walk through the sorted table, bring the corresponding section
  //      into memory, and hash the entire section (using the 'SizeOfRawData'
  //      field in the section header to determine the amount of data to hash).
  // 14.  Add the section's 'SizeOfRawData' to SUM_OF_BYTES_HASHED .
  // 15.  Repeat steps 13 and 14 for all the sections in the sorted table.
  //
  for (Index = 0; Index < mNtHeader.Pe32->FileHeader.NumberOfSections; Index++) {
    Section = &SectionHeader[Index];
    if (Section->SizeOfRawData == 0) {
      continue;
    }

    HashBase = mImageBase + Section->PointerToRawData;
    HashSize = (UINTN)Section->SizeOfRawData;

    Status = mHash[HashAlg].HashUpdate (HashCtx, HashBase, HashSize);
    if (!Status) {
      goto Done;
    }

    SumOfBytesHashed += HashSize;
  }

  //
  // 16.  If the file size is greater than SUM_OF_BYTES_HASHED, there is extra
  //      data in the file that needs to be added to the hash. This data begins
  //      at file offset SUM_OF_BYTES_HASHED and its length is:
  //             FileSize  -  (CertDirectory->Size)
  //
  if (mImageSize > SumOfBytesHashed) {
    HashBase = mImageBase + SumOfBytesHashed;

    if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
      CertSize = 0;
    } else {
      if (mNtHeader.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        //
        // Use PE32 offset.
        //
        CertSize = mNtHeader.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      } else {
        //
        // Use PE32+ offset.
        //
        CertSize = mNtHeader.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      }
    }

    if (mImageSize > CertSize + SumOfBytesHashed) {
      HashSize = (UINTN)(mImageSize - CertSize - SumOfBytesHashed);

      Status = mHash[HashAlg].HashUpdate (HashCtx, HashBase, HashSize);
      if (!Status) {
        goto Done;
      }
    } else if (mImageSize < CertSize + SumOfBytesHashed) {
      Status = FALSE;
      goto Done;
    }
  }

  Status = mHash[HashAlg].HashFinal (HashCtx, mImageDigest);

Done:
  if (HashCtx != NULL) {
    FreePool (HashCtx);
  }

  if (SectionHeader != NULL) {
    FreePool (SectionHeader);
  }

  return Status;
}

/**
  Recognize the Hash algorithm in PE/COFF Authenticode and calculate hash of
  Pe/Coff image based on the authenticode image hashing in PE/COFF Specification
  8.0 Appendix A

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will validate its data structure
  within this image buffer before use.

  If mImageDigestCache[] has a cached result for the determined hash algorithm,
  restore it instead of re-hashing the image.

  @param[in]  AuthData            Pointer to the Authenticode Signature retrieved from signed image.
  @param[in]  AuthDataSize        Size of the Authenticode Signature in bytes.

  @retval EFI_UNSUPPORTED             Hash algorithm is not supported.
  @retval EFI_BAD_BUFFER_SIZE         AuthData provided is invalid size.
  @retval EFI_SUCCESS                 Hash successfully.

**/
EFI_STATUS
HashPeImageByType (
  IN UINT8  *AuthData,
  IN UINTN  AuthDataSize
  )
{
  UINT8  Index;

  //
  // Check the Hash algorithm in PE/COFF Authenticode.
  //    According to PKCS#7 Definition:
  //        SignedData ::= SEQUENCE {
  //            version Version,
  //            digestAlgorithms DigestAlgorithmIdentifiers,
  //            contentInfo ContentInfo,
  //            .... }
  //    The DigestAlgorithmIdentifiers can be used to determine the hash algorithm in PE/COFF hashing
  //    This field has the fixed offset (+32) in final Authenticode ASN.1 data.
  //    Fixed offset (+32) is calculated based on two bytes of length encoding.
  //
  if ((AuthDataSize > 1) && ((*(AuthData + 1) & TWO_BYTE_ENCODE) != TWO_BYTE_ENCODE)) {
    //
    // Only support two bytes of Long Form of Length Encoding.
    //
    return EFI_BAD_BUFFER_SIZE;
  }

  for (Index = 0; Index < HASHALG_MAX; Index++) {
    if (AuthDataSize < 32 + mHash[Index].OidLength) {
      continue;
    }

    if (CompareMem (AuthData + 32, mHash[Index].OidValue, mHash[Index].OidLength) == 0) {
      break;
    }
  }

  if (Index == HASHALG_MAX) {
    return EFI_UNSUPPORTED;
  }

  //
  // If a cached digest is available for this algorithm, restore it.
  //
  if (mImageDigestCached[Index]) {
    mImageDigestSize = mHash[Index].DigestLength;
    mHashTypeStr     = mHash[Index].Name;
    CopyMem (mImageDigest, mImageDigestCache[Index], mImageDigestSize);
    switch (Index) {
      case HASHALG_SHA256:
        mCertType = gEfiCertSha256Guid;
        break;
      case HASHALG_SHA384:
        mCertType = gEfiCertSha384Guid;
        break;
      case HASHALG_SHA512:
        mCertType = gEfiCertSha512Guid;
        break;
      default:
        return EFI_UNSUPPORTED;
    }

    return EFI_SUCCESS;
  }

  //
  // HASH PE Image based on Hash algorithm in PE/COFF Authenticode.
  //
  if (!HashPeImage (Index)) {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

//
// IsCertHashFoundInSigList() and IsCertHashFoundInDbx() are the shared,
// phase-independent certificate-hash matcher. They live in ContentValidation.c
// (kept byte-identical with Pkcs7VerifyDxe) and are declared in
// ContentValidation.h.
//

/**
  Split a single signature-database region (many contiguous EFI_SIGNATURE_LIST
  entries, as returned by GetVariable for db/dbx) into a NULL-terminated array
  of pointers to each entry, suitable for Pkcs7VerifyContent().

  @param[in]  Region      Pointer to the signature-list region.
  @param[in]  RegionSize  Size of Region in bytes.

  @return A pool-allocated NULL-terminated array of EFI_SIGNATURE_LIST pointers
          into Region (caller frees the array with FreePool(); the pointed-to
          lists belong to Region). NULL on allocation failure or empty region.

**/
STATIC
EFI_SIGNATURE_LIST **
SigListRegionToArray (
  IN UINT8  *Region,
  IN UINTN  RegionSize
  )
{
  EFI_SIGNATURE_LIST  *SigList;
  EFI_SIGNATURE_LIST  **Array;
  UINTN               Count;
  UINTN               Remaining;
  UINTN               Index;

  if ((Region == NULL) || (RegionSize == 0)) {
    return NULL;
  }

  //
  // First pass: count the entries.
  //
  Count     = 0;
  SigList   = (EFI_SIGNATURE_LIST *)Region;
  Remaining = RegionSize;
  while ((Remaining > 0) && (Remaining >= SigList->SignatureListSize) && (SigList->SignatureListSize > 0)) {
    Count++;
    Remaining -= SigList->SignatureListSize;
    SigList    = (EFI_SIGNATURE_LIST *)((UINT8 *)SigList + SigList->SignatureListSize);
  }

  if (Count == 0) {
    return NULL;
  }

  Array = (EFI_SIGNATURE_LIST **)AllocateZeroPool ((Count + 1) * sizeof (EFI_SIGNATURE_LIST *));
  if (Array == NULL) {
    return NULL;
  }

  //
  // Second pass: fill the array.
  //
  SigList = (EFI_SIGNATURE_LIST *)Region;
  for (Index = 0; Index < Count; Index++) {
    Array[Index] = SigList;
    SigList      = (EFI_SIGNATURE_LIST *)((UINT8 *)SigList + SigList->SignatureListSize);
  }

  Array[Count] = NULL;
  return Array;
}

/**
  Provide verification service for signed images, which include both signature validation
  and platform policy control. For signature types, both UEFI WIN_CERTIFICATE_UEFI_GUID and
  MSFT Authenticode type signatures are supported.

  In this implementation, only verify external executables when in USER MODE.
  Executables from FV is bypass, so pass in AuthenticationStatus is ignored.

  The image verification policy is:
    If the image is signed,
      At least one valid signature or at least one hash value of the image must match a record
      in the security database "db", and no valid signature nor any hash value of the image may
      be reflected in the security database "dbx".
    Otherwise, the image is not signed,
      The hash value of the image must match a record in the security database "db", and
      not be reflected in the security data base "dbx".

  Caution: This function may receive untrusted input.
  PE/COFF image is external input, so this function will validate its data structure
  within this image buffer before use.

  @param[in]    AuthenticationStatus
                           This is the authentication status returned from the security
                           measurement services for the input file.
  @param[in]    File       This is a pointer to the device path of the file that is
                           being dispatched. This will optionally be used for logging.
  @param[in]    FileBuffer File buffer matches the input file device path.
  @param[in]    FileSize   Size of File buffer matches the input file device path.
  @param[in]    BootPolicy A boot policy that was used to call LoadImage() UEFI service.

  @retval EFI_SUCCESS            The file specified by DevicePath and non-NULL
                                 FileBuffer did authenticate, and the platform policy dictates
                                 that the DXE Foundation may use the file.
  @retval EFI_SUCCESS            The device path specified by NULL device path DevicePath
                                 and non-NULL FileBuffer did authenticate, and the platform
                                 policy dictates that the DXE Foundation may execute the image in
                                 FileBuffer.
  @retval EFI_SECURITY_VIOLATION The file specified by File did not authenticate, and
                                 the platform policy dictates that File should be placed
                                 in the untrusted state.
  @retval EFI_ACCESS_DENIED      The file specified by File and FileBuffer did not
                                 authenticate, and the platform policy dictates that the DXE
                                 Foundation may not use File.

**/
EFI_STATUS
EFIAPI
DxeImageVerificationHandler (
  IN  UINT32                          AuthenticationStatus,
  IN  CONST EFI_DEVICE_PATH_PROTOCOL  *File  OPTIONAL,
  IN  VOID                            *FileBuffer,
  IN  UINTN                           FileSize,
  IN  BOOLEAN                         BootPolicy
  )
{
  EFI_IMAGE_DOS_HEADER          *DosHdr;
  WIN_CERTIFICATE               *WinCertificate;
  UINT32                        Policy;
  UINT8                         SecureBoot;
  UINTN                         SecureBootSize;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;
  UINT32                        NumberOfRvaAndSizes;
  WIN_CERTIFICATE_EFI_PKCS      *PkcsCertData;
  WIN_CERTIFICATE_UEFI_GUID     *WinCertUefiGuid;
  UINT8                         *AuthData;
  UINTN                         AuthDataSize;
  EFI_IMAGE_DATA_DIRECTORY      *SecDataDir;
  UINT32                        SecDataDirEnd;
  UINT32                        SecDataDirLeft;
  UINT32                        OffSet;
  RETURN_STATUS                 PeCoffStatus;
  EFI_STATUS                    HashStatus;
  EFI_STATUS                    DbStatus;
  EFI_STATUS                    VarStatus;
  UINT32                        VarAttr;
  UINT8                         HashAlg;
  UINT8                         *DbData;
  UINTN                         DbDataSize;
  UINT8                         *DbxData;
  UINTN                         DbxDataSize;
  EFI_SIGNATURE_LIST            **HashDb;
  EFI_SIGNATURE_LIST            **HashDbx;

  WinCertificate = NULL;
  SecDataDir     = NULL;
  PkcsCertData   = NULL;
  DbData         = NULL;
  DbxData        = NULL;
  HashDb         = NULL;
  HashDbx        = NULL;
  ZeroMem (mImageDigestCached, sizeof (mImageDigestCached));

  //
  // Sanity check
  //
  if (File == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check the image type and get policy setting.
  //
  switch (GetImageType (File)) {
    case IMAGE_FROM_FV:
      Policy = ALWAYS_EXECUTE;
      break;

    case IMAGE_FROM_OPTION_ROM:
      Policy = PcdGet32 (PcdOptionRomImageVerificationPolicy);
      break;

    case IMAGE_FROM_REMOVABLE_MEDIA:
      Policy = PcdGet32 (PcdRemovableMediaImageVerificationPolicy);
      break;

    case IMAGE_FROM_FIXED_MEDIA:
      Policy = PcdGet32 (PcdFixedMediaImageVerificationPolicy);
      break;

    default:
      Policy = DENY_EXECUTE_ON_SECURITY_VIOLATION;
      break;
  }

  //
  // If policy is always/never execute, return directly.
  //
  if (Policy == ALWAYS_EXECUTE) {
    return EFI_SUCCESS;
  }

  if (Policy == NEVER_EXECUTE) {
    return EFI_ACCESS_DENIED;
  }

  //
  // The policy QUERY_USER_ON_SECURITY_VIOLATION and ALLOW_EXECUTE_ON_SECURITY_VIOLATION
  // violates the UEFI spec and has been removed.
  //
  ASSERT (Policy != QUERY_USER_ON_SECURITY_VIOLATION && Policy != ALLOW_EXECUTE_ON_SECURITY_VIOLATION);
  if ((Policy == QUERY_USER_ON_SECURITY_VIOLATION) || (Policy == ALLOW_EXECUTE_ON_SECURITY_VIOLATION)) {
    CpuDeadLoop ();
  }

  SecureBootSize = sizeof (SecureBoot);
  VarStatus      = gRT->GetVariable (EFI_SECURE_BOOT_MODE_NAME, &gEfiGlobalVariableGuid, &VarAttr, &SecureBootSize, &SecureBoot);
  //
  // Skip verification if SecureBoot variable doesn't exist.
  //
  if (VarStatus == EFI_NOT_FOUND) {
    return EFI_SUCCESS;
  }

  //
  // Skip verification if SecureBoot is disabled but not AuditMode
  //
  if ((VarStatus == EFI_SUCCESS) &&
      (VarAttr == (EFI_VARIABLE_BOOTSERVICE_ACCESS |
                   EFI_VARIABLE_RUNTIME_ACCESS)) &&
      (SecureBoot == SECURE_BOOT_MODE_DISABLE))
  {
    return EFI_SUCCESS;
  }

  //
  // Read the Dos header.
  //
  if (FileBuffer == NULL) {
    return EFI_ACCESS_DENIED;
  }

  mImageBase = (UINT8 *)FileBuffer;
  mImageSize = FileSize;

  ZeroMem (&ImageContext, sizeof (ImageContext));
  ImageContext.Handle    = (VOID *)FileBuffer;
  ImageContext.ImageRead = (PE_COFF_LOADER_READ_FILE)DxeImageVerificationLibImageRead;

  //
  // Get information about the image being loaded
  //
  PeCoffStatus = PeCoffLoaderGetImageInfo (&ImageContext);
  if (RETURN_ERROR (PeCoffStatus)) {
    //
    // The information can't be got from the invalid PeImage
    //
    DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: PeImage invalid. Cannot retrieve image information.\n"));
    goto Failed;
  }

  DosHdr = (EFI_IMAGE_DOS_HEADER *)mImageBase;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    //
    // DOS image header is present,
    // so read the PE header after the DOS image header.
    //
    mPeCoffHeaderOffset = DosHdr->e_lfanew;
  } else {
    mPeCoffHeaderOffset = 0;
  }

  //
  // Check PE/COFF image.
  //
  mNtHeader.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)(mImageBase + mPeCoffHeaderOffset);
  if (mNtHeader.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    //
    // It is not a valid Pe/Coff file.
    //
    DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: Not a valid PE/COFF image.\n"));
    goto Failed;
  }

  if (mNtHeader.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset.
    //
    NumberOfRvaAndSizes = mNtHeader.Pe32->OptionalHeader.NumberOfRvaAndSizes;
    if (NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
      SecDataDir = (EFI_IMAGE_DATA_DIRECTORY *)&mNtHeader.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
  } else {
    //
    // Use PE32+ offset.
    //
    NumberOfRvaAndSizes = mNtHeader.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
    if (NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
      SecDataDir = (EFI_IMAGE_DATA_DIRECTORY *)&mNtHeader.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
  }

  //
  // Start Image Validation.
  //
  // Per UEFI Spec Section 32.5.3.3, the validation order is:
  //   A. If the hash of the binary is in dbx, the image shall fail validation.
  //   B. Else if the hash of the binary is in db, the image shall pass validation.
  //   C. Else if one of signatures is in db and is not in dbx, the image shall pass validation.
  //   D. Else the image shall fail validation.
  //
  // Step A and B apply to both signed and unsigned images.
  // Step C only applies to signed images.
  //

  //
  // Step A and B: Check the image hash against dbx and db using all supported
  // hash algorithms. Read db/dbx once and present each as the NULL-terminated
  // array shape PeVerifyHash() expects (a single GetVariable region split with
  // SigListRegionToArray). PeVerifyHash() performs both rules in one call:
  // rule A (hash in dbx -> EFI_SECURITY_VIOLATION) and rule B (hash in db ->
  // EFI_SUCCESS, measuring the matched db node via SecureBootHook).
  //
  DbDataSize = 0;
  VarStatus  = gRT->GetVariable (EFI_IMAGE_SECURITY_DATABASE, &gEfiImageSecurityDatabaseGuid, NULL, &DbDataSize, NULL);
  if (VarStatus == EFI_BUFFER_TOO_SMALL) {
    DbData = (UINT8 *)AllocateZeroPool (DbDataSize);
    if ((DbData != NULL) &&
        !EFI_ERROR (gRT->GetVariable (EFI_IMAGE_SECURITY_DATABASE, &gEfiImageSecurityDatabaseGuid, NULL, &DbDataSize, DbData)))
    {
      HashDb = SigListRegionToArray (DbData, DbDataSize);
    }
  }

  DbxDataSize = 0;
  VarStatus   = gRT->GetVariable (EFI_IMAGE_SECURITY_DATABASE1, &gEfiImageSecurityDatabaseGuid, NULL, &DbxDataSize, NULL);
  if (VarStatus == EFI_BUFFER_TOO_SMALL) {
    DbxData = (UINT8 *)AllocateZeroPool (DbxDataSize);
    if ((DbxData != NULL) &&
        !EFI_ERROR (gRT->GetVariable (EFI_IMAGE_SECURITY_DATABASE1, &gEfiImageSecurityDatabaseGuid, NULL, &DbxDataSize, DbxData)))
    {
      HashDbx = SigListRegionToArray (DbxData, DbxDataSize);
    }
  }

  HashAlg = sizeof (mHash) / sizeof (HASH_TABLE);
  while (HashAlg > 0) {
    HashAlg--;
    if ((mHash[HashAlg].GetContextSize == NULL) || (mHash[HashAlg].HashInit == NULL) || (mHash[HashAlg].HashUpdate == NULL) || (mHash[HashAlg].HashFinal == NULL)) {
      continue;
    }

    if (!HashPeImage (HashAlg)) {
      continue;
    }

    CopyMem (mImageDigestCache[HashAlg], mImageDigest, mImageDigestSize);
    mImageDigestCached[HashAlg] = TRUE;

    //
    // Step A and B in one shared call.
    //
    DbStatus = PeVerifyHash (
                 mImageDigest,
                 mImageDigestSize,
                 HashDb,
                 HashDbx,
                 SecureBootHook
                 );
    if (DbStatus == EFI_SECURITY_VIOLATION) {
      //
      // Step A: the image hash is in dbx; the image fails validation.
      //
      DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: %s hash of image is found in DBX.\n", mHashTypeStr));
      goto Failed;
    }

    if (DbStatus == EFI_SUCCESS) {
      //
      // Step B: the image hash is in db (and not in dbx); the image passes.
      //
      FreeHashDb (HashDb, HashDbx, DbData, DbxData);
      return EFI_SUCCESS;
    }
  }

  //
  // Step C: For unsigned images, there are no signatures to check, so fail.
  // (The image-hash databases HashDb/HashDbx are kept for the signature checks
  // below and freed at Done.)
  //
  if ((SecDataDir == NULL) || (SecDataDir->Size == 0)) {
    DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: Image is not signed and %s hash of image is not found in DB/DBX.\n", mHashTypeStr));
    goto Done;
  }

  //
  // Step C: Check each signature in the certificate table against db and dbx.
  // Multiple signatures are allowed as per PE/COFF Section 4.7
  // "Attribute Certificate Table".
  // The first certificate starts at offset (SecDataDir->VirtualAddress) from the start of the file.
  //
  SecDataDirEnd = SecDataDir->VirtualAddress + SecDataDir->Size;
  for (OffSet = SecDataDir->VirtualAddress;
       OffSet < SecDataDirEnd;
       OffSet += (WinCertificate->dwLength + ALIGN_SIZE (WinCertificate->dwLength)))
  {
    SecDataDirLeft = SecDataDirEnd - OffSet;
    if (SecDataDirLeft <= sizeof (WIN_CERTIFICATE)) {
      break;
    }

    WinCertificate = (WIN_CERTIFICATE *)(mImageBase + OffSet);
    if ((SecDataDirLeft < WinCertificate->dwLength) ||
        (SecDataDirLeft - WinCertificate->dwLength <
         ALIGN_SIZE (WinCertificate->dwLength)))
    {
      break;
    }

    //
    // Verify the image's Authenticode signature, only DER-encoded PKCS#7 signed data is supported.
    //
    if (WinCertificate->wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
      //
      // The certificate is formatted as WIN_CERTIFICATE_EFI_PKCS which is described in the
      // Authenticode specification.
      //
      PkcsCertData = (WIN_CERTIFICATE_EFI_PKCS *)WinCertificate;
      if (PkcsCertData->Hdr.dwLength <= sizeof (PkcsCertData->Hdr)) {
        break;
      }

      AuthData     = PkcsCertData->CertData;
      AuthDataSize = PkcsCertData->Hdr.dwLength - sizeof (PkcsCertData->Hdr);
    } else if (WinCertificate->wCertificateType == WIN_CERT_TYPE_EFI_GUID) {
      //
      // The certificate is formatted as WIN_CERTIFICATE_UEFI_GUID which is described in UEFI Spec.
      //
      WinCertUefiGuid = (WIN_CERTIFICATE_UEFI_GUID *)WinCertificate;
      if (WinCertUefiGuid->Hdr.dwLength <= OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)) {
        break;
      }

      if (!CompareGuid (&WinCertUefiGuid->CertType, &gEfiCertPkcs7Guid)) {
        continue;
      }

      AuthData     = WinCertUefiGuid->CertData;
      AuthDataSize = WinCertUefiGuid->Hdr.dwLength - OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
    } else {
      if (WinCertificate->dwLength < sizeof (WIN_CERTIFICATE)) {
        break;
      }

      continue;
    }

    HashStatus = HashPeImageByType (AuthData, AuthDataSize);
    if (EFI_ERROR (HashStatus)) {
      continue;
    }

    //
    // Step C: A signature is accepted if it verifies up to a trust anchor in db
    // and neither that anchor nor any certificate below it (toward the leaf) is
    // revoked in dbx. Per UEFI Spec 32.5.3.3, dbx is evaluated relative to the
    // trust anchor: a certificate above the anchor (closer to the root) is
    // ignored even if present in dbx. The shared Pkcs7VerifyContent() performs
    // this anchor-relative db/dbx evaluation against the PE image digest
    // (ContentValidationVerifyByPeImageHash), measuring the matched db node via
    // SecureBootHook. A signature that is not accepted only disqualifies
    // itself; the image may still pass via another signature, so continue
    // evaluating the remaining ones.
    //
    if (Pkcs7VerifyContent (
          AuthData,
          AuthDataSize,
          mImageDigest,
          mImageDigestSize,
          ContentValidationVerifyByPeImageHash,
          HashDb,
          HashDbx,
          SecureBootHook
          ) == EFI_SUCCESS)
    {
      FreeHashDb (HashDb, HashDbx, DbData, DbxData);
      return EFI_SUCCESS;
    }
  }

  //
  // Step D: No signature was accepted. The image fails validation.
  //
  DEBUG ((DEBUG_INFO, "DxeImageVerificationLib: Image is signed but signature is not allowed by DB and is not found in DB/DBX.\n"));

Done:
  //
  // Free the image-hash db/dbx read once for Step A/B and reused for Step C.
  //
  FreeHashDb (HashDb, HashDbx, DbData, DbxData);

Failed:
  if (Policy == DEFER_EXECUTE_ON_SECURITY_VIOLATION) {
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_ACCESS_DENIED;
}

/**
  Register security measurement handler.

  @param  ImageHandle   ImageHandle of the loaded driver.
  @param  SystemTable   Pointer to the EFI System Table.

  @retval EFI_SUCCESS   The handlers were registered successfully.
**/
EFI_STATUS
EFIAPI
DxeImageVerificationLibConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return RegisterSecurity2Handler (
           DxeImageVerificationHandler,
           EFI_AUTH_OPERATION_VERIFY_IMAGE | EFI_AUTH_OPERATION_IMAGE_REQUIRED
           );
}
