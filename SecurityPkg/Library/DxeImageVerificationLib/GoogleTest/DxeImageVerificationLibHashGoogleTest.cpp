/** @file
  GoogleTest for HashPeImage() in DxeImageVerificationLib.

  Builds a minimal but structurally valid PE32+ image that exercises every part
  of the Authenticode image-hash traversal (PE/COFF Specification 8.0 Appendix
  A): the header split around the Certificate Table data directory, sections
  hashed in PointerToRawData order (deliberately enrolled out of order), and
  trailing data after the sections with the attribute-certificate region
  excluded.

  The test asserts the exact SHA-256/384/512 digests HashPeImage() produces. The
  expected digests are pinned constants, so the same test proves the digest is
  unchanged when HashPeImage()'s internals are refactored (e.g. extracting the
  traversal into PeImageHash.c).

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Library/BaseLib.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/MemoryAllocationLib.h>
  #include <Library/BaseCryptLib.h>
  #include <IndustryStandard/PeImage.h>
  #include <Guid/ImageAuthentication.h>

  //
  // HASHALG_* selectors used by HashPeImage() (from DxeImageVerificationLib.h).
  //
  #define HASHALG_SHA256  0x00000001
  #define HASHALG_SHA384  0x00000002
  #define HASHALG_SHA512  0x00000003

  //
  // Globals and function under test (non-static in DxeImageVerificationLib.c).
  // HashPeImage() reads mImageBase/mImageSize/mNtHeader/mPeCoffHeaderOffset and
  // writes mImageDigest/mImageDigestSize.
  //
  extern UINT8                                *mImageBase;
  extern UINTN                                mImageSize;
  extern UINT32                               mPeCoffHeaderOffset;
  extern EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  mNtHeader;
  extern UINT8                                mImageDigest[];
  extern UINTN                                mImageDigestSize;

  BOOLEAN
  HashPeImage (
    IN  UINT32  HashAlg
    );
}

//
// Layout of the synthetic PE32+ image. The numbers are chosen so the file has:
//   - a DOS header with e_lfanew pointing at the NT headers,
//   - an optional header carrying a non-empty SECURITY (certificate) directory,
//   - two sections whose on-disk order is the reverse of their header order
//     (forces the traversal's PointerToRawData sort to do real work),
//   - a trailing region that contains the (excluded) attribute certificate plus
//     a few bytes of extra data that MUST be hashed.
//
#define PE_OFFSET          0x40                         // e_lfanew
#define SECT_ALIGN         0x200
#define HDR_RAW_SIZE       SECT_ALIGN                   // SizeOfHeaders
#define SECT_RAW_SIZE      0x200
#define SECT0_RAW_PTR      (HDR_RAW_SIZE + SECT_RAW_SIZE)  // section[0] is LATER on disk
#define SECT1_RAW_PTR      HDR_RAW_SIZE                    // section[1] is EARLIER on disk
#define SECTIONS_END       (HDR_RAW_SIZE + 2 * SECT_RAW_SIZE)
#define EXTRA_DATA_SIZE     0x20
#define CERT_SIZE          0x40
#define IMAGE_TOTAL_SIZE   (SECTIONS_END + EXTRA_DATA_SIZE + CERT_SIZE)

class HashPeImageTest : public ::testing::Test {
protected:
  UINT8  *mImage;

  void SetUp () override {
    mImage = (UINT8 *)AllocateZeroPool (IMAGE_TOTAL_SIZE);
    ASSERT_NE (mImage, nullptr);

    BuildImage (mImage);

    //
    // Point the library globals at the synthetic image exactly as
    // DxeImageVerificationHandler() would before calling HashPeImage().
    //
    mImageBase          = mImage;
    mImageSize          = IMAGE_TOTAL_SIZE;
    mPeCoffHeaderOffset = PE_OFFSET;
    mNtHeader.Pe32      = (EFI_IMAGE_NT_HEADERS32 *)(mImage + PE_OFFSET);
  }

  void TearDown () override {
    if (mImage != NULL) {
      FreePool (mImage);
      mImage = NULL;
    }

    mImageBase = NULL;
    mImageSize = 0;
  }

  //
  // Fill Buffer with a deterministic PE32+ image (no randomness, so the digest
  // is reproducible).
  //
  static void
  BuildImage (
    UINT8  *Buffer
    )
  {
    EFI_IMAGE_DOS_HEADER     *Dos;
    EFI_IMAGE_NT_HEADERS64   *Nt;
    EFI_IMAGE_SECTION_HEADER *Sect;
    UINTN                    Index;

    //
    // Deterministic body fill so header/section/trailing bytes are non-zero.
    //
    for (Index = 0; Index < IMAGE_TOTAL_SIZE; Index++) {
      Buffer[Index] = (UINT8)(Index & 0xFF);
    }

    //
    // DOS header.
    //
    Dos          = (EFI_IMAGE_DOS_HEADER *)Buffer;
    Dos->e_magic = EFI_IMAGE_DOS_SIGNATURE;
    Dos->e_lfanew = PE_OFFSET;

    //
    // NT headers (PE32+).
    //
    Nt            = (EFI_IMAGE_NT_HEADERS64 *)(Buffer + PE_OFFSET);
    Nt->Signature = EFI_IMAGE_NT_SIGNATURE;

    Nt->FileHeader.Machine              = EFI_IMAGE_MACHINE_X64;
    Nt->FileHeader.NumberOfSections     = 2;
    Nt->FileHeader.SizeOfOptionalHeader = sizeof (EFI_IMAGE_OPTIONAL_HEADER64);

    Nt->OptionalHeader.Magic               = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    Nt->OptionalHeader.SizeOfHeaders       = HDR_RAW_SIZE;
    Nt->OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
    Nt->OptionalHeader.CheckSum            = 0x12345678;   // hashed-around, value irrelevant

    //
    // Non-empty Certificate Table (SECURITY) directory: located in the trailing
    // region, sized CERT_SIZE. This region must be excluded from the hash.
    //
    Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress =
      (UINT32)(SECTIONS_END + EXTRA_DATA_SIZE);
    Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size = CERT_SIZE;

    //
    // Section headers. Header order is {S0, S1} but on-disk order is reversed
    // (S0 points later than S1), so the Authenticode sort must reorder them.
    //
    Sect = (EFI_IMAGE_SECTION_HEADER *)((UINT8 *)&Nt->OptionalHeader + Nt->FileHeader.SizeOfOptionalHeader);

    CopyMem (Sect[0].Name, ".text", 5);
    Sect[0].SizeOfRawData    = SECT_RAW_SIZE;
    Sect[0].PointerToRawData = SECT0_RAW_PTR;

    CopyMem (Sect[1].Name, ".data", 5);
    Sect[1].SizeOfRawData    = SECT_RAW_SIZE;
    Sect[1].PointerToRawData = SECT1_RAW_PTR;
  }
};

//
// Expected digests of the synthetic image, captured from HashPeImage() BEFORE
// the PeImageHash.c refactor. They are byte-for-byte assertions: any change in
// the traversal that alters the final image hash fails here, which is what
// proves the refactor leaves the digest identical.
//
static CONST UINT8  mExpectedSha256[SHA256_DIGEST_SIZE] = {
  0xFF, 0xA7, 0x00, 0x5E, 0xFD, 0x1D, 0x91, 0x79, 0x66, 0xCC, 0xF2, 0x59, 0xF4, 0x85, 0xE4, 0x99,
  0xF1, 0x81, 0x87, 0x3A, 0xD4, 0xB4, 0xFA, 0x76, 0x37, 0x32, 0xD6, 0xAD, 0xC1, 0x47, 0xE5, 0x48
};

static CONST UINT8  mExpectedSha384[SHA384_DIGEST_SIZE] = {
  0x71, 0xEB, 0x28, 0x67, 0x55, 0xA1, 0xD8, 0x24, 0x60, 0x08, 0x71, 0x51, 0x94, 0xD6, 0x99, 0x1F,
  0x0E, 0x36, 0x1B, 0xDD, 0xCA, 0x20, 0xD5, 0xB4, 0xFB, 0x23, 0x7E, 0xD5, 0xC1, 0x52, 0xED, 0x7A,
  0x4B, 0x0B, 0x0C, 0x3F, 0x4F, 0x9C, 0x81, 0x18, 0x19, 0xF0, 0xD9, 0x8C, 0x13, 0x37, 0x62, 0xB5
};

static CONST UINT8  mExpectedSha512[SHA512_DIGEST_SIZE] = {
  0xAE, 0x45, 0xAF, 0xBB, 0x04, 0x0A, 0x67, 0x98, 0xE9, 0x59, 0x4C, 0xD3, 0xE5, 0x4F, 0x80, 0xC1,
  0xFA, 0xC5, 0x3C, 0x0D, 0xA6, 0xE3, 0x15, 0x9C, 0x26, 0x93, 0x10, 0xD5, 0xC7, 0x0F, 0xA1, 0x1A,
  0x68, 0x7C, 0x94, 0x4A, 0x9F, 0x97, 0x2B, 0x40, 0xAE, 0xC5, 0x49, 0x90, 0x43, 0xA7, 0x72, 0x1B,
  0xC1, 0x73, 0xAA, 0x2C, 0x2B, 0x20, 0x28, 0xDA, 0x0E, 0x26, 0x24, 0x62, 0x07, 0x35, 0x61, 0xD2
};

TEST_F (HashPeImageTest, Sha256_DigestStable) {
  ASSERT_TRUE (HashPeImage (HASHALG_SHA256));
  EXPECT_EQ (mImageDigestSize, (UINTN)SHA256_DIGEST_SIZE);
  EXPECT_EQ (CompareMem (mImageDigest, mExpectedSha256, SHA256_DIGEST_SIZE), 0);
}

TEST_F (HashPeImageTest, Sha384_DigestStable) {
  ASSERT_TRUE (HashPeImage (HASHALG_SHA384));
  EXPECT_EQ (mImageDigestSize, (UINTN)SHA384_DIGEST_SIZE);
  EXPECT_EQ (CompareMem (mImageDigest, mExpectedSha384, SHA384_DIGEST_SIZE), 0);
}

TEST_F (HashPeImageTest, Sha512_DigestStable) {
  ASSERT_TRUE (HashPeImage (HASHALG_SHA512));
  EXPECT_EQ (mImageDigestSize, (UINTN)SHA512_DIGEST_SIZE);
  EXPECT_EQ (CompareMem (mImageDigest, mExpectedSha512, SHA512_DIGEST_SIZE), 0);
}

int
main (
  int   argc,
  char  *argv[]
  )
{
  testing::InitGoogleTest (&argc, argv);
  return RUN_ALL_TESTS ();
}
