/** @file
  DXE driver that produces the EFI Crypto Indicator Table (ECIT) as an
  EFI Configuration Table entry.

  The ECIT advertises the cryptographic algorithms supported by the firmware
  for Secure Boot image verification, secure boot authorization, and
  authenticated variable updates.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/TlsLib.h>
#include <Guid/CryptoIndicatorTable.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>

//
// OID strings for supported signing algorithms.
//
// Image verification call chain (classic RSA/ECDSA):
//   AuthenticodeVerify()  - CryptoPkg/Library/BaseCryptLib/Pk/CryptAuthenticode.c
//     -> Pkcs7Verify()    - CryptoPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c
//       -> PKCS7_verify() - openssl/crypto/pkcs7/pk7_smime.c
//         -> PKCS7_signatureVerify() - openssl/crypto/pkcs7/pk7_doit.c
//           -> EVP_VerifyFinal_ex()  - openssl/crypto/evp/p_verify.c
//             -> EVP_PKEY_verify()   - dispatches by key type (RSA or EC)
//
// Image verification call chain (ML-DSA-87, UEFI_PQC branch):
//   AuthenticodeVerify()  - CryptoPkg/Library/BaseCryptLib/Pk/CryptAuthenticode.c
//     -> Pkcs7Verify()    - CryptoPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c
//       -> Detects ML-DSA-87 key via EVP_PKEY_get0_type_name()
//       -> Manually verifies messageDigest attribute against hash of InData
//       -> PKCS7_verify() with PKCS7_NOSIGS (cert chain only, skip sig)
//       -> EVP_PKEY_verify_message_init() + EVP_PKEY_verify()
//          Passes DER-encoded auth_attr as full message (not pre-hashed)
//          to ML-DSA-87 provider which does Pure ML-DSA verification.
//
// Registered digests in Pkcs7Verify(): MD5, SHA-1, SHA-256, SHA-384, SHA-512
//
// RSA PKCS#1 v1.5 signing algorithms:
//   EVP_PKEY_verify() with RSA key uses PKCS#1 v1.5 padding by default.
//   OID definitions: CryptoPkg/Library/OpensslLib/OpensslGen/providers/common/include/prov/der_rsa.h
//
//   1.2.840.113549.1.1.11  sha256WithRSAEncryption  (der_rsa.h: DER_OID_V_sha256WithRSAEncryption)
//   1.2.840.113549.1.1.12  sha384WithRSAEncryption  (der_rsa.h: DER_OID_V_sha384WithRSAEncryption)
//   1.2.840.113549.1.1.13  sha512WithRSAEncryption  (der_rsa.h: DER_OID_V_sha512WithRSAEncryption)
//
// NOTE: RSA-PSS (1.2.840.113549.1.1.10) is NOT supported through this path.
//   PKCS7_signatureVerify() calls EVP_VerifyFinal_ex() which does NOT set
//   RSA_PKCS1_PSS_PADDING on the EVP_PKEY_CTX. RSA-PSS requires explicit
//   padding mode configuration. The PKCS#7 (RFC 2315) structure does not
//   carry RSA-PSS parameters. RsaPssVerify() in CryptRsaPss.c is a separate
//   API not used in the Authenticode/PKCS7 verification path.
//
// ECDSA signing algorithms (when OpensslLibFull is used):
//   EVP_PKEY_verify() with EC key dispatches to ECDSA verification.
//   OID definitions: CryptoPkg/Library/OpensslLib/OpensslGen/providers/common/include/prov/der_ec.h
//   NOTE: EC support depends on the OpenSSL library variant linked:
//     - OpensslLib.inf / OpensslLibCrypto.inf:     EC DISABLED (EDK2_OPENSSL_NOEC=1)
//     - OpensslLibFull.inf / OpensslLibFullAccel.inf: EC ENABLED
//
//   1.2.840.10045.4.3.2    ecdsa-with-SHA256        (der_ec.h: DER_OID_V_ecdsa_with_SHA256)
//   1.2.840.10045.4.3.3    ecdsa-with-SHA384        (der_ec.h: DER_OID_V_ecdsa_with_SHA384)
//   1.2.840.10045.4.3.4    ecdsa-with-SHA512        (der_ec.h: DER_OID_V_ecdsa_with_SHA512)
//
// ML-DSA-87 signing algorithm (when OpensslLibFull is used, UEFI_PQC branch):
//   Pkcs7Verify() bypasses PKCS7_signatureVerify() and uses
//   EVP_PKEY_verify_message_init() + EVP_PKEY_verify() for message-level verification.
//   OID definitions: CryptoPkg/Library/OpensslLib/OpensslGen/providers/common/include/prov/der_ml_dsa.h
//   NOTE: ML-DSA support depends on the OpenSSL library variant linked:
//     - OpensslLib.inf (noec config):  ML-DSA DISABLED (OPENSSL_NO_ML_DSA)
//     - OpensslLibFull.inf (ec config): ML-DSA ENABLED
//
//   2.16.840.1.101.3.4.3.17  id-ml-dsa-44           (der_ml_dsa.h: DER_OID_V_id_ml_dsa_44)
//   2.16.840.1.101.3.4.3.18  id-ml-dsa-65           (der_ml_dsa.h: DER_OID_V_id_ml_dsa_65)
//   2.16.840.1.101.3.4.3.19  id-ml-dsa-87           (der_ml_dsa.h: DER_OID_V_id_ml_dsa_87)
//

//
// Per-algorithm-family OID strings are queried from BaseCryptLib via
// Pkcs7GetVerifyOidList(). This allows different crypto backends
// (OpenSSL, MbedTLS) to report their actual supported algorithms.
//
// Image Verification OIDs: only algorithms reachable through AuthenticodeVerify().
// The actual set depends on the linked crypto library.
//
// Authenticated Variable OIDs:
//   ProcessVarWithPk() / ProcessVarWithKek()
//     -> VerifyTimeBasedPayloadAndUpdate()
//       -> VerifyTimeBasedPayload()
//         1. FindHashAlgorithmIndex() - validates digest is SHA-256/384/512.
//         2. For AuthVarTypePk: Pkcs7Verify() with PK cert as trusted root.
//            For AuthVarTypeKek: Pkcs7Verify() with each KEK cert.
//            For AuthVarTypePayload: Pkcs7Verify() with cert from payload.
//   Pkcs7Verify() is the same entry point as image verification (see above).
//

//
// Key type flags for tracking which algorithm families are enrolled
// in the Secure Boot variables (PK, KEK, db).
//
#define KEY_TYPE_RSA     BIT0
#define KEY_TYPE_EC      BIT1
#define KEY_TYPE_ML_DSA  BIT2

//
// Supported EFI_SIGNATURE_LIST types for Secure Boot image authorization.
//
// This list is derived from the signature types consumed by
// DxeImageVerificationLib (SecurityPkg/Library/DxeImageVerificationLib):
//
// EFI_CERT_X509_GUID
//   - IsAllowedByDb(): match raw X.509 certs in db via AuthenticodeVerify().
//   - IsForbiddenByDbx(): match raw X.509 certs in dbx via AuthenticodeVerify().
//   - PassTimestampCheck(): match X.509 certs in dbt for timestamp verification.
//
// EFI_CERT_SHA256_GUID, EFI_CERT_SHA384_GUID, EFI_CERT_SHA512_GUID
//   - HashPeImage(): sets mCertType to the corresponding GUID.
//   - IsSignatureFoundInDatabase(): matches the PE image hash in db or dbx.
//
// EFI_CERT_X509_SHA256_GUID, EFI_CERT_X509_SHA384_GUID, EFI_CERT_X509_SHA512_GUID
//   - IsCertHashFoundInDbx(): matches TBSCertificate hashes in dbx for
//     certificate revocation by hash.
//
STATIC EFI_GUID  mSecureBootAuthTypes[] = {
  EFI_CERT_X509_GUID,
  EFI_CERT_SHA256_GUID,
  EFI_CERT_SHA384_GUID,
  EFI_CERT_SHA512_GUID,
  EFI_CERT_X509_SHA256_GUID,
  EFI_CERT_X509_SHA384_GUID,
  EFI_CERT_X509_SHA512_GUID,
};

/**
  Calculate the padded entry length aligned to 8 bytes.

  @param[in] DataSize  Size of the entry data in bytes.

  @return The total entry size including header, padded to 8 bytes.
**/
STATIC
UINT16
EcitEntrySize (
  IN UINTN  DataSize
  )
{
  UINTN  Total;

  Total = sizeof (EFI_CRYPTO_INDICATOR_ENTRY) + DataSize;
  //
  // Pad to 8-byte alignment
  //
  Total = ALIGN_VALUE (Total, 8);
  return (UINT16)Total;
}

/**
  Determine the key types present in X.509 certificates within a Secure Boot
  variable.

  Reads the specified UEFI variable and walks its EFI_SIGNATURE_LIST entries.
  For each EFI_CERT_X509_GUID entry, examines the certificate to determine
  whether it contains an RSA, EC, or ML-DSA public key.

  @param[in] VariableName  Name of the UEFI variable (e.g. L"PK", L"KEK", L"db").
  @param[in] VendorGuid    GUID of the variable vendor.

  @return  Bitmask of KEY_TYPE_RSA, KEY_TYPE_EC, KEY_TYPE_ML_DSA flags
           indicating which key types are present. Returns 0 if the
           variable does not exist or contains no X.509 entries.
**/
STATIC
UINT32
GetKeyTypesFromVariable (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid
  )
{
  EFI_STATUS          Status;
  UINT8               *Data;
  UINTN               DataSize;
  EFI_SIGNATURE_LIST  *SigList;
  EFI_SIGNATURE_DATA  *SigData;
  UINTN               CertCount;
  UINTN               Index;
  UINT8               *Cert;
  UINTN               CertSize;
  VOID                *KeyContext;
  UINT32              KeyTypes;

  KeyTypes = 0;

  //
  // Query variable size.
  //
  DataSize = 0;
  Status   = gRT->GetVariable (VariableName, VendorGuid, NULL, &DataSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return 0;
  }

  Data = AllocatePool (DataSize);
  if (Data == NULL) {
    return 0;
  }

  Status = gRT->GetVariable (VariableName, VendorGuid, NULL, &DataSize, Data);
  if (EFI_ERROR (Status)) {
    FreePool (Data);
    return 0;
  }

  //
  // Walk EFI_SIGNATURE_LIST entries. Only examine EFI_CERT_X509_GUID lists
  // since those contain the X.509 certificates used for signature verification.
  //
  SigList = (EFI_SIGNATURE_LIST *)Data;
  while ((DataSize > 0) && (DataSize >= SigList->SignatureListSize)) {
    if (CompareGuid (&SigList->SignatureType, &gEfiCertX509Guid)) {
      SigData   = (EFI_SIGNATURE_DATA *)((UINT8 *)SigList + sizeof (EFI_SIGNATURE_LIST) + SigList->SignatureHeaderSize);
      CertCount = (SigList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - SigList->SignatureHeaderSize) / SigList->SignatureSize;

      for (Index = 0; Index < CertCount; Index++) {
        Cert     = SigData->SignatureData;
        CertSize = SigList->SignatureSize - sizeof (EFI_GUID);

        KeyContext = NULL;
        if (RsaGetPublicKeyFromX509 (Cert, CertSize, &KeyContext)) {
          KeyTypes |= KEY_TYPE_RSA;
          RsaFree (KeyContext);
        } else if (EcGetPublicKeyFromX509 (Cert, CertSize, &KeyContext)) {
          KeyTypes |= KEY_TYPE_EC;
          EcFree (KeyContext);
        } else if (MlDsaGetPublicKeyFromX509 (Cert, CertSize)) {
          KeyTypes |= KEY_TYPE_ML_DSA;
        }

        //
        // All key types discovered; no need to continue.
        //
        if (KeyTypes == (KEY_TYPE_RSA | KEY_TYPE_EC | KEY_TYPE_ML_DSA)) {
          FreePool (Data);
          return KeyTypes;
        }

        SigData = (EFI_SIGNATURE_DATA *)((UINT8 *)SigData + SigList->SignatureSize);
      }
    }

    DataSize -= SigList->SignatureListSize;
    SigList   = (EFI_SIGNATURE_LIST *)((UINT8 *)SigList + SigList->SignatureListSize);
  }

  FreePool (Data);
  return KeyTypes;
}

/**
  Get the union of key types enrolled across the PK, KEK, and db variables.

  @return  Bitmask of KEY_TYPE_RSA, KEY_TYPE_EC, KEY_TYPE_ML_DSA flags.
**/
STATIC
UINT32
GetEnrolledKeyTypes (
  VOID
  )
{
  UINT32  KeyTypes;

  KeyTypes  = GetKeyTypesFromVariable (EFI_PLATFORM_KEY_NAME, &gEfiGlobalVariableGuid);
  KeyTypes |= GetKeyTypesFromVariable (EFI_KEY_EXCHANGE_KEY_NAME, &gEfiGlobalVariableGuid);
  KeyTypes |= GetKeyTypesFromVariable (EFI_IMAGE_SECURITY_DATABASE, &gEfiImageSecurityDatabaseGuid);

  return KeyTypes;
}

/**
  Build a CSV OID string containing only the signing algorithm OIDs for
  key types that are actually enrolled in the Secure Boot variables.

  The caller must free the returned string with FreePool().

  @param[in]  KeyTypes  Bitmask of KEY_TYPE_* flags from GetEnrolledKeyTypes().

  @return  Allocated ASCII string of comma-separated OIDs, or NULL on
           allocation failure. Returns an empty string if no key types match.
**/
STATIC
CHAR8 *
BuildFilteredOidString (
  IN UINT32  KeyTypes
  )
{
  CHAR8  *Result;
  UINTN  MaxLen;
  UINTN  Offset;

  CONST CHAR8  *RsaOids;
  CONST CHAR8  *EcOids;
  CONST CHAR8  *MlDsaOids;

  //
  // Query per-family OID strings from the crypto library.
  //
  RsaOids   = Pkcs7GetVerifyOidList (Pkcs7SignatureAlgoRsa);
  EcOids    = Pkcs7GetVerifyOidList (Pkcs7SignatureAlgoEc);
  MlDsaOids = Pkcs7GetVerifyOidList (Pkcs7SignatureAlgoMlDsa);

  //
  // Allocate enough for all OID groups plus commas and null terminator.
  //
  MaxLen = 1;  // null terminator
  if ((KeyTypes & KEY_TYPE_RSA) != 0 && RsaOids != NULL) {
    MaxLen += AsciiStrLen (RsaOids) + 1;
  }

  if ((KeyTypes & KEY_TYPE_EC) != 0 && EcOids != NULL) {
    MaxLen += AsciiStrLen (EcOids) + 1;
  }

  if ((KeyTypes & KEY_TYPE_ML_DSA) != 0 && MlDsaOids != NULL) {
    MaxLen += AsciiStrLen (MlDsaOids) + 1;
  }

  Result = AllocateZeroPool (MaxLen);
  if (Result == NULL) {
    return NULL;
  }

  Offset = 0;

  if ((KeyTypes & KEY_TYPE_RSA) != 0 && RsaOids != NULL) {
    AsciiStrCpyS (Result, MaxLen, RsaOids);
    Offset = AsciiStrLen (Result);
  }

  if ((KeyTypes & KEY_TYPE_EC) != 0 && EcOids != NULL) {
    if (Offset > 0) {
      Result[Offset++] = ',';
    }

    AsciiStrCpyS (Result + Offset, MaxLen - Offset, EcOids);
    Offset = AsciiStrLen (Result);
  }

  if ((KeyTypes & KEY_TYPE_ML_DSA) != 0 && MlDsaOids != NULL) {
    if (Offset > 0) {
      Result[Offset++] = ',';
    }

    AsciiStrCpyS (Result + Offset, MaxLen - Offset, MlDsaOids);
  }

  return Result;
}

/**
  Build and install the EFI Crypto Indicator Table as a Configuration Table.

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The table was installed successfully.
  @retval Others          An error occurred.
**/
EFI_STATUS
EFIAPI
CryptoIndicatorTableDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                   Status;
  EFI_CRYPTO_INDICATOR_TABLE   *Table;
  EFI_CRYPTO_INDICATOR_ENTRY   *Entry;
  UINT8                        *Buffer;
  UINTN                        TableSize;
  UINT16                       ImageVerifEntrySize;
  UINT16                       SecBootAuthEntrySize;
  UINT16                       AuthVarEntrySize;
  UINT16                       TlsVersionEntrySize;
  UINT16                       TlsCipherEntrySize;
  UINTN                        FilteredOidLen;
  UINTN                        AllOidLen;
  UINTN                        SecBootAuthDataSize;
  UINT32                       KeyTypes;
  CHAR8                        *FilteredOids;
  CONST CHAR8                  *AllOids;
  UINT16                       *TlsVersions;
  UINT16                       *TlsCipherSuites;
  UINTN                        TlsVersionCount;
  UINTN                        TlsCipherCount;
  UINTN                        TlsVersionDataSize;
  UINTN                        TlsCipherDataSize;
  UINT16                       NumberOfEntries;

  //
  // Query the complete set of supported signing OIDs from the crypto library.
  //
  AllOids = Pkcs7GetVerifyOidList (Pkcs7SignatureAlgoAll);
  if (AllOids == NULL) {
    DEBUG ((DEBUG_ERROR, "CryptoIndicatorTableDxe: Pkcs7GetVerifyOidList returned NULL\n"));
    return EFI_UNSUPPORTED;
  }

  //
  // Determine which key types are actually enrolled in PK/KEK/db,
  // then build the OID string containing only the algorithms that
  // can actually be used for verification with the current configuration.
  //
  KeyTypes     = GetEnrolledKeyTypes ();
  FilteredOids = BuildFilteredOidString (KeyTypes);
  if (FilteredOids == NULL) {
    DEBUG ((DEBUG_ERROR, "CryptoIndicatorTableDxe: Failed to build OID string\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((
    DEBUG_INFO,
    "CryptoIndicatorTableDxe: Enrolled key types: RSA=%d EC=%d ML-DSA=%d\n",
    (KeyTypes & KEY_TYPE_RSA) != 0,
    (KeyTypes & KEY_TYPE_EC) != 0,
    (KeyTypes & KEY_TYPE_ML_DSA) != 0
    ));

  //
  // Calculate sizes for each entry's data payload.
  //
  // Image Verification entry: filtered CSV OID string (only algorithms
  // for key types actually enrolled in PK/KEK/db).
  //
  FilteredOidLen      = AsciiStrSize (FilteredOids);
  ImageVerifEntrySize = EcitEntrySize (FilteredOidLen);

  //
  // Authenticated Variable entry: all supported OIDs (unfiltered), because
  // auth variable verification can use any supported algorithm.
  //
  AllOidLen        = AsciiStrSize (AllOids);
  AuthVarEntrySize = EcitEntrySize (AllOidLen);

  //
  // Secure Boot Authorization entry: array of EFI_GUID.
  //
  SecBootAuthDataSize  = sizeof (mSecureBootAuthTypes);
  SecBootAuthEntrySize = EcitEntrySize (SecBootAuthDataSize);

  //
  // TLS Version entry: query supported TLS protocol versions.
  //
  TlsVersions       = NULL;
  TlsVersionCount   = 0;
  TlsVersionEntrySize = 0;
  TlsVersionDataSize  = 0;

  Status = TlsGetSupportedVersions (NULL, &TlsVersionCount);
  if (!EFI_ERROR (Status) && (TlsVersionCount > 0)) {
    TlsVersionDataSize = TlsVersionCount * sizeof (UINT16);
    TlsVersions        = AllocatePool (TlsVersionDataSize);
    if (TlsVersions != NULL) {
      Status = TlsGetSupportedVersions (TlsVersions, &TlsVersionCount);
      if (EFI_ERROR (Status)) {
        FreePool (TlsVersions);
        TlsVersions      = NULL;
        TlsVersionCount   = 0;
        TlsVersionDataSize = 0;
      } else {
        TlsVersionDataSize  = TlsVersionCount * sizeof (UINT16);
        //
        // Entry data = UINT16 Count + UINT16 Versions[]
        //
        TlsVersionEntrySize = EcitEntrySize (sizeof (UINT16) + TlsVersionDataSize);
      }
    } else {
      TlsVersionCount   = 0;
      TlsVersionDataSize = 0;
    }
  }

  //
  // TLS Cipher Suite entry: query supported cipher suites.
  //
  TlsCipherSuites    = NULL;
  TlsCipherCount     = 0;
  TlsCipherEntrySize = 0;
  TlsCipherDataSize  = 0;

  Status = TlsGetSupportedCipherSuites (NULL, &TlsCipherCount);
  if (!EFI_ERROR (Status) && (TlsCipherCount > 0)) {
    TlsCipherDataSize = TlsCipherCount * sizeof (UINT16);
    TlsCipherSuites   = AllocatePool (TlsCipherDataSize);
    if (TlsCipherSuites != NULL) {
      Status = TlsGetSupportedCipherSuites (TlsCipherSuites, &TlsCipherCount);
      if (EFI_ERROR (Status)) {
        FreePool (TlsCipherSuites);
        TlsCipherSuites   = NULL;
        TlsCipherCount     = 0;
        TlsCipherDataSize  = 0;
      } else {
        TlsCipherDataSize  = TlsCipherCount * sizeof (UINT16);
        //
        // Entry data = UINT16 Count + UINT16 CipherSuites[]
        //
        TlsCipherEntrySize = EcitEntrySize (sizeof (UINT16) + TlsCipherDataSize);
      }
    } else {
      TlsCipherCount    = 0;
      TlsCipherDataSize = 0;
    }
  }

  //
  // Total table size: header + 3 base entries + optional TLS entries.
  //
  NumberOfEntries = 3;
  TableSize       = sizeof (EFI_CRYPTO_INDICATOR_TABLE) +
                    ImageVerifEntrySize +
                    SecBootAuthEntrySize +
                    AuthVarEntrySize;

  if (TlsVersionEntrySize > 0) {
    TableSize += TlsVersionEntrySize;
    NumberOfEntries++;
  }

  if (TlsCipherEntrySize > 0) {
    TableSize += TlsCipherEntrySize;
    NumberOfEntries++;
  }

  Table = AllocateZeroPool (TableSize);
  if (Table == NULL) {
    DEBUG ((DEBUG_ERROR, "CryptoIndicatorTableDxe: Failed to allocate table\n"));
    FreePool (FilteredOids);
    if (TlsVersions != NULL) {
      FreePool (TlsVersions);
    }

    if (TlsCipherSuites != NULL) {
      FreePool (TlsCipherSuites);
    }

    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Fill table header.
  //
  Table->Version         = EFI_CRYPTO_INDICATOR_TABLE_VERSION;
  Table->NumberOfEntries = NumberOfEntries;
  Table->Reserved        = 0;

  Buffer = (UINT8 *)Table + sizeof (EFI_CRYPTO_INDICATOR_TABLE);

  //
  // Entry 1: Image Verification
  //
  Entry = (EFI_CRYPTO_INDICATOR_ENTRY *)Buffer;
  CopyGuid (&Entry->FeatureIdentifier, &gEfiEcitFeatureImageVerificationGuid);
  Entry->EntryLength = ImageVerifEntrySize;
  ZeroMem (Entry->Reserved, sizeof (Entry->Reserved));
  AsciiStrCpyS (
    (CHAR8 *)(Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY)),
    FilteredOidLen,
    FilteredOids
    );
  Buffer += ImageVerifEntrySize;

  //
  // Entry 2: Secure Boot Authorization
  //
  Entry = (EFI_CRYPTO_INDICATOR_ENTRY *)Buffer;
  CopyGuid (&Entry->FeatureIdentifier, &gEfiEcitFeatureSecureBootAuthorizationGuid);
  Entry->EntryLength = SecBootAuthEntrySize;
  ZeroMem (Entry->Reserved, sizeof (Entry->Reserved));
  CopyMem (
    Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY),
    mSecureBootAuthTypes,
    SecBootAuthDataSize
    );
  Buffer += SecBootAuthEntrySize;

  //
  // Entry 3: Authenticated Variable
  //
  Entry = (EFI_CRYPTO_INDICATOR_ENTRY *)Buffer;
  CopyGuid (&Entry->FeatureIdentifier, &gEfiEcitFeatureAuthenticatedVariableGuid);
  Entry->EntryLength = AuthVarEntrySize;
  ZeroMem (Entry->Reserved, sizeof (Entry->Reserved));
  AsciiStrCpyS (
    (CHAR8 *)(Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY)),
    AllOidLen,
    AllOids
    );
  Buffer += AuthVarEntrySize;

  //
  // Entry 4 (optional): TLS Version
  // Data format: UINT16 Count + UINT16 Versions[]
  //
  if ((TlsVersions != NULL) && (TlsVersionEntrySize > 0)) {
    UINT16  VersionCount16;
    UINT8   *DataPtr;

    Entry = (EFI_CRYPTO_INDICATOR_ENTRY *)Buffer;
    CopyGuid (&Entry->FeatureIdentifier, &gEfiEcitFeatureTlsVersionGuid);
    Entry->EntryLength = TlsVersionEntrySize;
    ZeroMem (Entry->Reserved, sizeof (Entry->Reserved));

    DataPtr = Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY);
    VersionCount16 = (UINT16)TlsVersionCount;
    CopyMem (DataPtr, &VersionCount16, sizeof (UINT16));
    CopyMem (DataPtr + sizeof (UINT16), TlsVersions, TlsVersionDataSize);
    Buffer += TlsVersionEntrySize;
  }

  //
  // Entry 5 (optional): TLS Cipher Suite
  // Data format: UINT16 Count + UINT16 CipherSuites[]
  //
  if ((TlsCipherSuites != NULL) && (TlsCipherEntrySize > 0)) {
    UINT16  CipherCount16;
    UINT8   *DataPtr;

    Entry = (EFI_CRYPTO_INDICATOR_ENTRY *)Buffer;
    CopyGuid (&Entry->FeatureIdentifier, &gEfiEcitFeatureTlsCipherSuiteGuid);
    Entry->EntryLength = TlsCipherEntrySize;
    ZeroMem (Entry->Reserved, sizeof (Entry->Reserved));

    DataPtr = Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY);
    CipherCount16 = (UINT16)TlsCipherCount;
    CopyMem (DataPtr, &CipherCount16, sizeof (UINT16));
    CopyMem (DataPtr + sizeof (UINT16), TlsCipherSuites, TlsCipherDataSize);
    Buffer += TlsCipherEntrySize;
  }

  FreePool (FilteredOids);
  if (TlsVersions != NULL) {
    FreePool (TlsVersions);
  }

  if (TlsCipherSuites != NULL) {
    FreePool (TlsCipherSuites);
  }

  //
  // Install the table as an EFI Configuration Table.
  //
  Status = gBS->InstallConfigurationTable (
                  &gEfiCryptoIndicatorTableGuid,
                  (VOID *)Table
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "CryptoIndicatorTableDxe: InstallConfigurationTable failed - %r\n", Status));
    FreePool (Table);
    return Status;
  }

  DEBUG ((DEBUG_INFO, "CryptoIndicatorTableDxe: ECIT installed with %d entries\n", Table->NumberOfEntries));
  return EFI_SUCCESS;
}
