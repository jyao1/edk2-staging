/** @file
  UEFI Shell application to dump the EFI Crypto Indicator Table (ECIT).

  Locates the ECIT from the EFI Configuration Table and prints the contents
  of each entry in human-readable form.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Guid/CryptoIndicatorTable.h>
#include <Guid/ImageAuthentication.h>

///
/// ECIT entry data format types.
///
typedef enum {
  EcitDataTypeOid,           ///< Null-terminated CSV ASCII OID string
  EcitDataTypeGuidArray,     ///< Array of EFI_GUID
  EcitDataTypeTlsVersion,    ///< Array of UINT16 TLS version values
  EcitDataTypeTlsCipher,     ///< Array of UINT16 IANA cipher suite IDs
  EcitDataTypeTlsGroup,      ///< Array of UINT16 IANA named group IDs
  EcitDataTypeTlsSigAlg,      ///< Array of UINT16 IANA SignatureScheme IDs
} ECIT_DATA_TYPE;

///
/// Known ECIT feature identifiers with human-readable names.
///
typedef struct {
  EFI_GUID        *Guid;
  CONST CHAR16    *Name;
  ECIT_DATA_TYPE  DataType;
} ECIT_FEATURE_INFO;

STATIC ECIT_FEATURE_INFO  mKnownFeatures[] = {
  { &gEfiEcitFeatureImageVerificationGuid,        L"Image Verification",          EcitDataTypeOid        },
  { &gEfiEcitFeatureSecureBootAuthorizationGuid,   L"Secure Boot Authorization",   EcitDataTypeGuidArray  },
  { &gEfiEcitFeatureImageRevocationGuid,           L"Image Revocation",            EcitDataTypeGuidArray  },
  { &gEfiEcitFeatureSecureBootServicingAuthorizationGuid, L"Secure Boot Servicing Authorization", EcitDataTypeGuidArray },
  { &gEfiEcitFeatureAuthenticatedVariableGuid,     L"Authenticated Variable",      EcitDataTypeOid        },
  { &gEfiEcitFeatureSystemFirmwareUpdateGuid,      L"System Firmware Update",      EcitDataTypeOid        },
  { &gEfiEcitFeatureEsrtFirmwareUpdateGuid,        L"ESRT Firmware Update",        EcitDataTypeOid        },
  { &gEfiEcitFeatureTlsVersionGuid,               L"TLS Version",                 EcitDataTypeTlsVersion },
  { &gEfiEcitFeatureTlsCipherSuiteGuid,           L"TLS Cipher Suite",            EcitDataTypeTlsCipher  },
  { &gEfiEcitFeatureTlsGroupGuid,                  L"TLS Key Exchange Group",      EcitDataTypeTlsGroup   },
  { &gEfiEcitFeatureTlsSignatureSchemeGuid,       L"TLS Signature Scheme",        EcitDataTypeTlsSigAlg  },
};

///
/// Known EFI_SIGNATURE_LIST type GUIDs with human-readable names.
///
typedef struct {
  EFI_GUID      *Guid;
  CONST CHAR16  *Name;
} GUID_NAME_ENTRY;

STATIC GUID_NAME_ENTRY  mKnownSigTypes[] = {
  { &gEfiCertX509Guid,         L"EFI_CERT_X509"          },
  { &gEfiCertSha256Guid,       L"EFI_CERT_SHA256"         },
  { &gEfiCertSha384Guid,       L"EFI_CERT_SHA384"         },
  { &gEfiCertSha512Guid,       L"EFI_CERT_SHA512"         },
  { &gEfiCertX509Sha256Guid,   L"EFI_CERT_X509_SHA256"    },
  { &gEfiCertX509Sha384Guid,   L"EFI_CERT_X509_SHA384"    },
  { &gEfiCertX509Sha512Guid,   L"EFI_CERT_X509_SHA512"    },
  { &gEfiCertV2X509Guid,       L"EFI_CERT_V2_X509"        },
  { &gEfiCertV2Sha256Guid,     L"EFI_CERT_V2_SHA256"      },
  { &gEfiCertV2Sha384Guid,     L"EFI_CERT_V2_SHA384"      },
  { &gEfiCertV2Sha512Guid,     L"EFI_CERT_V2_SHA512"      },
  { &gEfiCertV2X509Sha256Guid, L"EFI_CERT_V2_X509_SHA256" },
  { &gEfiCertV2X509Sha384Guid, L"EFI_CERT_V2_X509_SHA384" },
  { &gEfiCertV2X509Sha512Guid, L"EFI_CERT_V2_X509_SHA512" },
};

/**
  Look up a human-readable name for a feature identifier GUID.

  @param[in]  Guid      Pointer to the feature identifier GUID.
  @param[out] DataType  Optional. If non-NULL, filled with the data format type.

  @return  Human-readable name, or NULL if unrecognized.
**/
STATIC
CONST CHAR16 *
LookupFeatureName (
  IN  EFI_GUID        *Guid,
  OUT ECIT_DATA_TYPE  *DataType  OPTIONAL
  )
{
  UINTN  Index;

  for (Index = 0; Index < ARRAY_SIZE (mKnownFeatures); Index++) {
    if (CompareGuid (Guid, mKnownFeatures[Index].Guid)) {
      if (DataType != NULL) {
        *DataType = mKnownFeatures[Index].DataType;
      }

      return mKnownFeatures[Index].Name;
    }
  }

  return NULL;
}

/**
  Look up a human-readable name for a signature type GUID.

  @param[in]  Guid  Pointer to the signature type GUID.

  @return  Human-readable name, or NULL if unrecognized.
**/
STATIC
CONST CHAR16 *
LookupSigTypeName (
  IN EFI_GUID  *Guid
  )
{
  UINTN  Index;

  for (Index = 0; Index < ARRAY_SIZE (mKnownSigTypes); Index++) {
    if (CompareGuid (Guid, mKnownSigTypes[Index].Guid)) {
      return mKnownSigTypes[Index].Name;
    }
  }

  return NULL;
}

/**
  Print a GUID-array entry (e.g., Secure Boot Authorization).

  @param[in] Data      Pointer to the entry data (array of EFI_GUID).
  @param[in] DataSize  Size of the data in bytes.
**/
STATIC
VOID
PrintGuidArrayEntry (
  IN UINT8  *Data,
  IN UINTN  DataSize
  )
{
  UINTN          Count;
  UINTN          Index;
  EFI_GUID       *GuidArray;
  CONST CHAR16   *Name;

  Count    = DataSize / sizeof (EFI_GUID);
  GuidArray = (EFI_GUID *)Data;

  Print (L"    GUID array (%u entries):\n", Count);

  for (Index = 0; Index < Count; Index++) {
    Name = LookupSigTypeName (&GuidArray[Index]);
    if (Name != NULL) {
      Print (L"      [%u] %g  %s\n", Index, &GuidArray[Index], Name);
    } else {
      Print (L"      [%u] %g\n", Index, &GuidArray[Index]);
    }
  }
}

/**
  Print an OID CSV entry (e.g., Image Verification, Authenticated Variable).

  @param[in] Data      Pointer to the entry data (null-terminated ASCII CSV).
  @param[in] DataSize  Size of the data in bytes.
**/
STATIC
VOID
PrintOidEntry (
  IN UINT8  *Data,
  IN UINTN  DataSize
  )
{
  CHAR8  *OidString;

  OidString = (CHAR8 *)Data;

  Print (L"    OID list: ");

  //
  // Print the ASCII OID string as Unicode character by character.
  //
  while (*OidString != '\0') {
    if (*OidString == ',') {
      Print (L"\n              ");
    } else {
      Print (L"%c", (CHAR16)*OidString);
    }

    OidString++;
  }

  Print (L"\n");
}

/**
  Get a human-readable name for a TLS protocol version.

  @param[in] Version  TLS version value (e.g. 0x0301).

  @return  Name string, or "Unknown".
**/
STATIC
CONST CHAR16 *
TlsVersionName (
  IN UINT16  Version
  )
{
  switch (Version) {
    case 0x0301:
      return L"TLS 1.0";
    case 0x0302:
      return L"TLS 1.1";
    case 0x0303:
      return L"TLS 1.2";
    case 0x0304:
      return L"TLS 1.3";
    default:
      return L"Unknown";
  }
}

///
/// Known IANA TLS cipher suite IDs with human-readable names.
///
typedef struct {
  UINT16        Id;
  CONST CHAR16  *Name;
} CIPHER_SUITE_NAME;

STATIC CIPHER_SUITE_NAME  mKnownCipherSuites[] = {
  { 0x002F, L"TLS_RSA_WITH_AES_128_CBC_SHA"             },
  { 0x0033, L"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"         },
  { 0x0035, L"TLS_RSA_WITH_AES_256_CBC_SHA"             },
  { 0x0039, L"TLS_DHE_RSA_WITH_AES_256_CBC_SHA"         },
  { 0x003C, L"TLS_RSA_WITH_AES_128_CBC_SHA256"          },
  { 0x003D, L"TLS_RSA_WITH_AES_256_CBC_SHA256"          },
  { 0x0067, L"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"      },
  { 0x006B, L"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"      },
  { 0x009C, L"TLS_RSA_WITH_AES_128_GCM_SHA256"          },
  { 0x009D, L"TLS_RSA_WITH_AES_256_GCM_SHA384"          },
  { 0x009E, L"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"      },
  { 0x009F, L"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"      },
  { 0x1301, L"TLS_AES_128_GCM_SHA256"                   },
  { 0x1302, L"TLS_AES_256_GCM_SHA384"                   },
  { 0x1303, L"TLS_CHACHA20_POLY1305_SHA256"             },
  { 0xC009, L"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"     },
  { 0xC00A, L"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"     },
  { 0xC013, L"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"       },
  { 0xC014, L"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"       },
  { 0xC023, L"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"  },
  { 0xC024, L"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"  },
  { 0xC027, L"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"    },
  { 0xC028, L"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"    },
  { 0xC02B, L"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"  },
  { 0xC02C, L"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"  },
  { 0xC02F, L"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"    },
  { 0xC030, L"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"    },
  { 0xCCA8, L"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"     },
  { 0xCCA9, L"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"   },
  { 0xCCAA, L"TLS_DHE_RSA_WITH_CHACHA20_POLY1305"       },
};

///
/// Known IANA TLS named group IDs with human-readable names.
///
typedef struct {
  UINT16        Id;
  CONST CHAR16  *Name;
} GROUP_NAME;

STATIC GROUP_NAME  mKnownGroups[] = {
  { 0x0017, L"secp256r1"          },
  { 0x0018, L"secp384r1"          },
  { 0x0019, L"secp521r1"          },
  { 0x001D, L"x25519"             },
  { 0x001E, L"x448"               },
  { 0x0100, L"ffdhe2048"          },
  { 0x0101, L"ffdhe3072"          },
  { 0x0102, L"ffdhe4096"          },
  { 0x0103, L"ffdhe6144"          },
  { 0x0104, L"ffdhe8192"          },
  { 0x0200, L"ML-KEM-512"         },
  { 0x0201, L"ML-KEM-768"         },
  { 0x0202, L"ML-KEM-1024"        },
  { 0x4588, L"X25519MLKEM768"     },
  { 0x4589, L"SecP256r1MLKEM768"  },
  { 0x4590, L"X448MLKEM1024"      },
  { 0x4591, L"SecP384r1MLKEM1024" },
};

///
/// Known TLS SignatureScheme IDs with human-readable names.
///
typedef struct {
  UINT16        Id;
  CONST CHAR16  *Name;
} SIGALG_NAME;

STATIC SIGALG_NAME  mKnownSigAlgs[] = {
  // ECDSA
  { 0x0403, L"ecdsa_secp256r1_sha256"          },
  { 0x0503, L"ecdsa_secp384r1_sha384"          },
  { 0x0603, L"ecdsa_secp521r1_sha512"          },
  { 0x0303, L"ecdsa_sha224"                    },
  { 0x0203, L"ecdsa_sha1"                      },
  // EdDSA
  { 0x0807, L"ed25519"                         },
  { 0x0808, L"ed448"                           },
  // RSA-PSS (RSAE)
  { 0x0804, L"rsa_pss_rsae_sha256"             },
  { 0x0805, L"rsa_pss_rsae_sha384"             },
  { 0x0806, L"rsa_pss_rsae_sha512"             },
  // RSA-PSS (PSS)
  { 0x0809, L"rsa_pss_pss_sha256"              },
  { 0x080a, L"rsa_pss_pss_sha384"              },
  { 0x080b, L"rsa_pss_pss_sha512"              },
  // RSA PKCS#1 v1.5
  { 0x0401, L"rsa_pkcs1_sha256"                },
  { 0x0501, L"rsa_pkcs1_sha384"                },
  { 0x0601, L"rsa_pkcs1_sha512"                },
  { 0x0301, L"rsa_pkcs1_sha224"                },
  { 0x0201, L"rsa_pkcs1_sha1"                  },
  // Brainpool ECDSA (TLS 1.3)
  { 0x081a, L"ecdsa_brainpoolP256r1_sha256"    },
  { 0x081b, L"ecdsa_brainpoolP384r1_sha384"    },
  { 0x081c, L"ecdsa_brainpoolP512r1_sha512"    },
  // PQC -- ML-DSA (FIPS 204)
  { 0x0904, L"mldsa44"                         },
  { 0x0905, L"mldsa65"                         },
  { 0x0906, L"mldsa87"                         },
};

/**
  Print a TLS Version entry.

  Data format: UINT16 Count followed by Count UINT16 version values.

  @param[in] Data      Pointer to the entry data.
  @param[in] DataSize  Size of the data in bytes.
**/
STATIC
VOID
PrintTlsVersionEntry (
  IN UINT8  *Data,
  IN UINTN  DataSize
  )
{
  UINT16  Count;
  UINTN   Index;
  UINT16  *Versions;

  if (DataSize < sizeof (UINT16)) {
    Print (L"    (invalid TLS version data)\n");
    return;
  }

  CopyMem (&Count, Data, sizeof (UINT16));
  Versions = (UINT16 *)(Data + sizeof (UINT16));

  Print (L"    TLS versions (%u entries):\n", Count);

  for (Index = 0; Index < Count; Index++) {
    Print (L"      [%u] 0x%04x  %s\n", Index, Versions[Index], TlsVersionName (Versions[Index]));
  }
}

/**
  Print a TLS Cipher Suite entry.

  Data format: UINT16 Count followed by Count UINT16 IANA cipher suite IDs.

  @param[in] Data      Pointer to the entry data.
  @param[in] DataSize  Size of the data in bytes.
**/
STATIC
VOID
PrintTlsCipherSuiteEntry (
  IN UINT8  *Data,
  IN UINTN  DataSize
  )
{
  UINT16         Count;
  UINTN          Index;
  UINTN          Idx;
  UINT16         *Suites;
  CONST CHAR16   *Name;

  if (DataSize < sizeof (UINT16)) {
    Print (L"    (invalid TLS cipher suite data)\n");
    return;
  }

  CopyMem (&Count, Data, sizeof (UINT16));
  Suites = (UINT16 *)(Data + sizeof (UINT16));

  Print (L"    TLS cipher suites (%u entries):\n", Count);

  for (Index = 0; Index < Count; Index++) {
    Name = NULL;
    for (Idx = 0; Idx < ARRAY_SIZE (mKnownCipherSuites); Idx++) {
      if (mKnownCipherSuites[Idx].Id == Suites[Index]) {
        Name = mKnownCipherSuites[Idx].Name;
        break;
      }
    }

    if (Name != NULL) {
      Print (L"      [%u] 0x%04x  %s\n", Index, Suites[Index], Name);
    } else {
      Print (L"      [%u] 0x%04x\n", Index, Suites[Index]);
    }
  }
}

/**
  Print a TLS Key Exchange Group entry.

  Data format: UINT16 Count followed by Count UINT16 IANA named group IDs.

  @param[in] Data      Pointer to the entry data.
  @param[in] DataSize  Size of the data in bytes.
**/
STATIC
VOID
PrintTlsGroupEntry (
  IN UINT8  *Data,
  IN UINTN  DataSize
  )
{
  UINT16         Count;
  UINTN          Index;
  UINTN          Idx;
  UINT16         *Groups;
  CONST CHAR16   *Name;

  if (DataSize < sizeof (UINT16)) {
    Print (L"    (invalid TLS group data)\n");
    return;
  }

  CopyMem (&Count, Data, sizeof (UINT16));
  Groups = (UINT16 *)(Data + sizeof (UINT16));

  Print (L"    TLS key exchange groups (%u entries):\n", Count);

  for (Index = 0; Index < Count; Index++) {
    Name = NULL;
    for (Idx = 0; Idx < ARRAY_SIZE (mKnownGroups); Idx++) {
      if (mKnownGroups[Idx].Id == Groups[Index]) {
        Name = mKnownGroups[Idx].Name;
        break;
      }
    }

    if (Name != NULL) {
      Print (L"      [%u] 0x%04x  %s\n", Index, Groups[Index], Name);
    } else {
      Print (L"      [%u] 0x%04x\n", Index, Groups[Index]);
    }
  }
}

/**
  Print a TLS Signature Algorithm entry.

  Data format: UINT16 Count followed by Count UINT16 IANA SignatureScheme IDs.

  @param[in] Data      Pointer to the entry data.
  @param[in] DataSize  Size of the data in bytes.
**/
STATIC
VOID
PrintTlsSigAlgEntry (
  IN UINT8  *Data,
  IN UINTN  DataSize
  )
{
  UINT16         Count;
  UINTN          Index;
  UINTN          Idx;
  UINT16         *SigAlgs;
  CONST CHAR16   *Name;

  if (DataSize < sizeof (UINT16)) {
    Print (L"    (invalid TLS signature algorithm data)\n");
    return;
  }

  CopyMem (&Count, Data, sizeof (UINT16));
  SigAlgs = (UINT16 *)(Data + sizeof (UINT16));

  Print (L"    TLS signature algorithms (%u entries):\n", Count);

  for (Index = 0; Index < Count; Index++) {
    Name = NULL;
    for (Idx = 0; Idx < ARRAY_SIZE (mKnownSigAlgs); Idx++) {
      if (mKnownSigAlgs[Idx].Id == SigAlgs[Index]) {
        Name = mKnownSigAlgs[Idx].Name;
        break;
      }
    }

    if (Name != NULL) {
      Print (L"      [%u] 0x%04x  %s\n", Index, SigAlgs[Index], Name);
    } else {
      Print (L"      [%u] 0x%04x\n", Index, SigAlgs[Index]);
    }
  }
}

/**
  UEFI application entry point.

  Locates and dumps the EFI Crypto Indicator Table from the
  EFI Configuration Table.

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The table was found and dumped.
  @retval EFI_NOT_FOUND   The table was not found.
**/
EFI_STATUS
EFIAPI
DumpCryptoIndicatorTableMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  UINTN                        Index;
  EFI_CRYPTO_INDICATOR_TABLE   *Table;
  EFI_CRYPTO_INDICATOR_ENTRY   *Entry;
  UINT8                        *Buffer;
  CONST CHAR16                 *FeatureName;
  ECIT_DATA_TYPE               DataType;
  UINTN                        DataSize;

  //
  // Search EFI Configuration Table for the ECIT.
  //
  Table = NULL;
  for (Index = 0; Index < SystemTable->NumberOfTableEntries; Index++) {
    if (CompareGuid (&SystemTable->ConfigurationTable[Index].VendorGuid, &gEfiCryptoIndicatorTableGuid)) {
      Table = (EFI_CRYPTO_INDICATOR_TABLE *)SystemTable->ConfigurationTable[Index].VendorTable;
      break;
    }
  }

  if (Table == NULL) {
    Print (L"EFI Crypto Indicator Table not found.\n");
    return EFI_NOT_FOUND;
  }

  //
  // Print table header.
  //
  Print (L"=== EFI Crypto Indicator Table (ECIT) ===\n");
  Print (L"  Version:          %u\n", Table->Version);
  Print (L"  NumberOfEntries:  %u\n", Table->NumberOfEntries);
  Print (L"\n");

  //
  // Walk entries.
  //
  Buffer = (UINT8 *)Table + sizeof (EFI_CRYPTO_INDICATOR_TABLE);

  for (Index = 0; Index < Table->NumberOfEntries; Index++) {
    Entry = (EFI_CRYPTO_INDICATOR_ENTRY *)Buffer;

    Print (L"--- Entry %u ---\n", Index);
    Print (L"  FeatureIdentifier: %g\n", &Entry->FeatureIdentifier);

    FeatureName = LookupFeatureName (&Entry->FeatureIdentifier, &DataType);
    if (FeatureName != NULL) {
      Print (L"  Feature:           %s\n", FeatureName);
    } else {
      Print (L"  Feature:           (unknown)\n");
      DataType = EcitDataTypeOid;  // default: try to print as OID string
    }

    Print (L"  EntryLength:       %u bytes\n", Entry->EntryLength);

    DataSize = Entry->EntryLength - sizeof (EFI_CRYPTO_INDICATOR_ENTRY);
    if (DataSize > 0) {
      switch (DataType) {
        case EcitDataTypeOid:
          PrintOidEntry (
            Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY),
            DataSize
            );
          break;
        case EcitDataTypeGuidArray:
          PrintGuidArrayEntry (
            Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY),
            DataSize
            );
          break;
        case EcitDataTypeTlsVersion:
          PrintTlsVersionEntry (
            Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY),
            DataSize
            );
          break;
        case EcitDataTypeTlsCipher:
          PrintTlsCipherSuiteEntry (
            Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY),
            DataSize
            );
          break;
        case EcitDataTypeTlsGroup:
          PrintTlsGroupEntry (
            Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY),
            DataSize
            );
          break;
        case EcitDataTypeTlsSigAlg:
          PrintTlsSigAlgEntry (
            Buffer + sizeof (EFI_CRYPTO_INDICATOR_ENTRY),
            DataSize
            );
          break;
      }
    }

    Print (L"\n");
    Buffer += Entry->EntryLength;
  }

  Print (L"=== End of ECIT ===\n");
  return EFI_SUCCESS;
}
