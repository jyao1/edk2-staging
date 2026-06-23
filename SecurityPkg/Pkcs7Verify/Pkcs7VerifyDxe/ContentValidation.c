/** @file
  Shared, phase-independent X.509 certificate-hash matching for the UEFI image
  security databases (db/dbx).

  The functions here answer the question "is the To-Be-Signed hash of this X.509
  certificate present in this EFI_SIGNATURE_LIST?" for the cert-hash signature
  types (EFI_CERT_X509_SHAxxx and the EFI_CERT_V2_X509_SHAxxx variants). The
  logic is identical for image verification (db/dbx) and for the PKCS#7
  verification protocol, so this source file is kept byte-identical between
  DxeImageVerificationLib and Pkcs7VerifyDxe.

  Only phase-independent (Base-class) APIs are used - BaseLib, BaseMemoryLib,
  MemoryAllocationLib and BaseCryptLib - so the same code compiles unchanged in
  any consuming module. All boot/runtime-services access (e.g. reading the db/dbx
  variables) stays in the phase-dependent source of each consumer.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseCryptLib.h>
#include <Guid/ImageAuthentication.h>

#include "ContentValidation.h"

#define CONTENT_VALIDATION_MAX_DIGEST_SIZE  SHA512_DIGEST_SIZE

//
// Internal types for the AllowedDb decision rule (ProcessAllowedDbList). These
// are implementation details of Pkcs7VerifyContent() and are not exposed in
// ContentValidation.h.
//

//
// Callback: verify that the signature verifies up to the given certificate (the
// candidate trust anchor) - e.g. AuthenticodeVerify() against a PE image digest,
// or Pkcs7Verify() against content.
//
typedef
BOOLEAN
(*CONTENT_VALIDATION_VERIFY_UP_TO_CERT) (
  IN VOID   *Context,
  IN UINT8  *Cert,
  IN UINTN  CertSize
  );

//
// Callback: check whether the trust anchor and the certificates below it (toward
// the leaf) are allowed by dbx (UEFI Spec 32.5.3.3); certificates above the
// anchor are ignored.
//
typedef
BOOLEAN
(*CONTENT_VALIDATION_CHAIN_ALLOWED_BY_DBX) (
  IN VOID   *Context,
  IN UINT8  *Anchor,
  IN UINTN  AnchorSize
  );

//
// Result of evaluating one AllowedDb signature list against the signature.
//
typedef enum {
  ContentValidationDbContinue = 0, ///< Not decided by this list; keep iterating.
  ContentValidationDbAllowed,      ///< Verified by a db anchor and not revoked.
  ContentValidationDbRevoked       ///< Verified by a db anchor but revoked in dbx.
} CONTENT_VALIDATION_DB_RESULT;

/**
  Compute the SHA-256/384/512 digest of a data buffer using BaseCryptLib.

  @param[in]  HashSize  Digest length in bytes; selects the algorithm
                        (SHA256_DIGEST_SIZE, SHA384_DIGEST_SIZE or
                        SHA512_DIGEST_SIZE).
  @param[in]  Data      Pointer to the data to hash.
  @param[in]  DataSize  Size of Data in bytes.
  @param[out] Digest    Buffer to receive the digest; must be at least HashSize
                        bytes (CONTENT_VALIDATION_MAX_DIGEST_SIZE is always safe).

  @retval TRUE   The digest was computed.
  @retval FALSE  The algorithm is unsupported or hashing failed.

**/
BOOLEAN
ContentValidationHashData (
  IN  UINTN  HashSize,
  IN  UINT8  *Data,
  IN  UINTN  DataSize,
  OUT UINT8  *Digest
  )
{
  BOOLEAN  Status;
  VOID     *HashCtx;
  UINTN    CtxSize;

  Status  = FALSE;
  HashCtx = NULL;

  switch (HashSize) {
    case SHA256_DIGEST_SIZE:
      CtxSize = Sha256GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      if (HashCtx == NULL) {
        return FALSE;
      }

      Status = Sha256Init (HashCtx);
      if (Status) {
        Status = Sha256Update (HashCtx, Data, DataSize);
      }

      if (Status) {
        Status = Sha256Final (HashCtx, Digest);
      }

      break;

    case SHA384_DIGEST_SIZE:
      CtxSize = Sha384GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      if (HashCtx == NULL) {
        return FALSE;
      }

      Status = Sha384Init (HashCtx);
      if (Status) {
        Status = Sha384Update (HashCtx, Data, DataSize);
      }

      if (Status) {
        Status = Sha384Final (HashCtx, Digest);
      }

      break;

    case SHA512_DIGEST_SIZE:
      CtxSize = Sha512GetContextSize ();
      HashCtx = AllocatePool (CtxSize);
      if (HashCtx == NULL) {
        return FALSE;
      }

      Status = Sha512Init (HashCtx);
      if (Status) {
        Status = Sha512Update (HashCtx, Data, DataSize);
      }

      if (Status) {
        Status = Sha512Final (HashCtx, Digest);
      }

      break;

    default:
      return FALSE;
  }

  if (HashCtx != NULL) {
    FreePool (HashCtx);
  }

  return Status;
}

/**
  Check whether the hash of a given X.509 certificate is in the specified
  signature list.

  @param[in]  Certificate       Pointer to X.509 Certificate that is searched for.
  @param[in]  CertSize          Size of X.509 Certificate.
  @param[in]  SignatureList     Pointer to the Signature List to search.
  @param[in]  SignatureListSize Size of Signature List.
  @param[out] IsFound           Search result. Only valid if EFI_SUCCESS returned.
  @param[out] MatchedSigData    Return the matched signature data node. Optional.

  @retval EFI_SUCCESS           Finished the search; *IsFound holds the result.
  @retval EFI_INVALID_PARAMETER SignatureList is NULL.
  @retval EFI_NOT_FOUND         No matching cert hash was found.
  @retval Others                Error occurred during the search.

**/
EFI_STATUS
IsCertHashFoundInSigList (
  IN  UINT8               *Certificate,
  IN  UINTN               CertSize,
  IN  EFI_SIGNATURE_LIST  *SignatureList,
  IN  UINTN               SignatureListSize,
  OUT BOOLEAN             *IsFound,
  OUT EFI_SIGNATURE_DATA  **MatchedSigData OPTIONAL
  )
{
  EFI_STATUS          Status;
  EFI_SIGNATURE_LIST  *SigList;
  UINTN               SigSize;
  EFI_SIGNATURE_DATA  *CertHash;
  UINTN               CertHashCount;
  UINTN               Index;
  UINTN               HashSize;
  UINT8               CertDigest[CONTENT_VALIDATION_MAX_DIGEST_SIZE];
  UINT8               *SigCertHash;
  UINTN               SiglistHeaderSize;
  UINT8               *TBSCert;
  UINTN               TBSCertSize;
  BOOLEAN             IsV2;

  Status   = EFI_ABORTED;
  *IsFound = FALSE;
  SigList  = SignatureList;
  SigSize  = SignatureListSize;

  if (SigList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (MatchedSigData != NULL) {
    *MatchedSigData = NULL;
  }

  //
  // Retrieve the TBSCertificate from the X.509 Certificate.
  //
  if (!X509GetTBSCert (Certificate, CertSize, &TBSCert, &TBSCertSize)) {
    return Status;
  }

  while ((SigSize > 0) && (SigSize >= SigList->SignatureListSize)) {
    //
    // Determine Hash Algorithm of Certificate in the signature list.
    //
    IsV2 = FALSE;
    if (CompareGuid (&SigList->SignatureType, &gEfiCertX509Sha256Guid)) {
      HashSize = SHA256_DIGEST_SIZE;
    } else if (CompareGuid (&SigList->SignatureType, &gEfiCertV2X509Sha256Guid)) {
      HashSize = SHA256_DIGEST_SIZE;
      IsV2     = TRUE;
    } else if (CompareGuid (&SigList->SignatureType, &gEfiCertX509Sha384Guid)) {
      HashSize = SHA384_DIGEST_SIZE;
    } else if (CompareGuid (&SigList->SignatureType, &gEfiCertV2X509Sha384Guid)) {
      HashSize = SHA384_DIGEST_SIZE;
      IsV2     = TRUE;
    } else if (CompareGuid (&SigList->SignatureType, &gEfiCertX509Sha512Guid)) {
      HashSize = SHA512_DIGEST_SIZE;
    } else if (CompareGuid (&SigList->SignatureType, &gEfiCertV2X509Sha512Guid)) {
      HashSize = SHA512_DIGEST_SIZE;
      IsV2     = TRUE;
    } else {
      SigSize -= SigList->SignatureListSize;
      SigList  = (EFI_SIGNATURE_LIST *)((UINT8 *)SigList + SigList->SignatureListSize);
      continue;
    }

    //
    // Calculate the hash value of current TBSCertificate for comparison.
    //
    ZeroMem (CertDigest, CONTENT_VALIDATION_MAX_DIGEST_SIZE);
    if (!ContentValidationHashData (HashSize, TBSCert, TBSCertSize, CertDigest)) {
      goto Done;
    }

    SiglistHeaderSize = sizeof (EFI_SIGNATURE_LIST) + SigList->SignatureHeaderSize;
    CertHash          = (EFI_SIGNATURE_DATA *)((UINT8 *)SigList + SiglistHeaderSize);
    CertHashCount     = (SigList->SignatureListSize - SiglistHeaderSize) / SigList->SignatureSize;
    for (Index = 0; Index < CertHashCount; Index++) {
      //
      // Iterate each Signature Data Node within this CertList for verify.
      // V2 types use EFI_SIGNATURE_V2_DATA (no SignatureOwner prefix).
      //
      if (IsV2) {
        SigCertHash = (UINT8 *)CertHash;
      } else {
        SigCertHash = CertHash->SignatureData;
      }

      if (CompareMem (SigCertHash, CertDigest, HashSize) == 0) {
        //
        // Hash of Certificate is found in signature list.
        //
        Status   = EFI_SUCCESS;
        *IsFound = TRUE;

        //
        // Return the matched signature data node.
        //
        if (MatchedSigData != NULL) {
          *MatchedSigData = CertHash;
        }

        goto Done;
      }

      CertHash = (EFI_SIGNATURE_DATA *)((UINT8 *)CertHash + SigList->SignatureSize);
    }

    SigSize -= SigList->SignatureListSize;
    SigList  = (EFI_SIGNATURE_LIST *)((UINT8 *)SigList + SigList->SignatureListSize);
  }

  Status = EFI_NOT_FOUND;

Done:
  return Status;
}

/**
  Check whether the hash of a given X.509 certificate is in a forbidden database
  (dbx) signature list.

  @param[in]  Certificate       Pointer to X.509 Certificate that is searched for.
  @param[in]  CertSize          Size of X.509 Certificate.
  @param[in]  SignatureList     Pointer to the Signature List in forbidden database.
  @param[in]  SignatureListSize Size of Signature List.
  @param[out] IsFound           Search result. Only valid if EFI_SUCCESS returned.

  @retval EFI_SUCCESS           Finished the search without any error.
  @retval EFI_INVALID_PARAMETER SignatureList is NULL.
  @retval Others                Error occurred in the search of the database.

**/
EFI_STATUS
IsCertHashFoundInDbx (
  IN  UINT8               *Certificate,
  IN  UINTN               CertSize,
  IN  EFI_SIGNATURE_LIST  *SignatureList,
  IN  UINTN               SignatureListSize,
  OUT BOOLEAN             *IsFound
  )
{
  EFI_STATUS  Status;

  if (SignatureList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = IsCertHashFoundInSigList (
             Certificate,
             CertSize,
             SignatureList,
             SignatureListSize,
             IsFound,
             NULL
             );
  if (Status == EFI_NOT_FOUND) {
    return EFI_SUCCESS;
  }

  return Status;
}

/**
  Check whether a content/data hash is present in a single content-hash
  signature list (EFI_CERT_SHAxxx or its EFI_CERT_V2_SHAxxx variant).

  @param[in]  Hash              Pointer to the content/data hash to search for.
  @param[in]  HashSize          Size of Hash in bytes.
  @param[in]  SignatureList     Pointer to a single EFI_SIGNATURE_LIST to search.
  @param[out] IsFound           Search result. Only valid if EFI_SUCCESS returned.
  @param[out] MatchedSigData    Return the matched signature data node. Optional.

  @retval EFI_SUCCESS           Finished the search; *IsFound holds the result.
  @retval EFI_INVALID_PARAMETER Hash or SignatureList is NULL.

**/
EFI_STATUS
IsContentHashFoundInSigList (
  IN  UINT8               *Hash,
  IN  UINTN               HashSize,
  IN  EFI_SIGNATURE_LIST  *SignatureList,
  OUT BOOLEAN             *IsFound,
  OUT EFI_SIGNATURE_DATA  **MatchedSigData OPTIONAL
  )
{
  EFI_SIGNATURE_DATA  *SigData;
  UINT8               *EntryHash;
  UINTN               EntryHashSize;
  UINTN               EntryCount;
  UINTN               Index;
  BOOLEAN             IsV2;

  if ((Hash == NULL) || (SignatureList == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *IsFound = FALSE;
  if (MatchedSigData != NULL) {
    *MatchedSigData = NULL;
  }

  //
  // Only the pure content-hash signature types are matched. V2 types use
  // EFI_SIGNATURE_V2_DATA (no SignatureOwner prefix), so the hash starts at
  // offset 0 and SignatureSize equals the hash size; V1 types carry a
  // SignatureOwner GUID before the hash.
  //
  if (CompareGuid (&SignatureList->SignatureType, &gEfiCertSha256Guid) ||
      CompareGuid (&SignatureList->SignatureType, &gEfiCertSha384Guid) ||
      CompareGuid (&SignatureList->SignatureType, &gEfiCertSha512Guid))
  {
    IsV2 = FALSE;
  } else if (CompareGuid (&SignatureList->SignatureType, &gEfiCertV2Sha256Guid) ||
             CompareGuid (&SignatureList->SignatureType, &gEfiCertV2Sha384Guid) ||
             CompareGuid (&SignatureList->SignatureType, &gEfiCertV2Sha512Guid))
  {
    IsV2 = TRUE;
  } else {
    //
    // Not a content-hash list type.
    //
    return EFI_SUCCESS;
  }

  SigData = (EFI_SIGNATURE_DATA *)((UINT8 *)SignatureList + sizeof (EFI_SIGNATURE_LIST) +
                                   SignatureList->SignatureHeaderSize);
  EntryCount = (SignatureList->SignatureListSize - SignatureList->SignatureHeaderSize -
                sizeof (EFI_SIGNATURE_LIST)) / SignatureList->SignatureSize;
  for (Index = 0; Index < EntryCount; Index++) {
    if (IsV2) {
      EntryHash     = (UINT8 *)SigData;
      EntryHashSize = SignatureList->SignatureSize;
    } else {
      EntryHash     = SigData->SignatureData;
      EntryHashSize = SignatureList->SignatureSize - sizeof (EFI_GUID);
    }

    //
    // A mismatched length means a different hash algorithm; it cannot match.
    //
    if ((EntryHashSize == HashSize) && (CompareMem (EntryHash, Hash, HashSize) == 0)) {
      *IsFound = TRUE;
      if (MatchedSigData != NULL) {
        *MatchedSigData = SigData;
      }

      break;
    }

    SigData = (EFI_SIGNATURE_DATA *)((UINT8 *)SigData + SignatureList->SignatureSize);
  }

  return EFI_SUCCESS;
}

/**
  Check whether a single X.509 certificate is revoked by a forbidden database
  (dbx) signature-list region.

  @param[in]  Certificate   Pointer to the X.509 certificate that is searched for.
  @param[in]  CertSize      Size of the certificate in bytes.
  @param[in]  DbxList       Pointer to the dbx signature-list region, or NULL if
                            dbx is absent.
  @param[in]  DbxListSize   Size of DbxList in bytes.

  @retval TRUE   The certificate is revoked, or the dbx search failed.
  @retval FALSE  The certificate is not revoked (including when dbx is absent).

**/
BOOLEAN
IsCertRevokedByDbxList (
  IN UINT8               *Certificate,
  IN UINTN               CertSize,
  IN EFI_SIGNATURE_LIST  *DbxList,
  IN UINTN               DbxListSize
  )
{
  EFI_STATUS  Status;
  BOOLEAN     IsFound;

  if ((DbxList == NULL) || (DbxListSize == 0)) {
    return FALSE;
  }

  IsFound = FALSE;
  Status  = IsCertHashFoundInDbx (Certificate, CertSize, DbxList, DbxListSize, &IsFound);
  if (EFI_ERROR (Status)) {
    //
    // Fail-safe: a failed dbx search is treated as revoked.
    //
    return TRUE;
  }

  return IsFound;
}

/**
  Find the index of a certificate within a signing-chain certificate buffer.

  @param[in]  CertBuffer    Signing-chain certificate buffer (cert stack format).
  @param[in]  TargetCert    Pointer to the DER certificate to locate.
  @param[in]  TargetSize    Size of TargetCert in bytes.

  @retval >= 0  The index of the matching certificate in the chain.
  @retval -1    The certificate is not present in the chain (or invalid input).

**/
STATIC
INTN
FindCertIndexInChain (
  IN UINT8  *CertBuffer,
  IN UINT8  *TargetCert,
  IN UINTN  TargetSize
  )
{
  UINT8  CertNumber;
  UINT8  *CertPtr;
  UINT8  *Cert;
  UINTN  CertSize;
  UINTN  Index;

  if ((CertBuffer == NULL) || (TargetCert == NULL)) {
    return -1;
  }

  CertNumber = (UINT8)(*CertBuffer);
  CertPtr    = CertBuffer + 1;
  for (Index = 0; Index < CertNumber; Index++) {
    CertSize = (UINTN)ReadUnaligned32 ((UINT32 *)CertPtr);
    Cert     = (UINT8 *)CertPtr + sizeof (UINT32);
    CertPtr  = CertPtr + sizeof (UINT32) + CertSize;

    if ((CertSize == TargetSize) && (CompareMem (Cert, TargetCert, CertSize) == 0)) {
      return (INTN)Index;
    }
  }

  return -1;
}

/**
  Check the trust anchor and the certificates below it (toward the leaf) in a
  signing chain against a forbidden database (dbx) signature list.

  @param[in]  CertBuffer    Signing-chain certificate buffer (cert stack format).
  @param[in]  AnchorIndex   Index of the trust anchor in CertBuffer; negative
                            means the anchor is above the whole chain so every
                            certificate is evaluated.
  @param[in]  DbxList       Pointer to the dbx signature-list region, or NULL if
                            dbx is absent.
  @param[in]  DbxListSize   Size of DbxList in bytes.

  @retval TRUE   Neither the anchor nor any certificate below it is revoked.
  @retval FALSE  The anchor or a certificate below it is revoked, or a dbx
                 search failed (fail-safe).

**/
STATIC
BOOLEAN
IsCertChainAllowedByDbx (
  IN UINT8               *CertBuffer,
  IN INTN                AnchorIndex,
  IN EFI_SIGNATURE_LIST  *DbxList,
  IN UINTN               DbxListSize
  )
{
  UINT8  CertNumber;
  UINT8  *CertPtr;
  UINT8  *Cert;
  UINTN  CertSize;
  UINTN  Index;

  //
  // No dbx: nothing can be revoked.
  //
  if ((DbxList == NULL) || (DbxListSize == 0)) {
    return TRUE;
  }

  if (CertBuffer == NULL) {
    return FALSE;
  }

  CertNumber = (UINT8)(*CertBuffer);
  CertPtr    = CertBuffer + 1;
  for (Index = 0; Index < CertNumber; Index++) {
    CertSize = (UINTN)ReadUnaligned32 ((UINT32 *)CertPtr);
    Cert     = (UINT8 *)CertPtr + sizeof (UINT32);
    CertPtr  = CertPtr + sizeof (UINT32) + CertSize;

    //
    // Certificates above the trust anchor (lower index, closer to the root) are
    // not evaluated against dbx. When AnchorIndex is negative the anchor is
    // above the whole chain, so every certificate is checked.
    //
    if ((AnchorIndex >= 0) && (Index < (UINTN)AnchorIndex)) {
      continue;
    }

    if (IsCertRevokedByDbxList (Cert, CertSize, DbxList, DbxListSize)) {
      return FALSE;
    }
  }

  return TRUE;
}

/**
  Evaluate one AllowedDb signature list against an image signature, per UEFI
  Spec 32.5.3.3.

  @param[in]  SigList            One AllowedDb EFI_SIGNATURE_LIST to evaluate.
  @param[in]  SignerCertChain    Signing-chain certificate buffer (cert stack
                                 format) for the cert-hash entry kind; may be NULL.
  @param[in]  VerifyUpToCert     Callback verifying the signature up to a cert.
  @param[in]  ChainAllowedByDbx  Callback for the anchor-relative dbx check.
  @param[in]  Context            Opaque context passed to both callbacks.
  @param[out] MatchedSigData     Optional matched AllowedDb node on "allowed".

  @return One of CONTENT_VALIDATION_DB_RESULT.

**/
STATIC
CONTENT_VALIDATION_DB_RESULT
ProcessAllowedDbList (
  IN  EFI_SIGNATURE_LIST                     *SigList,
  IN  UINT8                                  *SignerCertChain,
  IN  CONTENT_VALIDATION_VERIFY_UP_TO_CERT     VerifyUpToCert,
  IN  CONTENT_VALIDATION_CHAIN_ALLOWED_BY_DBX  ChainAllowedByDbx,
  IN  VOID                                   *Context,
  OUT EFI_SIGNATURE_DATA                     **MatchedSigData OPTIONAL
  )
{
  EFI_SIGNATURE_DATA  *SigData;
  EFI_SIGNATURE_DATA  *MatchedNode;
  UINT8               *Anchor;
  UINTN               AnchorSize;
  UINTN               EntryCount;
  UINTN               Index;
  UINT8               CertNumber;
  UINT8               *CertPtr;
  UINT8               *Cert;
  UINTN               CertSize;
  BOOLEAN             IsV2;
  BOOLEAN             IsFound;

  if ((SigList == NULL) || (VerifyUpToCert == NULL) || (ChainAllowedByDbx == NULL)) {
    return ContentValidationDbContinue;
  }

  if (MatchedSigData != NULL) {
    *MatchedSigData = NULL;
  }

  //
  // Full X.509 certificate entry kind: each certificate in the list is a
  // candidate trust anchor. V2 has no SignatureOwner prefix.
  //
  if (CompareGuid (&SigList->SignatureType, &gEfiCertX509Guid) ||
      CompareGuid (&SigList->SignatureType, &gEfiCertV2X509Guid))
  {
    IsV2       = (BOOLEAN)CompareGuid (&SigList->SignatureType, &gEfiCertV2X509Guid);
    SigData    = (EFI_SIGNATURE_DATA *)((UINT8 *)SigList + sizeof (EFI_SIGNATURE_LIST) + SigList->SignatureHeaderSize);
    EntryCount = (SigList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - SigList->SignatureHeaderSize) / SigList->SignatureSize;

    for (Index = 0; Index < EntryCount; Index++) {
      if (IsV2) {
        Anchor     = (UINT8 *)SigData;
        AnchorSize = SigList->SignatureSize;
      } else {
        Anchor     = SigData->SignatureData;
        AnchorSize = SigList->SignatureSize - sizeof (EFI_GUID);
      }

      if (VerifyUpToCert (Context, Anchor, AnchorSize)) {
        if (!ChainAllowedByDbx (Context, Anchor, AnchorSize)) {
          return ContentValidationDbRevoked;
        }

        if (MatchedSigData != NULL) {
          *MatchedSigData = SigData;
        }

        return ContentValidationDbAllowed;
      }

      SigData = (EFI_SIGNATURE_DATA *)((UINT8 *)SigData + SigList->SignatureSize);
    }

    return ContentValidationDbContinue;
  }

  //
  // X.509 certificate-hash entry kind: each certificate in the signing chain
  // whose TBS hash is present in this list is a candidate trust anchor.
  //
  if (CompareGuid (&SigList->SignatureType, &gEfiCertX509Sha256Guid) ||
      CompareGuid (&SigList->SignatureType, &gEfiCertX509Sha384Guid) ||
      CompareGuid (&SigList->SignatureType, &gEfiCertX509Sha512Guid) ||
      CompareGuid (&SigList->SignatureType, &gEfiCertV2X509Sha256Guid) ||
      CompareGuid (&SigList->SignatureType, &gEfiCertV2X509Sha384Guid) ||
      CompareGuid (&SigList->SignatureType, &gEfiCertV2X509Sha512Guid))
  {
    if (SignerCertChain == NULL) {
      return ContentValidationDbContinue;
    }

    CertNumber = (UINT8)(*SignerCertChain);
    CertPtr    = SignerCertChain + 1;
    for (Index = 0; Index < CertNumber; Index++) {
      CertSize = (UINTN)ReadUnaligned32 ((UINT32 *)CertPtr);
      Cert     = (UINT8 *)CertPtr + sizeof (UINT32);
      CertPtr  = CertPtr + sizeof (UINT32) + CertSize;

      //
      // The certificate's TBS hash must be present in this db list, and the
      // signature must verify up to it, before it is trusted as the anchor.
      // Capture the matched db node so the caller can measure it.
      //
      IsFound = FALSE;
      MatchedNode = NULL;
      if (EFI_ERROR (IsCertHashFoundInSigList (Cert, CertSize, SigList, SigList->SignatureListSize, &IsFound, &MatchedNode)) ||
          !IsFound)
      {
        continue;
      }

      if (!VerifyUpToCert (Context, Cert, CertSize)) {
        //
        // Hash matched a db entry but the signature does not verify up to this
        // certificate; keep checking the remaining chain certificates.
        //
        continue;
      }

      if (!ChainAllowedByDbx (Context, Cert, CertSize)) {
        return ContentValidationDbRevoked;
      }

      if (MatchedSigData != NULL) {
        *MatchedSigData = MatchedNode;
      }

      return ContentValidationDbAllowed;
    }

    return ContentValidationDbContinue;
  }

  //
  // Other (non X.509) list types are ignored.
  //
  return ContentValidationDbContinue;
}

/**
  Retrieve the candidate trust-anchor certificate set of a PKCS#7 signature.

  Use Pkcs7GetCertificatesList() to retrieve the signer's full leaf-to-root
  chain so that an intermediate or root certificate (not just the leaf signer)
  can serve as a candidate trust anchor, per UEFI Spec 32.5.3.3. A UEFI image
  signature is single-signer; Pkcs7GetCertificatesList() returns that one
  signer's chain and yields no chain for a (non-conformant) multi-signer
  SignedData, which is therefore reported as no certificate set.

  The returned buffer is a certificate stack:
        UINT8  CertNumber;
        UINT32 Cert1Length; UINT8 Cert1[]; ... UINT32 CertnLength; UINT8 Certn[];
  ordered root-first (index 0 closest to the root, leaf at the highest index).
  The caller frees it with Pkcs7FreeSigners().

  @param[in]  SignedData      Pointer to the PKCS#7 signedData.
  @param[in]  SignedDataSize  Size of SignedData in bytes.
  @param[out] CertChain       On success, the certificate stack. NULL on failure.
                              Caller frees with Pkcs7FreeSigners().
  @param[out] CertChainSize   Size of CertChain in bytes; 0 on failure.

  @retval TRUE   A non-empty certificate set was retrieved.
  @retval FALSE  No certificate set could be retrieved.

**/
STATIC
BOOLEAN
ContentValidationGetSignerChain (
  IN  UINT8  *SignedData,
  IN  UINTN  SignedDataSize,
  OUT UINT8  **CertChain,
  OUT UINTN  *CertChainSize
  )
{
  UINT8  *Unchained;
  UINTN  UnchainedSize;

  *CertChain     = NULL;
  *CertChainSize = 0;
  Unchained      = NULL;
  UnchainedSize  = 0;

  if (!Pkcs7GetCertificatesList (SignedData, SignedDataSize, CertChain, CertChainSize, &Unchained, &UnchainedSize) ||
      (*CertChainSize == 0) || (*CertChain == NULL) || (**CertChain == 0))
  {
    //
    // No single-signer chain (e.g. a non-conformant multi-signer SignedData).
    // The image is therefore not allowed by db.
    //
    Pkcs7FreeSigners (*CertChain);
    Pkcs7FreeSigners (Unchained);
    *CertChain     = NULL;
    *CertChainSize = 0;
    return FALSE;
  }

  //
  // The unchained certificate set is not used by the trust-anchor evaluation.
  //
  Pkcs7FreeSigners (Unchained);

  return TRUE;
}

//
// Context for the shared Pkcs7VerifyContent() decision rule. It carries the
// inputs that the ProcessAllowedDbList() callbacks need: the signed data and
// the content it covers, the signing-chain cert stack (used to anchor an
// intermediate/root listed in db by hash), and the RevokedDb array (a
// NULL-terminated array of dbx signature-list regions) for the anchor-relative
// revocation check.
//
// VerifyType selects how In/InSize is interpreted and which primitive verifies
// the signature against it (see CONTENT_VALIDATION_VERIFY_TYPE).
//
typedef struct {
  UINT8                            *SignedData;
  UINTN                            SignedDataSize;
  UINT8                            *In;
  UINTN                            InSize;
  CONTENT_VALIDATION_VERIFY_TYPE     VerifyType;
  UINT8                            *CertChain;
  EFI_SIGNATURE_LIST               **RevokedDb;
} PKCS7_VERIFY_CONTEXT;

/**
  ProcessAllowedDbList() verify callback for Pkcs7VerifyContent(): verify the
  PKCS#7 signature up to a candidate trust-anchor certificate, per the context's
  VerifyType:
  - ContentValidationVerifyByData: Pkcs7Verify() over the raw content (In).
  - ContentValidationVerifyByPeImageHash: AuthenticodeVerify() against the PE
    image hash in In (the signed content is always SPC_INDIRECT_DATA).
  - ContentValidationVerifyByHash: AuthenticodeVerify() first (Authenticode
    SPC_INDIRECT_DATA content), then Pkcs7VerifyByHash() (generic RFC 5652
    detached content bound by the messageDigest signed attribute).

  @param[in]  Context   Pointer to a PKCS7_VERIFY_CONTEXT.
  @param[in]  Cert      Pointer to the DER trust-anchor certificate.
  @param[in]  CertSize  Size of Cert in bytes.

  @retval TRUE   The signature verifies up to Cert.
  @retval FALSE  It does not.

**/
STATIC
BOOLEAN
Pkcs7VerifyUpToCert (
  IN VOID   *Context,
  IN UINT8  *Cert,
  IN UINTN  CertSize
  )
{
  PKCS7_VERIFY_CONTEXT  *Ctx;

  Ctx = (PKCS7_VERIFY_CONTEXT *)Context;

  switch (Ctx->VerifyType) {
    case ContentValidationVerifyByData:
      //
      // In is raw content; CMS hashes it and verifies the signature over it.
      //
      return (BOOLEAN)Pkcs7Verify (
                        Ctx->SignedData,
                        Ctx->SignedDataSize,
                        Cert,
                        CertSize,
                        Ctx->In,
                        Ctx->InSize
                        );

    case ContentValidationVerifyByPeImageHash:
      //
      // In is a PE image hash; the signed content is always an Authenticode
      // SPC_INDIRECT_DATA structure, so verify with AuthenticodeVerify().
      //
      return (BOOLEAN)AuthenticodeVerify (
                        Ctx->SignedData,
                        Ctx->SignedDataSize,
                        Cert,
                        CertSize,
                        Ctx->In,
                        Ctx->InSize
                        );

    case ContentValidationVerifyByHash:
      //
      // In is a plain content hash. Try AuthenticodeVerify() first for an
      // Authenticode SPC_INDIRECT_DATA content, then Pkcs7VerifyByHash() for a
      // generic (RFC 5652) detached signature whose content is bound by the
      // messageDigest signed attribute.
      //
      if (AuthenticodeVerify (
            Ctx->SignedData,
            Ctx->SignedDataSize,
            Cert,
            CertSize,
            Ctx->In,
            Ctx->InSize
            ))
      {
        return TRUE;
      }

      return (BOOLEAN)Pkcs7VerifyByHash (
                        Ctx->SignedData,
                        Ctx->SignedDataSize,
                        Cert,
                        CertSize,
                        Ctx->In,
                        Ctx->InSize
                        );

    default:
      return FALSE;
  }
}

/**
  ProcessAllowedDbList() dbx callback for Pkcs7VerifyContent(): apply the
  anchor-relative dbx check (UEFI Spec 32.5.3.3) to the signing chain over every
  RevokedDb region. The image is allowed only if no region revokes the anchor or
  a certificate below it (toward the leaf).

  @param[in]  Context     Pointer to a PKCS7_VERIFY_CONTEXT.
  @param[in]  Anchor      Pointer to the DER trust-anchor certificate.
  @param[in]  AnchorSize  Size of Anchor in bytes.

  @retval TRUE   Neither the anchor nor any certificate below it is revoked.
  @retval FALSE  The anchor or a certificate below it is revoked.

**/
STATIC
BOOLEAN
Pkcs7ChainAllowedByDbx (
  IN VOID   *Context,
  IN UINT8  *Anchor,
  IN UINTN  AnchorSize
  )
{
  PKCS7_VERIFY_CONTEXT  *Ctx;
  INTN                  AnchorIndex;
  UINTN                 Index;

  Ctx = (PKCS7_VERIFY_CONTEXT *)Context;

  if (Ctx->RevokedDb == NULL) {
    return TRUE;
  }

  AnchorIndex = FindCertIndexInChain (Ctx->CertChain, Anchor, AnchorSize);
  for (Index = 0; Ctx->RevokedDb[Index] != NULL; Index++) {
    if (!IsCertChainAllowedByDbx (
           Ctx->CertChain,
           AnchorIndex,
           Ctx->RevokedDb[Index],
           Ctx->RevokedDb[Index]->SignatureListSize
           ))
    {
      return FALSE;
    }
  }

  return TRUE;
}

/**
  Verify a PKCS#7 signature against the UEFI image security databases, per UEFI
  Spec 32.5.3.3.

  This is the shared signature-trust decision used by both the EFI_PKCS7_VERIFY
  protocol (Pkcs7VerifyDxe) and PE/COFF image verification
  (DxeImageVerificationLib). The AllowedDb (db) and optional RevokedDb (dbx) are
  NULL-terminated arrays of EFI_SIGNATURE_LIST regions, and an optional
  measurement hook is invoked on the matched db node when the signature is
  allowed.

  This function evaluates only the signature-trust rule (UEFI Spec 32.5.3.3
  rule C): for each AllowedDb list, verify the signature up to a candidate trust
  anchor (a full X.509 entry, or a chain certificate whose TBS hash is listed);
  on success apply the anchor-relative dbx certificate check. The first list
  that anchors a verifiable, non-revoked signature wins.

  Content-hash revocation (rule A: the content/image hash itself listed in a dbx
  EFI_CERT_SHAxxx entry) is NOT evaluated here - it is a buffer property, not a
  signature property. The image path performs it via PeVerifyHash() (step A/B
  before any signature check), and the EFI_PKCS7_VERIFY protocol performs it in
  VerifyBuffer()/VerifySignature() before calling this function.

  VerifyType selects how In/InSize is interpreted and which primitive verifies
  the signature against it (see CONTENT_VALIDATION_VERIFY_TYPE):
  - ContentValidationVerifyByPeImageHash: In is a PE image hash (AuthenticodeVerify).
  - ContentValidationVerifyByHash:        In is a plain content hash (currently also
                                        AuthenticodeVerify; see the enum note).
  - ContentValidationVerifyByData:        In is raw content (Pkcs7Verify).

  @param[in]  SignedData      Pointer to the DER PKCS#7 signedData.
  @param[in]  SignedDataSize  Size of SignedData in bytes.
  @param[in]  In              Image hash, content hash, or raw content, per
                              VerifyType.
  @param[in]  InSize          Size of In in bytes.
  @param[in]  VerifyType      How In is interpreted and verified.
  @param[in]  AllowedDb       NULL-terminated array of db EFI_SIGNATURE_LIST
                              regions. Must not be NULL.
  @param[in]  RevokedDb       NULL-terminated array of dbx EFI_SIGNATURE_LIST
                              regions, or NULL if dbx is absent.
  @param[in]  SecureBootHook  Optional callback invoked with the matched db
                              signature node when the signature is allowed (used
                              by image verification to measure the db entry).

  @retval EFI_SUCCESS            The signature is allowed by db and not revoked.
  @retval EFI_SECURITY_VIOLATION The signature is revoked, or not allowed by db.
  @retval EFI_INVALID_PARAMETER  A required parameter is NULL or zero-length.

**/
EFI_STATUS
Pkcs7VerifyContent (
  IN UINT8                             *SignedData,
  IN UINTN                             SignedDataSize,
  IN UINT8                             *In,
  IN UINTN                             InSize,
  IN CONTENT_VALIDATION_VERIFY_TYPE      VerifyType,
  IN EFI_SIGNATURE_LIST                **AllowedDb,
  IN EFI_SIGNATURE_LIST                **RevokedDb       OPTIONAL,
  IN CONTENT_VALIDATION_SECURE_BOOT_HOOK  SecureBootHook       OPTIONAL
  )
{
  EFI_STATUS                  Status;
  PKCS7_VERIFY_CONTEXT        Ctx;
  UINT8                       *CertChain;
  UINTN                       CertChainSize;
  UINTN                       Index;
  EFI_SIGNATURE_LIST          *SigList;
  EFI_SIGNATURE_DATA          *MatchedData;
  CONTENT_VALIDATION_DB_RESULT  Result;

  if ((SignedData == NULL) || (SignedDataSize == 0) || (AllowedDb == NULL) ||
      (In == NULL) || (InSize == 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Retrieve the signer's certificate chain once (used only for the cert-hash
  // entry kind, so an intermediate/root listed in db can anchor trust). May be
  // empty for a non-conformant multi-signer SignedData; ProcessAllowedDbList()
  // tolerates a NULL chain.
  //
  CertChain     = NULL;
  CertChainSize = 0;
  ContentValidationGetSignerChain (SignedData, SignedDataSize, &CertChain, &CertChainSize);

  ZeroMem (&Ctx, sizeof (Ctx));
  Ctx.SignedData      = SignedData;
  Ctx.SignedDataSize  = SignedDataSize;
  Ctx.In              = In;
  Ctx.InSize          = InSize;
  Ctx.VerifyType      = VerifyType;
  Ctx.CertChain       = CertChain;
  Ctx.RevokedDb       = RevokedDb;

  //
  // Rule C: evaluate each AllowedDb list with the shared decision rule. The
  // first list that anchors a verifiable, non-revoked signature wins.
  //
  Status = EFI_SECURITY_VIOLATION;
  for (Index = 0; AllowedDb[Index] != NULL; Index++) {
    SigList     = AllowedDb[Index];
    MatchedData = NULL;
    Result      = ProcessAllowedDbList (
                    SigList,
                    CertChain,
                    Pkcs7VerifyUpToCert,
                    Pkcs7ChainAllowedByDbx,
                    &Ctx,
                    &MatchedData
                    );
    if (Result == ContentValidationDbAllowed) {
      Status = EFI_SUCCESS;
      if (SecureBootHook != NULL) {
        SecureBootHook (
          EFI_IMAGE_SECURITY_DATABASE,
          &gEfiImageSecurityDatabaseGuid,
          SigList->SignatureSize,
          MatchedData
          );
      }

      break;
    }

    if (Result == ContentValidationDbRevoked) {
      Status = EFI_SECURITY_VIOLATION;
      break;
    }
  }

  Pkcs7FreeSigners (CertChain);

  return Status;
}

/**
  Verify a content/image hash against the UEFI image security databases, per
  UEFI Spec 32.5.3.3 rules A and B (the unsigned-image path).

  Unlike Pkcs7VerifyContent(), there is no PKCS#7 signature here: the decision
  is a direct content-hash lookup. InHash is matched against the content-hash
  lists (EFI_CERT_SHAxxx / EFI_CERT_V2_SHAxxx) of each database region:
  - Rule A: if InHash is present in any RevokedDb (dbx) region, the image is
    rejected.
  - Rule B: else if InHash is present in any AllowedDb (db) region, the image is
    accepted, and the matched db node is reported to the measurement hook.

  AllowedDb and RevokedDb are NULL-terminated arrays of EFI_SIGNATURE_LIST
  regions. Only entries whose list type matches InHashSize are comparable; other
  list types (e.g. full X.509 entries) are ignored by the content-hash matcher.

  @param[in]  InHash          The content/image hash to look up.
  @param[in]  InHashSize      Size of InHash in bytes (selects the hash type).
  @param[in]  AllowedDb       NULL-terminated array of db EFI_SIGNATURE_LIST
                              regions, or NULL if db is absent.
  @param[in]  RevokedDb       NULL-terminated array of dbx EFI_SIGNATURE_LIST
                              regions, or NULL if dbx is absent.
  @param[in]  SecureBootHook     Optional callback invoked with the matched db node
                              when the hash is allowed by db.

  @retval EFI_SUCCESS            InHash is in db and not in dbx.
  @retval EFI_SECURITY_VIOLATION InHash is in dbx.
  @retval EFI_NOT_FOUND          InHash is in neither db nor dbx.
  @retval EFI_INVALID_PARAMETER  InHash is NULL or InHashSize is zero.

**/
EFI_STATUS
PeVerifyHash (
  IN UINT8                             *InHash,
  IN UINTN                             InHashSize,
  IN EFI_SIGNATURE_LIST                **AllowedDb,
  IN EFI_SIGNATURE_LIST                **RevokedDb       OPTIONAL,
  IN CONTENT_VALIDATION_SECURE_BOOT_HOOK  SecureBootHook       OPTIONAL
  )
{
  EFI_STATUS          Status;
  UINTN               Index;
  BOOLEAN             IsFound;
  EFI_SIGNATURE_DATA  *MatchedData;

  if ((InHash == NULL) || (InHashSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Rule A: reject if the hash is in any dbx content-hash list.
  //
  if (RevokedDb != NULL) {
    for (Index = 0; RevokedDb[Index] != NULL; Index++) {
      IsFound = FALSE;
      Status  = IsContentHashFoundInSigList (InHash, InHashSize, RevokedDb[Index], &IsFound, NULL);
      if (!EFI_ERROR (Status) && IsFound) {
        return EFI_SECURITY_VIOLATION;
      }
    }
  }

  //
  // Rule B: accept if the hash is in any db content-hash list; measure the node.
  //
  if (AllowedDb != NULL) {
    for (Index = 0; AllowedDb[Index] != NULL; Index++) {
      IsFound     = FALSE;
      MatchedData = NULL;
      Status      = IsContentHashFoundInSigList (InHash, InHashSize, AllowedDb[Index], &IsFound, &MatchedData);
      if (!EFI_ERROR (Status) && IsFound) {
        if (SecureBootHook != NULL) {
          SecureBootHook (
            EFI_IMAGE_SECURITY_DATABASE,
            &gEfiImageSecurityDatabaseGuid,
            AllowedDb[Index]->SignatureSize,
            MatchedData
            );
        }

        return EFI_SUCCESS;
      }
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Map a content-hash signature-list type GUID (EFI_CERT_SHAxxx and the
  EFI_CERT_V2_SHAxxx variants) to its digest length.

  @param[in]  CertType  The EFI_SIGNATURE_LIST SignatureType GUID.
  @param[out] HashSize  On success, the digest length in bytes.

  @retval TRUE   CertType is a content-hash type; HashSize is set.
  @retval FALSE  CertType is not a content-hash type.

**/
STATIC
BOOLEAN
ContentHashTypeToSize (
  IN  EFI_GUID  *CertType,
  OUT UINTN     *HashSize
  )
{
  if (CompareGuid (CertType, &gEfiCertSha256Guid) ||
      CompareGuid (CertType, &gEfiCertV2Sha256Guid))
  {
    *HashSize = SHA256_DIGEST_SIZE;
  } else if (CompareGuid (CertType, &gEfiCertSha384Guid) ||
             CompareGuid (CertType, &gEfiCertV2Sha384Guid))
  {
    *HashSize = SHA384_DIGEST_SIZE;
  } else if (CompareGuid (CertType, &gEfiCertSha512Guid) ||
             CompareGuid (CertType, &gEfiCertV2Sha512Guid))
  {
    *HashSize = SHA512_DIGEST_SIZE;
  } else {
    return FALSE;
  }

  return TRUE;
}

/**
  Verify a content buffer's hash against the UEFI image security databases, per
  UEFI Spec 32.5.3.3 rules A and B - the content counterpart of PeVerifyHash().

  PeVerifyHash() takes a precomputed hash; this function takes the raw content
  and hashes it with each database list's own algorithm before matching, so a
  content hash listed under any supported algorithm is detected (the spec
  cautions that a single precomputed hash can miss a revocation recorded under a
  different algorithm).

  - Rule A: if the content hash is present in a RevokedDb (dbx) content-hash
    list, the content is rejected.
  - Rule B: else if it is present in an AllowedDb (db) content-hash list, the
    content is accepted and the matched db node is reported to the hook.

  @param[in]  Content         The content buffer to look up.
  @param[in]  ContentSize     Size of Content in bytes.
  @param[in]  AllowedDb       NULL-terminated array of db EFI_SIGNATURE_LIST
                              regions, or NULL if db is absent.
  @param[in]  RevokedDb       NULL-terminated array of dbx EFI_SIGNATURE_LIST
                              regions, or NULL if dbx is absent.
  @param[in]  SecureBootHook  Optional callback invoked with the matched db node
                              when the content is allowed by db.

  @retval EFI_SUCCESS            Content hash is in db and not in dbx.
  @retval EFI_SECURITY_VIOLATION Content hash is in dbx.
  @retval EFI_NOT_FOUND          Content hash is in neither db nor dbx.
  @retval EFI_INVALID_PARAMETER  Content is NULL or ContentSize is zero.

**/
EFI_STATUS
VerifyContentNoRevokedHash (
  IN UINT8                          *In,
  IN UINTN                          InSize,
  IN CONTENT_VALIDATION_VERIFY_TYPE  VerifyType,
  IN EFI_SIGNATURE_LIST             **RevokedDb       OPTIONAL
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  UINTN       HashSize;
  UINT8       HashVal[CONTENT_VALIDATION_MAX_DIGEST_SIZE];
  UINT8       *Hash;
  BOOLEAN     IsFound;

  if ((In == NULL) || (InSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Reject if the content hash is in any RevokedDb (dbx) content-hash list.
  //
  // VerifyType selects how In/InSize is interpreted:
  //   ContentValidationVerifyByData - In is the raw content; it is hashed with
  //     each list's own algorithm, so a revocation recorded under any supported
  //     algorithm is detected.
  //   ContentValidationVerifyByHash / ByPeImageHash - In is a precomputed hash
  //     supplied by the caller; it is compared directly. Only lists whose entry
  //     length matches InSize can match (a different algorithm cannot), so the
  //     caller is responsible for the hash it presents (see the spec NOTE on
  //     cycling through supported hashes).
  //
  // NOTE: There is intentionally no "accept if the hash is in an AllowedDb (db)
  // list" rule (UEFI Spec 32.5.3.3 rule B) here. This function exists only to
  // implement the content-hash *revocation* check of the EFI_PKCS7_VERIFY
  // protocol (UEFI Spec Ch. 37 VerifyBuffer/VerifySignature), where the spec
  // states "Any hash certificate in AllowedDb list is ignored by this function"
  // and trust is established solely by the signer's X.509 certificate. A content
  // hash present in db must NOT by itself authorize the buffer, so db is never
  // consulted and no AllowedDb/measurement-hook parameters are accepted. (The
  // PE/COFF image path's rule B - hash in db -> accept - is a different code
  // path; see PeVerifyHash().)
  //
  if (RevokedDb != NULL) {
    for (Index = 0; RevokedDb[Index] != NULL; Index++) {
      if (VerifyType == ContentValidationVerifyByData) {
        //
        // Raw content: hash it with this list's algorithm before matching.
        //
        if (!ContentHashTypeToSize (&RevokedDb[Index]->SignatureType, &HashSize) ||
            !ContentValidationHashData (HashSize, In, InSize, HashVal))
        {
          continue;
        }

        Hash = HashVal;
      } else {
        //
        // Precomputed hash: match In directly. IsContentHashFoundInSigList()
        // only matches lists whose entry length equals HashSize.
        //
        Hash     = In;
        HashSize = InSize;
      }

      IsFound = FALSE;
      Status  = IsContentHashFoundInSigList (Hash, HashSize, RevokedDb[Index], &IsFound, NULL);
      if (!EFI_ERROR (Status) && IsFound) {
        return EFI_SECURITY_VIOLATION;
      }
    }
  }

  //
  // The content hash is not revoked by dbx. This is purely a revocation check,
  // so "not revoked" is success; it does NOT mean the buffer is trusted - the
  // caller still establishes trust via the signer certificate.
  //
  return EFI_SUCCESS;
}
