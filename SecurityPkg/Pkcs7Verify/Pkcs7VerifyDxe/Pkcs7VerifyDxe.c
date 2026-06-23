/** @file
  Pkcs7Verify Driver to produce the UEFI PKCS7 Verification Protocol.

  The driver will produce the UEFI PKCS7 Verification Protocol which is used to
  verify data signed using PKCS7 structure. The PKCS7 data to be verified must
  be ASN.1 (DER) encoded.

Copyright (c) 2015 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseCryptLib.h>
#include <Protocol/Pkcs7Verify.h>

#include "ContentValidation.h"

/**
  Check the integrity of a PKCS7 signedData against the signer's own certificate
  embedded in the signedData, independent of any AllowedDb/RevokedDb policy.

  Per the UEFI Spec VerifyBuffer() Description, the first step verifies the PKCS7
  signature of the content hash "by decrypting the hash calculated at time of
  signing" using the certificate "included within the signed data". A failure of
  this step means the calculated content hash differs from the signed hash, which
  the spec maps to EFI_COMPROMISED_DATA (as distinct from the policy failures that
  map to EFI_SECURITY_VIOLATION).

  The signer's own certificate is retrieved from the signedData and used as the
  trust certificate, so this check reflects content integrity only and does not
  consult AllowedDb or RevokedDb.

  @param[in]  SignedData      Pointer to the ASN.1 DER-encoded PKCS7 signedData.
  @param[in]  SignedDataSize  Size of SignedData in bytes.
  @param[in]  InData          Pointer to the content to be verified.
  @param[in]  InDataSize      Size of InData in bytes.

  @retval TRUE   The content hash matches the signed hash (integrity intact).
  @retval FALSE  The content hash differs from the signed hash, or the signer's
                 certificate could not be retrieved.
**/
STATIC
BOOLEAN
P7CheckContentIntegrity (
  IN UINT8  *SignedData,
  IN UINTN  SignedDataSize,
  IN UINT8  *InData,
  IN UINTN  InDataSize
  )
{
  BOOLEAN  Status;
  UINT8    *CertStack;
  UINTN    StackLength;
  UINT8    *SignerCert;
  UINTN    SignerCertSize;

  CertStack  = NULL;
  SignerCert = NULL;

  //
  // Retrieve the signer's own certificate embedded in the signedData.
  //
  if (!Pkcs7GetSigners (
         SignedData,
         SignedDataSize,
         &CertStack,
         &StackLength,
         &SignerCert,
         &SignerCertSize
         ))
  {
    return FALSE;
  }

  //
  // Verify the signature against the signer's own certificate. This confirms
  // the content has not been modified since signing, without applying any
  // AllowedDb/RevokedDb policy.
  //
  Status = Pkcs7Verify (
             SignedData,
             SignedDataSize,
             SignerCert,
             SignerCertSize,
             InData,
             InDataSize
             );

  Pkcs7FreeSigners (CertStack);
  Pkcs7FreeSigners (SignerCert);

  return Status;
}

/**
  Check the integrity of a detached PKCS7 signature against the signer's own
  certificate embedded in the signature, using a caller-supplied content hash,
  independent of any AllowedDb/RevokedDb policy.

  Per the UEFI Spec VerifySignature() Description, the signature of the hash is
  verified by decrypting the hash computed at time of signing, using the signer
  certificate included within the signature. A failure of this step means the
  caller-provided hash differs from the signed hash (or the caller hash and the
  signed hash are different sizes), which the spec maps to EFI_COMPROMISED_DATA -
  distinct from the policy failures that map to EFI_SECURITY_VIOLATION.

  The signer's own certificate is retrieved from the signature and used as the
  trust certificate, so this check reflects integrity only and does not consult
  AllowedDb or RevokedDb. AuthenticodeVerify() is tried first (SPC_INDIRECT_DATA
  content) and Pkcs7VerifyByHash() second (generic detached content), matching
  the two content forms the protocol accepts.

  @param[in]  Signature      Pointer to the ASN.1 DER-encoded detached PKCS7 signature.
  @param[in]  SignatureSize  Size of Signature in bytes.
  @param[in]  InHash         Pointer to the caller-computed content hash.
  @param[in]  InHashSize     Size of InHash in bytes.

  @retval TRUE   The caller-provided hash matches the signed hash (integrity intact).
  @retval FALSE  The caller-provided hash differs from the signed hash (including a
                 size difference), or the signer's certificate could not be retrieved.
**/
STATIC
BOOLEAN
P7CheckContentIntegrityByHash (
  IN UINT8  *Signature,
  IN UINTN  SignatureSize,
  IN UINT8  *InHash,
  IN UINTN  InHashSize
  )
{
  BOOLEAN  Status;
  UINT8    *CertStack;
  UINTN    StackLength;
  UINT8    *SignerCert;
  UINTN    SignerCertSize;

  CertStack  = NULL;
  SignerCert = NULL;

  //
  // Retrieve the signer's own certificate embedded in the signature.
  //
  if (!Pkcs7GetSigners (
         Signature,
         SignatureSize,
         &CertStack,
         &StackLength,
         &SignerCert,
         &SignerCertSize
         ))
  {
    return FALSE;
  }

  //
  // Verify the caller-supplied hash against the signer's own certificate. A
  // size mismatch fails the same way, since the signed messageDigest cannot
  // equal a different-length hash. This confirms integrity without applying any
  // AllowedDb/RevokedDb policy.
  //
  Status = AuthenticodeVerify (
             Signature,
             SignatureSize,
             SignerCert,
             SignerCertSize,
             InHash,
             InHashSize
             );
  if (!Status) {
    Status = Pkcs7VerifyByHash (
               Signature,
               SignatureSize,
               SignerCert,
               SignerCertSize,
               InHash,
               InHashSize
               );
  }

  Pkcs7FreeSigners (CertStack);
  Pkcs7FreeSigners (SignerCert);

  return Status;
}

/**
  Processes a buffer containing binary DER-encoded PKCS7 signature.
  The signed data content may be embedded within the buffer or separated. Function
  verifies the signature of the content is valid and signing certificate was not
  revoked and is contained within a list of trusted signers.

  @param[in]     This                 Pointer to EFI_PKCS7_VERIFY_PROTOCOL instance.
  @param[in]     SignedData           Points to buffer containing ASN.1 DER-encoded PKCS7
                                      signature.
  @param[in]     SignedDataSize       The size of SignedData buffer in bytes.
  @param[in]     InData               In case of detached signature, InData points to
                                      buffer containing the raw message data previously
                                      signed and to be verified by function. In case of
                                      SignedData containing embedded data, InData must be
                                      NULL.
  @param[in]     InDataSize           When InData is used, the size of InData buffer in
                                      bytes. When InData is NULL. This parameter must be
                                      0.
  @param[in]     AllowedDb            Pointer to a list of pointers to EFI_SIGNATURE_LIST
                                      structures. The list is terminated by a null
                                      pointer. The EFI_SIGNATURE_LIST structures contain
                                      lists of X.509 certificates of approved signers.
                                      Function recognizes signer certificates of type
                                      EFI_CERT_X509_GUID. Any hash certificate in AllowedDb
                                      list is ignored by this function. Function returns
                                      success if signer of the buffer is within this list
                                      (and not within RevokedDb). This parameter is
                                      required.
  @param[in]     RevokedDb            Optional pointer to a list of pointers to
                                      EFI_SIGNATURE_LIST structures. The list is terminated
                                      by a null pointer. List of X.509 certificates of
                                      revoked signers and revoked file hashes. Signature
                                      verification will always fail if the signer of the
                                      file or the hash of the data component of the buffer
                                      is in RevokedDb list. This list is optional and
                                      caller may pass Null or pointer to NULL if not
                                      required.
  @param[in]     TimeStampDb          [DEPRECATED] This parameter is ignored.
  @param[out]    Content              On input, points to an optional caller-allocated
                                      buffer into which the function will copy the content
                                      portion of the file after verification succeeds.
                                      This parameter is optional and if NULL, no copy of
                                      content from file is performed.
  @param[in,out] ContentSize          On input, points to the size in bytes of the optional
                                      buffer Content previously allocated by caller. On
                                      output, if the verification succeeds, the value
                                      referenced by ContentSize will contain the actual
                                      size of the content from signed file. If ContentSize
                                      indicates the caller-allocated buffer is too small
                                      to contain content, an error is returned, and
                                      ContentSize will be updated with the required size.
                                      This parameter must be 0 if Content is Null.

  @retval EFI_SUCCESS                 Content signature was verified against hash of
                                      content, the signer's certificate was not found in
                                      RevokedDb, and was found in AllowedDb, and no hash
                                      matching content hash was found in RevokedDb.
  @retval EFI_SECURITY_VIOLATION      The SignedData buffer was correctly formatted but
                                      signer was in RevokedDb or not in AllowedDb. Also
                                      returned if matching content hash found in RevokedDb.
  @retval EFI_COMPROMISED_DATA        Calculated hash differs from signed hash.
  @retval EFI_INVALID_PARAMETER       SignedData is NULL or SignedDataSize is zero.
                                      AllowedDb is NULL.
  @retval EFI_INVALID_PARAMETER       Content is not NULL and ContentSize is NULL.
  @retval EFI_ABORTED                 Unsupported or invalid format in
                                      RevokedDb or AllowedDb list contents was detected.
  @retval EFI_NOT_FOUND               Content not found because InData is NULL and no
                                      content embedded in SignedData.
  @retval EFI_UNSUPPORTED             The SignedData buffer was not correctly formatted
                                      for processing by the function.
  @retval EFI_UNSUPPORTED             Signed data embedded in SignedData but InData is not
                                      NULL.
  @retval EFI_BUFFER_TOO_SMALL        The size of buffer indicated by ContentSize is too
                                      small to hold the content. ContentSize updated to
                                      required size.

**/
EFI_STATUS
EFIAPI
VerifyBuffer (
  IN EFI_PKCS7_VERIFY_PROTOCOL  *This,
  IN VOID                       *SignedData,
  IN UINTN                      SignedDataSize,
  IN VOID                       *InData          OPTIONAL,
  IN UINTN                      InDataSize,
  IN EFI_SIGNATURE_LIST         **AllowedDb,
  IN EFI_SIGNATURE_LIST         **RevokedDb      OPTIONAL,
  IN EFI_SIGNATURE_LIST         **TimeStampDb    OPTIONAL,
  OUT VOID                      *Content         OPTIONAL,
  IN OUT UINTN                  *ContentSize
  )
{
  EFI_STATUS          Status;
  EFI_SIGNATURE_LIST  *SigList;
  UINTN               Index;
  UINT8               *AttachedData;
  UINTN               AttachedDataSize;
  UINT8               *DataPtr;
  UINTN               DataSize;

  //
  // Parameters Checking
  //
  if ((SignedData == NULL) || (SignedDataSize == 0) || (AllowedDb == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Content != NULL) && (ContentSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check if any invalid entry format in AllowedDb list contents
  //
  for (Index = 0; ; Index++) {
    SigList = (EFI_SIGNATURE_LIST *)(AllowedDb[Index]);

    if (SigList == NULL) {
      break;
    }

    if (SigList->SignatureListSize < sizeof (EFI_SIGNATURE_LIST) +
        SigList->SignatureHeaderSize +
        SigList->SignatureSize)
    {
      return EFI_ABORTED;
    }
  }

  //
  // Check if any invalid entry format in RevokedDb list contents
  //
  if (RevokedDb != NULL) {
    for (Index = 0; ; Index++) {
      SigList = (EFI_SIGNATURE_LIST *)(RevokedDb[Index]);

      if (SigList == NULL) {
        break;
      }

      if (SigList->SignatureListSize < sizeof (EFI_SIGNATURE_LIST) +
          SigList->SignatureHeaderSize +
          SigList->SignatureSize)
      {
        return EFI_ABORTED;
      }
    }
  }

  //
  // Try to retrieve the attached content from PKCS7 signedData
  //
  AttachedData     = NULL;
  AttachedDataSize = 0;
  if (!Pkcs7GetAttachedContent (
         SignedData,
         SignedDataSize,
         (VOID **)&AttachedData,
         &AttachedDataSize
         ))
  {
    //
    // The SignedData buffer was not correctly formatted for processing
    //
    return EFI_UNSUPPORTED;
  }

  if (AttachedData != NULL) {
    if (InData != NULL) {
      //
      // The embedded content is found in SignedData but InData is not NULL
      //
      Status = EFI_UNSUPPORTED;
      goto _Exit;
    }

    //
    // PKCS7-formatted signedData with attached content; Use the embedded
    // content for verification
    //
    DataPtr  = AttachedData;
    DataSize = AttachedDataSize;
  } else if (InData != NULL) {
    //
    // PKCS7-formatted signedData with detached content; Use the user-supplied
    // input data for verification
    //
    DataPtr  = (UINT8 *)InData;
    DataSize = InDataSize;
  } else {
    //
    // Content not found because InData is NULL and no content attached in SignedData
    //
    Status = EFI_NOT_FOUND;
    goto _Exit;
  }

  //
  // Per the UEFI Spec VerifyBuffer() Description, first verify the content hash
  // against the signed hash using the signer's own certificate. This is a
  // content-integrity check independent of AllowedDb/RevokedDb policy; a
  // mismatch means the calculated hash differs from the signed hash.
  //
  if (!P7CheckContentIntegrity (SignedData, SignedDataSize, DataPtr, DataSize)) {
    Status = EFI_COMPROMISED_DATA;
    goto _Exit;
  }

  //
  // Content-hash revocation first (UEFI Spec EFI_PKCS7_VERIFY): verification
  // fails if the hash of the content is present in a RevokedDb content-hash
  // list. VerifyContentNoRevokedHash() hashes the content with each dbx list's algorithm,
  // so a revocation recorded under any supported hash is caught. It consults
  // only RevokedDb (dbx); db is never used for content-hash acceptance here
  // (hash entries in AllowedDb are ignored per the protocol spec).
  //
  if (VerifyContentNoRevokedHash (DataPtr, DataSize, ContentValidationVerifyByData, RevokedDb) == EFI_SECURITY_VIOLATION) {
    Status = EFI_SECURITY_VIOLATION;
    goto _Exit;
  }

  //
  // Verify the signature trust: signer chains to a cert in AllowedDb and the
  // chain is not revoked by dbx (anchor-relative). The content form
  // (ContentValidationVerifyByData) verifies with Pkcs7Verify() against the
  // attached/detached content. No measurement hook is needed for the protocol.
  //
  Status = Pkcs7VerifyContent (
             SignedData,
             SignedDataSize,
             DataPtr,
             DataSize,
             ContentValidationVerifyByData,
             AllowedDb,
             RevokedDb,
             NULL
             );
  if (EFI_ERROR (Status)) {
    //
    // Verification failed (revoked, or not allowed by db)
    //
    goto _Exit;
  }

  //
  // Copy the content portion after verification succeeds
  //
  if (Content != NULL) {
    if (*ContentSize < DataSize) {
      //
      // Caller-allocated buffer is too small to contain content
      //
      *ContentSize = DataSize;
      Status       = EFI_BUFFER_TOO_SMALL;
    } else {
      *ContentSize = DataSize;
      CopyMem (Content, DataPtr, DataSize);
    }
  }

_Exit:
  if (AttachedData != NULL) {
    FreePool (AttachedData);
  }

  return Status;
}

/**
  Processes a buffer containing binary DER-encoded detached PKCS7 signature.
  The hash of the signed data content is calculated and passed by the caller. Function
  verifies the signature of the content is valid and signing certificate was not revoked
  and is contained within a list of trusted signers.

  Note: because this function uses hashes and the specification contains a variety of
        hash choices, you should be aware that the check against the RevokedDb list
        will improperly succeed if the signature is revoked using a different hash
        algorithm.  For this reason, you should either cycle through all UEFI supported
        hashes to see if one is forbidden, or rely on a single hash choice only if the
        UEFI signature authority only signs and revokes with a single hash (at time
        of writing, this hash choice is SHA256).

  @param[in]     This                 Pointer to EFI_PKCS7_VERIFY_PROTOCOL instance.
  @param[in]     Signature            Points to buffer containing ASN.1 DER-encoded PKCS
                                      detached signature.
  @param[in]     SignatureSize        The size of Signature buffer in bytes.
  @param[in]     InHash               InHash points to buffer containing the caller
                                      calculated hash of the data. The parameter may not
                                      be NULL.
  @param[in]     InHashSize           The size in bytes of InHash buffer.
  @param[in]     AllowedDb            Pointer to a list of pointers to EFI_SIGNATURE_LIST
                                      structures. The list is terminated by a null
                                      pointer. The EFI_SIGNATURE_LIST structures contain
                                      lists of X.509 certificates of approved signers.
                                      Function recognizes signer certificates of type
                                      EFI_CERT_X509_GUID. Any hash certificate in AllowedDb
                                      list is ignored by this function. Function returns
                                      success if signer of the buffer is within this list
                                      (and not within RevokedDb). This parameter is
                                      required.
  @param[in]     RevokedDb            Optional pointer to a list of pointers to
                                      EFI_SIGNATURE_LIST structures. The list is terminated
                                      by a null pointer. List of X.509 certificates of
                                      revoked signers and revoked file hashes. Signature
                                      verification will always fail if the signer of the
                                      file or the hash of the data component of the buffer
                                      is in RevokedDb list. This parameter is optional
                                      and caller may pass Null if not required.
  @param[in]     TimeStampDb          [DEPRECATED] This parameter is ignored.

  @retval EFI_SUCCESS                 Signed hash was verified against caller-provided
                                      hash of content, the signer's certificate was not
                                      found in RevokedDb, and was found in AllowedDb, and
                                      no hash matching content hash was found in RevokedDb.
  @retval EFI_SECURITY_VIOLATION      The SignedData buffer was correctly formatted but
                                      signer was in RevokedDb or not in AllowedDb. Also
                                      returned if matching content hash found in RevokedDb.
  @retval EFI_COMPROMISED_DATA        Caller provided hash differs from signed hash. Or,
                                      caller and encrypted hash are different sizes.
  @retval EFI_INVALID_PARAMETER       Signature is NULL or SignatureSize is zero. InHash
                                      is NULL or InHashSize is zero. AllowedDb is NULL.
  @retval EFI_ABORTED                 Unsupported or invalid format in
                                      RevokedDb or AllowedDb list contents was detected.
  @retval EFI_UNSUPPORTED             The Signature buffer was not correctly formatted
                                      for processing by the function.

**/
EFI_STATUS
EFIAPI
VerifySignature (
  IN EFI_PKCS7_VERIFY_PROTOCOL  *This,
  IN VOID                       *Signature,
  IN UINTN                      SignatureSize,
  IN VOID                       *InHash,
  IN UINTN                      InHashSize,
  IN EFI_SIGNATURE_LIST         **AllowedDb,
  IN EFI_SIGNATURE_LIST         **RevokedDb       OPTIONAL,
  IN EFI_SIGNATURE_LIST         **TimeStampDb     OPTIONAL
  )
{
  //
  // Parameters Checking
  //
  if (  (Signature == NULL) || (SignatureSize == 0) || (AllowedDb == NULL)
     || (InHash == NULL) || (InHashSize == 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Per the UEFI Spec VerifySignature() Description, first verify the caller-
  // provided hash against the signed hash using the signer's own certificate.
  // This is an integrity check independent of AllowedDb/RevokedDb policy; a
  // failure means the caller-provided hash differs from the signed hash (or the
  // caller and signed hash are different sizes).
  //
  if (!P7CheckContentIntegrityByHash (Signature, SignatureSize, InHash, InHashSize)) {
    return EFI_COMPROMISED_DATA;
  }

  //
  // Content-hash revocation first (UEFI Spec EFI_PKCS7_VERIFY): verification
  // fails if the hash of the data is present in a RevokedDb content-hash list.
  // The caller supplies a single precomputed InHash, so VerifyContentNoRevokedHash() is
  // called with ContentValidationVerifyByHash to compare it directly against
  // dbx; per the spec NOTE the caller is responsible for the hash algorithm it
  // presents. Only RevokedDb (dbx) is consulted - db is never used for
  // content-hash acceptance (hash entries in AllowedDb are ignored per the
  // protocol spec).
  //
  if (VerifyContentNoRevokedHash (InHash, InHashSize, ContentValidationVerifyByHash, RevokedDb) == EFI_SECURITY_VIOLATION) {
    return EFI_SECURITY_VIOLATION;
  }

  //
  // Verify the signature trust: signer chains to a cert in AllowedDb and the
  // chain is not revoked by dbx (anchor-relative). No measurement hook is needed
  // for the protocol. TimeStampDb is not consumed by this implementation.
  //
  return Pkcs7VerifyContent (
           Signature,
           SignatureSize,
           InHash,
           InHashSize,
           ContentValidationVerifyByHash,
           AllowedDb,
           RevokedDb,
           NULL
           );
}

//
// The PKCS7 Verification Protocol
//
EFI_PKCS7_VERIFY_PROTOCOL  mPkcs7Verify = {
  VerifyBuffer,
  VerifySignature
};

/**
  The user Entry Point for the PKCS7 Verification driver.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval EFI_NOT_SUPPORTED Platform does not support PKCS7 Verification.
  @retval Other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
Pkcs7VerifyDriverEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                 Status;
  EFI_HANDLE                 Handle;
  EFI_PKCS7_VERIFY_PROTOCOL  Useless;

  //
  // Avoid loading a second copy if this is built as an external module
  //
  Status = gBS->LocateProtocol (&gEfiPkcs7VerifyProtocolGuid, NULL, (VOID **)&Useless);
  if (!EFI_ERROR (Status)) {
    return EFI_ABORTED;
  }

  //
  // Install UEFI Pkcs7 Verification Protocol
  //
  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiPkcs7VerifyProtocolGuid,
                  &mPkcs7Verify,
                  NULL
                  );

  return Status;
}
