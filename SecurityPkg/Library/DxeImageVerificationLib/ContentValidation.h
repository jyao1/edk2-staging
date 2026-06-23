/** @file
  Shared, phase-independent X.509 certificate-hash matching for the UEFI image
  security databases (db/dbx).

  This header declares the helpers implemented in ContentValidation.c. The source
  file is intentionally kept byte-identical between DxeImageVerificationLib and
  Pkcs7VerifyDxe so the common certificate-hash logic stays in lock-step. It uses
  only phase-independent (Base-class) APIs - no boot/runtime services - so the
  same code is valid in any module that links BaseCryptLib.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef CONTENT_VALIDATION_H_
#define CONTENT_VALIDATION_H_

#include <Uefi.h>
#include <Guid/ImageAuthentication.h>

///
/// Selects how Pkcs7VerifyContent() interprets its In/InSize buffer and which
/// crypto primitive verifies the signature against it.
///
typedef enum {
  ///
  /// In is the PE/COFF image hash. The SignedData is a PE/COFF Authenticode
  /// signature; the hash is checked against the digest embedded in its
  /// SPC_INDIRECT_DATA via AuthenticodeVerify().
  ///
  ContentValidationVerifyByPeImageHash,

  ///
  /// In is a plain content hash (a detached PKCS#7 signature over the hash, per
  /// EFI_PKCS7_VERIFY VerifySignature()). The signature is verified against the
  /// supplied hash without the content: AuthenticodeVerify() first (Authenticode
  /// SPC_INDIRECT_DATA content), then Pkcs7VerifyByHash() for a generic
  /// (RFC 5652) detached signature bound by the messageDigest signed attribute.
  ///
  ContentValidationVerifyByHash,

  ///
  /// In is the raw signed content. The signature is verified over the content
  /// with Pkcs7Verify() (CMS), which hashes the content internally.
  ///
  ContentValidationVerifyByData
} CONTENT_VALIDATION_VERIFY_TYPE;

/**
  Caller callback invoked when a signature is allowed by db, so the caller can
  measure the matched db node. The signature matches SecureBootHook(), so a
  consumer can pass SecureBootHook directly. Pkcs7VerifyContent()/PeVerifyHash()
  invoke it with the authorized image security database name and GUID
  (EFI_IMAGE_SECURITY_DATABASE / gEfiImageSecurityDatabaseGuid), the matched
  list's SignatureSize, and the matched EFI_SIGNATURE_DATA node.

  @param[in]  VariableName  The database variable name (EFI_IMAGE_SECURITY_DATABASE).
  @param[in]  VendorGuid    The database variable vendor GUID.
  @param[in]  DataSize      Size of the matched signature data (SignatureSize).
  @param[in]  Data          The matched EFI_SIGNATURE_DATA node.

**/
typedef
VOID
(EFIAPI *CONTENT_VALIDATION_SECURE_BOOT_HOOK) (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN UINTN     DataSize,
  IN VOID      *Data
  );

/**
  Verify a PKCS#7 signature against the UEFI image security databases, per UEFI
  Spec 32.5.3.3.

  Shared signature-trust decision (UEFI Spec 32.5.3.3 rule C) used by both the
  EFI_PKCS7_VERIFY protocol and PE/COFF image verification. The AllowedDb (db)
  and optional RevokedDb (dbx) are NULL-terminated arrays of EFI_SIGNATURE_LIST
  regions, and an optional measurement hook is invoked on the matched db node
  when the signature is allowed. Content-hash revocation (rule A) is the
  caller's responsibility (see PeVerifyHash()/VerifyContentNoRevokedHash()).

  VerifyType selects how In/InSize is interpreted and which primitive verifies
  the signature against it (see CONTENT_VALIDATION_VERIFY_TYPE):
  - ContentValidationVerifyByPeImageHash: In is a PE image hash (AuthenticodeVerify).
  - ContentValidationVerifyByHash:        In is a plain content hash
                                        (AuthenticodeVerify, then Pkcs7VerifyByHash).
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
  @param[in]  SecureBootHook  Optional callback invoked with the matched db node
                              when the signature is allowed.

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
  );

/**
  Verify a content/image hash against the UEFI image security databases, per
  UEFI Spec 32.5.3.3 rules A and B (the unsigned-image path).

  There is no PKCS#7 signature: the decision is a direct content-hash lookup.
  InHash is matched against the content-hash lists (EFI_CERT_SHAxxx /
  EFI_CERT_V2_SHAxxx) of each database region. If InHash is in dbx the image is
  rejected; else if it is in db the image is accepted and the matched db node is
  reported to the measurement hook. AllowedDb/RevokedDb are NULL-terminated
  arrays of EFI_SIGNATURE_LIST regions.

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
  );

/**
  Check whether a buffer's content hash is revoked by the forbidden database
  (dbx) - the content-hash revocation check of the EFI_PKCS7_VERIFY protocol
  (UEFI Spec Ch. 37 VerifyBuffer/VerifySignature).

  VerifyType selects how In/InSize is interpreted:
  - ContentValidationVerifyByData: In is the raw content; it is hashed with each
    RevokedDb list's own algorithm before matching, so a revocation recorded
    under any supported algorithm is detected (used by VerifyBuffer()).
  - ContentValidationVerifyByHash / ByPeImageHash: In is a precomputed hash
    supplied by the caller; it is compared directly. Only dbx lists whose entry
    length equals InSize can match, so the caller is responsible for the hash
    algorithm it presents (used by VerifySignature()).

  NOTE: This is revocation only. There is intentionally no "hash in db -> accept"
  rule (UEFI Spec 32.5.3.3 rule B): for the EFI_PKCS7_VERIFY protocol the spec
  states hash certificates in AllowedDb are ignored and trust comes solely from
  the signer's X.509 certificate. db is therefore never consulted and this
  function takes no AllowedDb argument. EFI_SUCCESS means "not revoked", not
  "trusted". (The PE/COFF image path's rule B lives in PeVerifyHash().)

  @param[in]  In          Raw content or a precomputed hash, per VerifyType.
  @param[in]  InSize      Size of In in bytes.
  @param[in]  VerifyType  How In is interpreted (data to hash, or a hash).
  @param[in]  RevokedDb   NULL-terminated array of dbx EFI_SIGNATURE_LIST
                          regions, or NULL if dbx is absent.

  @retval EFI_SUCCESS            Content hash is not in dbx (not revoked).
  @retval EFI_SECURITY_VIOLATION Content hash is in dbx (revoked).
  @retval EFI_INVALID_PARAMETER  In is NULL or InSize is zero.

**/
EFI_STATUS
VerifyContentNoRevokedHash (
  IN UINT8                          *In,
  IN UINTN                          InSize,
  IN CONTENT_VALIDATION_VERIFY_TYPE  VerifyType,
  IN EFI_SIGNATURE_LIST             **RevokedDb       OPTIONAL
  );

#endif // CONTENT_VALIDATION_H_
