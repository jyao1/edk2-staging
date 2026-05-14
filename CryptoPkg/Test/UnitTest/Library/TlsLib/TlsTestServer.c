/** @file
  TLS Test Server Setup using TlsLib APIs.

  This file provides server-side TLS setup and cleanup functions that
  use the TlsLib library wrapper instead of raw OpenSSL APIs.

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TlsTests.h"
#include <Library/TlsLib.h>

/**
  Set up a TLS server endpoint using TlsLib APIs.

  @param[out] Server        Pointer to the endpoint structure to initialize.
  @param[in]  Params        Test parameters (version, cipher, groups, etc.).
  @param[in]  CertDer       DER-encoded server certificate.
  @param[in]  CertDerSize   Size of CertDer in bytes.
  @param[in]  KeyDer        DER-encoded server private key (PKCS#8).
  @param[in]  KeyDerSize    Size of KeyDer in bytes.

  @retval EFI_SUCCESS     Server endpoint set up successfully.
  @retval Others          Setup failed.

**/
EFI_STATUS
EFIAPI
TlsTestSetupServer (
  OUT TLS_TEST_ENDPOINT  *Server,
  IN  TLS_TEST_PARAMS    *Params,
  IN  VOID               *CertDer,
  IN  UINTN              CertDerSize,
  IN  VOID               *KeyDer,
  IN  UINTN              KeyDerSize
  )
{
  EFI_STATUS  Status;
  UINT8       MajorVer;
  UINT8       MinorVer;

  Server->Ctx = NULL;
  Server->Tls = NULL;

  //
  // Create TLS context. Use TLS 1.2 as minimum for context creation.
  // The actual version is set later via TlsSetVersion.
  //
  Server->Ctx = TlsCtxNew (TLS12_PROTOCOL_VERSION_MAJOR, TLS12_PROTOCOL_VERSION_MINOR);
  if (Server->Ctx == NULL) {
    return EFI_ABORTED;
  }

  //
  // Create TLS connection object (sets up internal BIOs)
  //
  Server->Tls = TlsNew (Server->Ctx);
  if (Server->Tls == NULL) {
    return EFI_ABORTED;
  }

  //
  // Set server mode
  //
  Status = TlsSetConnectionEnd (Server->Tls, TRUE);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Set TLS version
  //
  MajorVer = (UINT8)((Params->MaxVersion >> 8) & 0xFF);
  MinorVer = (UINT8)(Params->MaxVersion & 0xFF);
  Status   = TlsSetVersion (Server->Tls, MajorVer, MinorVer);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Lower security level to 2 (112-bit) to allow RSA 2048 certificates.
  // TlsNew sets security level 3 (128-bit) which rejects RSA 2048.
  //
  Status = TlsSetSecurityLevel (Server->Tls, 2);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Set TLS 1.2 cipher list
  //
  if (Params->CipherList != NULL) {
    Status = TlsSetCipherString (Server->Tls, Params->CipherList);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Set TLS 1.3 ciphersuites
  //
  if (Params->CipherSuites != NULL) {
    Status = TlsSetCipherSuites (Server->Tls, Params->CipherSuites);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Set key exchange groups
  //
  if (Params->Groups != NULL) {
    Status = TlsSetGroups (Server->Tls, Params->Groups);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Set signature schemes
  //
  if (Params->SignatureSchemes != NULL) {
    Status = TlsSetSignatureSchemeList (Server->Tls, Params->SignatureSchemes);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Load server certificate
  //
  Status = TlsSetHostPublicCert (Server->Tls, CertDer, CertDerSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Load server private key
  //
  Status = TlsSetHostPrivateKey (Server->Tls, KeyDer, KeyDerSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  Clean up a TLS server endpoint.

  @param[in,out] Server  Pointer to the endpoint structure to clean up.

**/
VOID
EFIAPI
TlsTestCleanupServer (
  IN OUT TLS_TEST_ENDPOINT  *Server
  )
{
  if (Server->Tls != NULL) {
    TlsFree (Server->Tls);
    Server->Tls = NULL;
  }

  if (Server->Ctx != NULL) {
    TlsCtxFree (Server->Ctx);
    Server->Ctx = NULL;
  }
}
