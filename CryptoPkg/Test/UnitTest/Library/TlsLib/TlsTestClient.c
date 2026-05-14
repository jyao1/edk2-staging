/** @file
  TLS Test Client Setup using TlsLib APIs.

  This file provides client-side TLS setup and cleanup functions that
  use the TlsLib library wrapper instead of raw OpenSSL APIs.

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TlsTests.h"
#include <Library/TlsLib.h>

/**
  Set up a TLS client endpoint using TlsLib APIs.

  @param[out] Client        Pointer to the endpoint structure to initialize.
  @param[in]  Params        Test parameters (version, cipher, groups, etc.).
  @param[in]  CaCertDer     DER-encoded CA certificate for trust store.
  @param[in]  CaCertDerSize Size of CaCertDer in bytes.

  @retval EFI_SUCCESS     Client endpoint set up successfully.
  @retval Others          Setup failed.

**/
EFI_STATUS
EFIAPI
TlsTestSetupClient (
  OUT TLS_TEST_ENDPOINT  *Client,
  IN  TLS_TEST_PARAMS    *Params,
  IN  VOID               *CaCertDer,
  IN  UINTN              CaCertDerSize
  )
{
  EFI_STATUS  Status;
  UINT8       MajorVer;
  UINT8       MinorVer;

  Client->Ctx = NULL;
  Client->Tls = NULL;

  //
  // Create TLS context. Use TLS 1.2 as minimum for context creation.
  // The actual version is set later via TlsSetVersion.
  //
  Client->Ctx = TlsCtxNew (TLS12_PROTOCOL_VERSION_MAJOR, TLS12_PROTOCOL_VERSION_MINOR);
  if (Client->Ctx == NULL) {
    return EFI_ABORTED;
  }

  //
  // Create TLS connection object (sets up internal BIOs)
  //
  Client->Tls = TlsNew (Client->Ctx);
  if (Client->Tls == NULL) {
    return EFI_ABORTED;
  }

  //
  // Set client mode
  //
  Status = TlsSetConnectionEnd (Client->Tls, FALSE);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Set TLS version
  //
  MajorVer = (UINT8)((Params->MaxVersion >> 8) & 0xFF);
  MinorVer = (UINT8)(Params->MaxVersion & 0xFF);
  Status   = TlsSetVersion (Client->Tls, MajorVer, MinorVer);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Lower security level to 2 (112-bit) to allow RSA 2048 certificates.
  // TlsNew sets security level 3 (128-bit) which rejects RSA 2048.
  //
  Status = TlsSetSecurityLevel (Client->Tls, 2);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Set TLS 1.2 cipher list
  //
  if (Params->CipherList != NULL) {
    Status = TlsSetCipherString (Client->Tls, Params->CipherList);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Set TLS 1.3 ciphersuites
  //
  if (Params->CipherSuites != NULL) {
    Status = TlsSetCipherSuites (Client->Tls, Params->CipherSuites);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Set key exchange groups
  //
  if (Params->Groups != NULL) {
    Status = TlsSetGroups (Client->Tls, Params->Groups);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Set signature schemes
  //
  if (Params->SignatureSchemes != NULL) {
    Status = TlsSetSignatureSchemeList (Client->Tls, Params->SignatureSchemes);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Add CA certificate to trust store
  //
  Status = TlsSetCaCertificate (Client->Tls, CaCertDer, CaCertDerSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Enable peer certificate verification
  //
  TlsSetVerify (Client->Tls, 0x01);

  //
  // Skip certificate time validation.
  // The EDK2 host environment uses ConstantTimeClock which returns 0 from time()
  // and NULL from gmtime(), causing OpenSSL cert time verification to crash.
  //
  Status = TlsSetNoCheckTime (Client->Tls);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  Clean up a TLS client endpoint.

  @param[in,out] Client  Pointer to the endpoint structure to clean up.

**/
VOID
EFIAPI
TlsTestCleanupClient (
  IN OUT TLS_TEST_ENDPOINT  *Client
  )
{
  if (Client->Tls != NULL) {
    TlsFree (Client->Tls);
    Client->Tls = NULL;
  }

  if (Client->Ctx != NULL) {
    TlsCtxFree (Client->Ctx);
    Client->Ctx = NULL;
  }
}
