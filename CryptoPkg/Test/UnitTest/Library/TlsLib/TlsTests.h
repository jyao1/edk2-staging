/** @file
  Header for TLS Handshake Unit Test.

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef TLS_TESTS_H_
#define TLS_TESTS_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/UnitTestLib.h>

//
// TLS protocol version constants (from OpenSSL tls1.h)
//
#define TLS1_2_VERSION  0x0303
#define TLS1_3_VERSION  0x0304

//
// TLS protocol version major/minor (from IndustryStandard/Tls1.h, avoiding
// the full include which depends on Protocol/Tls.h EFI types)
//
#define TLS12_PROTOCOL_VERSION_MAJOR  0x03
#define TLS12_PROTOCOL_VERSION_MINOR  0x03

//
// Configuration for a single TLS handshake test variation.
// Add new fields here to extend coverage (e.g. mutual auth, ALPN, etc.).
//
// CipherList -- OpenSSL TLS 1.2 cipher string (NULL to skip). Possible values:
//   RSA key exchange:
//     "AES128-SHA", "AES256-SHA", "AES128-SHA256", "AES256-SHA256",
//     "AES128-GCM-SHA256", "AES256-GCM-SHA384"
//   ECDHE-RSA key exchange:
//     "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA",
//     "ECDHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA384",
//     "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"
//   ECDHE-ECDSA key exchange (requires EC KeyAlgorithm):
//     "ECDHE-ECDSA-AES128-SHA", "ECDHE-ECDSA-AES256-SHA",
//     "ECDHE-ECDSA-AES128-SHA256", "ECDHE-ECDSA-AES256-SHA384",
//     "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384"
//
// CipherSuites -- OpenSSL TLS 1.3 ciphersuite string (NULL to skip). Possible values:
//     "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"
//
// KeyAlgorithm -- Algorithm name to select embedded cert/key for the test.
//   Must be explicitly specified. Supported values:
//   Classic:
//     "RSA", "EC", "ED25519", "ED448"
//   PQC -- ML-DSA (FIPS 204):
//     "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
//   PQC -- SLH-DSA (FIPS 205) SHA2-based:
//     "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
//     "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
//     "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"
//   PQC -- SLH-DSA (FIPS 205) SHAKE-based:
//     "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
//     "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
//     "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
//
// Groups -- TLS key exchange group name (NULL = OpenSSL default). Possible values:
//   Classic ECDHE:
//     "P-256", "P-384", "P-521", "X25519", "X448"
//   Classic FFDHE:
//     "ffdhe2048", "ffdhe3072", "ffdhe4096"
//   PQC -- ML-KEM (FIPS 203) standalone:
//     "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
//   PQC -- ML-KEM hybrid (TLS 1.3 only):
//     "X25519MLKEM768", "X448MLKEM1024",
//     "SecP256r1MLKEM768", "SecP384r1MLKEM1024"
//   Multiple groups can be colon-separated, e.g. "X25519MLKEM768:X25519"
//
// SignatureSchemes -- TLS signature scheme string (NULL = OpenSSL default). Possible values:
//   TLS 1.2 style (hash+sig):
//     "RSA+SHA256", "RSA+SHA384", "RSA+SHA512",
//     "ECDSA+SHA256", "ECDSA+SHA384", "ECDSA+SHA512"
//   TLS 1.3 SignatureScheme names:
//     "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512",
//     "rsa_pss_pss_sha256", "rsa_pss_pss_sha384", "rsa_pss_pss_sha512",
//     "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384",
//     "ed25519", "ed448"
//   PQC -- ML-DSA (FIPS 204):
//     "mldsa44", "mldsa65", "mldsa87"
//   Multiple values can be colon-separated, e.g. "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384"
//
typedef struct {
  CONST CHAR8    *Description;      // Human-readable test name
  int            MinVersion;        // TLS version (TLS1_2_VERSION, TLS1_3_VERSION, etc.)
  int            MaxVersion;        // TLS version upper bound
  CONST CHAR8    *CipherList;       // Cipher string for TLS 1.2 (see above)
  CONST CHAR8    *CipherSuites;     // Ciphersuites string for TLS 1.3 (see above)
  CONST CHAR8    *KeyAlgorithm;     // Key algorithm to select embedded cert/key (see above)
  CONST CHAR8    *Groups;           // Key exchange groups (see above)
  CONST CHAR8    *SignatureSchemes;  // Signature schemes (see above)
} TLS_TEST_PARAMS;

//
// TLS test endpoint -- wraps the TlsLib context and connection objects.
//
typedef struct {
  VOID    *Ctx;     // SSL_CTX via TlsCtxNew
  VOID    *Tls;     // TLS connection via TlsNew
} TLS_TEST_ENDPOINT;

//
// Table of test configurations, defined in TlsTests.c
//
extern TLS_TEST_PARAMS  mTlsTestParams[];
extern UINTN            mTlsTestCount;

UNIT_TEST_STATUS
EFIAPI
TestTlsHandshake (
  IN UNIT_TEST_CONTEXT  Context
  );

//
// Client setup/cleanup -- defined in TlsTestClient.c
//
EFI_STATUS
EFIAPI
TlsTestSetupClient (
  OUT TLS_TEST_ENDPOINT  *Client,
  IN  TLS_TEST_PARAMS    *Params,
  IN  VOID               *CaCertDer,
  IN  UINTN              CaCertDerSize
  );

VOID
EFIAPI
TlsTestCleanupClient (
  IN OUT TLS_TEST_ENDPOINT  *Client
  );

//
// Server setup/cleanup -- defined in TlsTestServer.c
//
EFI_STATUS
EFIAPI
TlsTestSetupServer (
  OUT TLS_TEST_ENDPOINT  *Server,
  IN  TLS_TEST_PARAMS    *Params,
  IN  VOID               *CertDer,
  IN  UINTN              CertDerSize,
  IN  VOID               *KeyDer,
  IN  UINTN              KeyDerSize
  );

VOID
EFIAPI
TlsTestCleanupServer (
  IN OUT TLS_TEST_ENDPOINT  *Server
  );

#endif // TLS_TESTS_H_
