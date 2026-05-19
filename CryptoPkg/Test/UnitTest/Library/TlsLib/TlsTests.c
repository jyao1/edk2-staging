/** @file
  TLS Handshake Loopback Unit Test -- OpenSSL test parameters.

  Contains the test parameter table for OpenSSL which supports both
  classic and PQC algorithms.

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TlsTests.h"

//
// Test parameter table -- add new rows to extend TLS test coverage.
// Each entry drives one independent handshake test case.
//
TLS_TEST_PARAMS  mTlsTestParams[] = {
  {
    "TLS 1.2 AES128-SHA",
    TLS1_2_VERSION,
    TLS1_2_VERSION,
    "AES128-SHA",       // CipherList  (TLS 1.2)
    NULL,               // CipherSuites (TLS 1.3 -- unused)
    "RSA",              // KeyAlgorithm
    "P-256",            // Groups
    "RSA+SHA256"        // SignatureSchemes (TLS 1.2 style)
  },
  {
    "TLS 1.2 AES256-GCM-SHA384",
    TLS1_2_VERSION,
    TLS1_2_VERSION,
    "AES256-GCM-SHA384",
    NULL,
    "RSA",
    "P-256",
    "RSA+SHA256"        // SignatureSchemes (TLS 1.2 style)
  },
  //
  // TLS 1.3 test cases
  //
  {
    "TLS 1.3 TLS_AES_128_GCM_SHA256",
    TLS1_3_VERSION,
    TLS1_3_VERSION,
    NULL,
    "TLS_AES_128_GCM_SHA256",
    "RSA",
    "X25519",
    "rsa_pss_rsae_sha256"  // SignatureSchemes (TLS 1.3 style)
  },
  //
  // PQC test cases -- ML-DSA authentication (TLS 1.3 only)
  //
  {
    "TLS 1.3 ML-DSA-65 Auth",
    TLS1_3_VERSION,
    TLS1_3_VERSION,
    NULL,
    "TLS_AES_128_GCM_SHA256",
    "ML-DSA-65",
    "X25519",
    "mldsa65"              // SignatureSchemes (PQC)
  },
  //
  // PQC test cases -- ML-KEM hybrid key exchange (TLS 1.3 only)
  //
  {
    "TLS 1.3 X25519MLKEM768 KeyExchange",
    TLS1_3_VERSION,
    TLS1_3_VERSION,
    NULL,
    "TLS_AES_128_GCM_SHA256",
    "RSA",
    "X25519MLKEM768",
    "rsa_pss_rsae_sha256"  // SignatureSchemes
  },
  //
  // PQC test cases -- ML-DSA auth + ML-KEM key exchange (full PQC, TLS 1.3 only)
  //
  {
    "TLS 1.3 ML-DSA-65 + X25519MLKEM768",
    TLS1_3_VERSION,
    TLS1_3_VERSION,
    NULL,
    "TLS_AES_128_GCM_SHA256",
    "ML-DSA-65",
    "X25519MLKEM768",
    "mldsa65"              // SignatureSchemes (full PQC)
  },
};

UINTN  mTlsTestCount = ARRAY_SIZE (mTlsTestParams);
