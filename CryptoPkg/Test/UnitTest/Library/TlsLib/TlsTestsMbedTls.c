/** @file
  TLS Handshake Loopback Unit Test -- MbedTLS configuration.

  This file contains the test parameter table for MbedTLS which only supports
  classic TLS 1.2 and TLS 1.3 algorithms. PQC algorithms (ML-DSA, ML-KEM)
  are not supported by MbedTLS and are excluded from this configuration.

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TlsTests.h"

//
// Test parameter table for MbedTLS -- only classic algorithms.
// PQC tests (ML-DSA, X25519MLKEM768) are excluded because MbedTLS
// does not implement post-quantum cryptography.
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
};

UINTN  mTlsTestCount = ARRAY_SIZE (mTlsTestParams);
