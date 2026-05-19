/** @file
  Internal include file for TlsLibMbedTls.

Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __INTERNAL_TLS_LIB_MBEDTLS_H__
#define __INTERNAL_TLS_LIB_MBEDTLS_H__

#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/SafeIntLib.h>
#include <Protocol/Tls.h>
#include <IndustryStandard/Tls1.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

#define MAX_BUFFER_SIZE  32768

///
/// TLS Connection Context wrapping MbedTLS objects.
/// This is analogous to TLS_CONNECTION in the OpenSSL version.
///
typedef struct {
  //
  // MbedTLS SSL context (per-connection state)
  //
  mbedtls_ssl_context       Ssl;
  //
  // MbedTLS SSL configuration (shared settings)
  //
  mbedtls_ssl_config        Conf;
  //
  // Certificate trust chain (CA certificates for peer verification)
  //
  mbedtls_x509_crt          CaCert;
  //
  // Own certificate chain (host public certificate)
  //
  mbedtls_x509_crt          OwnCert;
  //
  // Own private key
  //
  mbedtls_pk_context        OwnKey;
  //
  // Memory-based I/O buffers (replaces OpenSSL BIO)
  //
  UINT8                     *InBuf;       // Data written by peer (to be read by SSL)
  UINTN                     InBufSize;    // Total allocated size
  UINTN                     InBufStart;   // Read position
  UINTN                     InBufEnd;     // Write position (data available)
  UINT8                     *OutBuf;      // Data written by SSL (to be read by peer)
  UINTN                     OutBufSize;   // Total allocated size
  UINTN                     OutBufStart;  // Read position
  UINTN                     OutBufEnd;    // Write position (data available)
  //
  // Connection state flags
  //
  BOOLEAN                   IsServer;
  BOOLEAN                   SslSetupDone;
  //
  // Signature algorithms list (must persist for lifetime of config)
  //
  UINT16                    *SigAlgs;
  //
  // Groups list (must persist for lifetime of config)
  //
  UINT16                    *Groups;
} TLS_CONNECTION;

///
/// TLS Context wrapping MbedTLS configuration template.
/// This is analogous to SSL_CTX in the OpenSSL version.
///
typedef struct {
  //
  // Protocol version bounds
  //
  mbedtls_ssl_protocol_version  MinVersion;
  mbedtls_ssl_protocol_version  MaxVersion;
} TLS_CONTEXT;

//
// Internal BIO callback functions for MbedTLS
//
int
TlsMbedTlsSend (
  void                *Ctx,
  const unsigned char *Buf,
  size_t              Len
  );

int
TlsMbedTlsRecv (
  void          *Ctx,
  unsigned char *Buf,
  size_t        Len
  );

//
// Internal RNG callback wrapping EDK2 RandomBytes()
//
int
TlsMbedTlsRng (
  void           *Context,
  unsigned char  *Output,
  size_t         Len
  );

#endif
