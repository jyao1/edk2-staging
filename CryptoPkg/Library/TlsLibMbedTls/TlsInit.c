/** @file
  SSL/TLS Initialization Library Wrapper Implementation over MbedTLS.

Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalTlsLib.h"
#include <psa/crypto.h>

/**
  Custom RNG callback for MbedTLS that wraps EDK2's RandomBytes().

  This function has the signature required by mbedtls_ssl_conf_rng():
    int f_rng(void *p_rng, unsigned char *output, size_t output_len)

  @param[in]   Context    Unused context pointer.
  @param[out]  Output     Buffer to fill with random bytes.
  @param[in]   Len        Number of random bytes requested.

  @retval  0   Success.
  @retval  -1  Failure.

**/
int
TlsMbedTlsRng (
  void           *Context,
  unsigned char  *Output,
  size_t         Len
  )
{
  if (RandomBytes (Output, (UINTN)Len)) {
    return 0;
  }

  return -1;
}

/**
  Initializes the MbedTLS library.

  This function registers ciphers and digests used directly and indirectly
  by SSL/TLS, and initializes the readable error messages.
  This function must be called before any other action takes places.

  @retval TRUE   The MbedTLS library has been initialized.
  @retval FALSE  Failed to initialize the MbedTLS library.

**/
BOOLEAN
EFIAPI
TlsInitialize (
  VOID
  )
{
  //
  // MbedTLS TLS 1.3 requires PSA Crypto to be initialized.
  // Initialize the pseudorandom number generator first.
  //
  if (!RandomSeed (NULL, 0)) {
    return FALSE;
  }

  return (psa_crypto_init () == PSA_SUCCESS);
}

/**
  Free an allocated TLS context object.

  @param[in]  TlsCtx    Pointer to the TLS context object to be released.

**/
VOID
EFIAPI
TlsCtxFree (
  IN   VOID  *TlsCtx
  )
{
  TLS_CONTEXT  *Ctx;

  Ctx = (TLS_CONTEXT *)TlsCtx;
  if (Ctx == NULL) {
    return;
  }

  FreePool (Ctx);
}

/**
  Creates a new TLS context object as framework to establish TLS/SSL enabled
  connections.

  @param[in]  MajorVer    Major Version of TLS/SSL Protocol.
  @param[in]  MinorVer    Minor Version of TLS/SSL Protocol.

  @return  Pointer to an allocated TLS context object.
           If the creation failed, TlsCtxNew() returns NULL.

**/
VOID *
EFIAPI
TlsCtxNew (
  IN     UINT8  MajorVer,
  IN     UINT8  MinorVer
  )
{
  TLS_CONTEXT  *Ctx;
  UINT16       ProtoVersion;

  ProtoVersion = (MajorVer << 8) | MinorVer;

  //
  // Only TLS 1.2 and TLS 1.3 are supported
  //
  if ((ProtoVersion != MBEDTLS_SSL_VERSION_TLS1_2) &&
      (ProtoVersion != MBEDTLS_SSL_VERSION_TLS1_3))
  {
    return NULL;
  }

  Ctx = AllocateZeroPool (sizeof (TLS_CONTEXT));
  if (Ctx == NULL) {
    return NULL;
  }

  //
  // Store the minimum version. Max is set based on compiled-in protocol support.
  //
  Ctx->MinVersion = (mbedtls_ssl_protocol_version)ProtoVersion;
 #ifdef MBEDTLS_SSL_PROTO_TLS1_3
  Ctx->MaxVersion = MBEDTLS_SSL_VERSION_TLS1_3;
 #else
  Ctx->MaxVersion = MBEDTLS_SSL_VERSION_TLS1_2;
 #endif

  return (VOID *)Ctx;
}

/**
  Free an allocated TLS object.

  This function removes the TLS object pointed to by Tls and frees up the
  allocated memory. If Tls is NULL, nothing is done.

  @param[in]  Tls    Pointer to the TLS object to be freed.

**/
VOID
EFIAPI
TlsFree (
  IN     VOID  *Tls
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    return;
  }

  mbedtls_ssl_free (&TlsConn->Ssl);
  mbedtls_ssl_config_free (&TlsConn->Conf);
  mbedtls_x509_crt_free (&TlsConn->CaCert);
  mbedtls_x509_crt_free (&TlsConn->OwnCert);
  mbedtls_pk_free (&TlsConn->OwnKey);

  if (TlsConn->InBuf != NULL) {
    FreePool (TlsConn->InBuf);
  }

  if (TlsConn->OutBuf != NULL) {
    FreePool (TlsConn->OutBuf);
  }

  if (TlsConn->SigAlgs != NULL) {
    FreePool (TlsConn->SigAlgs);
  }

  if (TlsConn->Groups != NULL) {
    FreePool (TlsConn->Groups);
  }

  FreePool (TlsConn);
}

/**
  Create a new TLS object for a connection.

  This function creates a new TLS object for a connection. The new object
  inherits the setting of the underlying context TlsCtx: connection method,
  options, verification setting.

  @param[in]  TlsCtx    Pointer to the TLS context object.

  @return  Pointer to an allocated TLS object.
           If the creation failed, TlsNew() returns NULL.

**/
VOID *
EFIAPI
TlsNew (
  IN     VOID  *TlsCtx
  )
{
  TLS_CONNECTION  *TlsConn;
  TLS_CONTEXT     *Ctx;
  int             Ret;

  Ctx = (TLS_CONTEXT *)TlsCtx;
  if (Ctx == NULL) {
    return NULL;
  }

  TlsConn = AllocateZeroPool (sizeof (TLS_CONNECTION));
  if (TlsConn == NULL) {
    return NULL;
  }

  //
  // Initialize all MbedTLS sub-contexts
  //
  mbedtls_ssl_init (&TlsConn->Ssl);
  mbedtls_ssl_config_init (&TlsConn->Conf);
  mbedtls_x509_crt_init (&TlsConn->CaCert);
  mbedtls_x509_crt_init (&TlsConn->OwnCert);
  mbedtls_pk_init (&TlsConn->OwnKey);

  //
  // Set up default configuration (client mode, TLS stream)
  // The endpoint can be changed later via TlsSetConnectionEnd.
  //
  Ret = mbedtls_ssl_config_defaults (
          &TlsConn->Conf,
          MBEDTLS_SSL_IS_CLIENT,
          MBEDTLS_SSL_TRANSPORT_STREAM,
          MBEDTLS_SSL_PRESET_DEFAULT
          );
  if (Ret != 0) {
    TlsFree ((VOID *)TlsConn);
    return NULL;
  }

  //
  // Set version bounds from context
  //
  mbedtls_ssl_conf_min_tls_version (&TlsConn->Conf, Ctx->MinVersion);
  mbedtls_ssl_conf_max_tls_version (&TlsConn->Conf, Ctx->MaxVersion);

  //
  // Set RNG callback using EDK2's RandomBytes() wrapper
  //
  mbedtls_ssl_conf_rng (&TlsConn->Conf, TlsMbedTlsRng, NULL);

  //
  // Default: no peer verification (will be set by TlsSetVerify)
  //
  mbedtls_ssl_conf_authmode (&TlsConn->Conf, MBEDTLS_SSL_VERIFY_NONE);

  //
  // Allocate I/O buffers
  //
  TlsConn->InBufSize  = MAX_BUFFER_SIZE;
  TlsConn->OutBufSize = MAX_BUFFER_SIZE;
  TlsConn->InBuf      = AllocateZeroPool (TlsConn->InBufSize);
  TlsConn->OutBuf     = AllocateZeroPool (TlsConn->OutBufSize);
  if ((TlsConn->InBuf == NULL) || (TlsConn->OutBuf == NULL)) {
    TlsFree ((VOID *)TlsConn);
    return NULL;
  }

  TlsConn->IsServer     = FALSE;
  TlsConn->SslSetupDone = FALSE;

  return (VOID *)TlsConn;
}

//
// Internal BIO send callback: SSL writes outgoing data here.
// We buffer it in OutBuf for the caller to retrieve via TlsCtrlTrafficOut.
//
int
TlsMbedTlsSend (
  void                *Ctx,
  const unsigned char *Buf,
  size_t              Len
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           Available;

  TlsConn   = (TLS_CONNECTION *)Ctx;
  Available = TlsConn->OutBufSize - TlsConn->OutBufEnd;

  if (Len > Available) {
    //
    // Not enough space - would block
    //
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }

  CopyMem (TlsConn->OutBuf + TlsConn->OutBufEnd, Buf, Len);
  TlsConn->OutBufEnd += Len;

  return (int)Len;
}

//
// Internal BIO recv callback: SSL reads incoming data from here.
// The caller feeds data via TlsCtrlTrafficIn into InBuf.
//
int
TlsMbedTlsRecv (
  void          *Ctx,
  unsigned char *Buf,
  size_t        Len
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           Available;

  TlsConn   = (TLS_CONNECTION *)Ctx;
  Available = TlsConn->InBufEnd - TlsConn->InBufStart;

  if (Available == 0) {
    //
    // No data available - would block
    //
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  if (Len > Available) {
    Len = Available;
  }

  CopyMem (Buf, TlsConn->InBuf + TlsConn->InBufStart, Len);
  TlsConn->InBufStart += Len;

  //
  // Compact buffer if fully consumed
  //
  if (TlsConn->InBufStart == TlsConn->InBufEnd) {
    TlsConn->InBufStart = 0;
    TlsConn->InBufEnd   = 0;
  }

  return (int)Len;
}

//
// ============== TlsGetSupported* APIs ==============
//

/**
  Get the list of TLS protocol versions supported by the MbedTLS library.

  @param[out]     Versions      Buffer for UINT16 TLS version values.
  @param[in,out]  VersionCount  On input, max entries. On output, actual count.

  @retval EFI_SUCCESS           Version list returned successfully.
  @retval EFI_INVALID_PARAMETER VersionCount is NULL.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small, VersionCount updated.
**/
EFI_STATUS
EFIAPI
TlsGetSupportedVersions (
  OUT    UINT16  *Versions      OPTIONAL,
  IN OUT UINTN   *VersionCount
  )
{
  STATIC CONST UINT16  SupportedVersions[] = {
 #ifdef MBEDTLS_SSL_PROTO_TLS1_2
    0x0303,   // TLS 1.2
 #endif
 #ifdef MBEDTLS_SSL_PROTO_TLS1_3
    0x0304,   // TLS 1.3
 #endif
  };

  UINTN  Count;

  if (VersionCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Count = ARRAY_SIZE (SupportedVersions);

  if ((Versions == NULL) || (*VersionCount < Count)) {
    *VersionCount = Count;
    if (Versions == NULL) {
      return EFI_SUCCESS;
    }

    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (Versions, SupportedVersions, Count * sizeof (UINT16));
  *VersionCount = Count;
  return EFI_SUCCESS;
}

/**
  Get the list of TLS cipher suites supported by the MbedTLS library.

  Queries mbedtls_ssl_list_ciphersuites() to obtain all compiled-in
  cipher suites.

  @param[out]     CipherSuites  Buffer for UINT16 IANA cipher suite IDs.
  @param[in,out]  CipherCount   On input, max entries. On output, actual count.

  @retval EFI_SUCCESS           Cipher suite list returned successfully.
  @retval EFI_INVALID_PARAMETER CipherCount is NULL.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small, CipherCount updated.
**/
EFI_STATUS
EFIAPI
TlsGetSupportedCipherSuites (
  OUT    UINT16  *CipherSuites  OPTIONAL,
  IN OUT UINTN   *CipherCount
  )
{
  CONST int  *List;
  UINTN      Count;
  UINTN      Index;

  if (CipherCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  List  = mbedtls_ssl_list_ciphersuites ();
  Count = 0;
  while (List[Count] != 0) {
    Count++;
  }

  if ((CipherSuites == NULL) || (*CipherCount < Count)) {
    *CipherCount = Count;
    if (CipherSuites == NULL) {
      return EFI_SUCCESS;
    }

    return EFI_BUFFER_TOO_SMALL;
  }

  for (Index = 0; Index < Count; Index++) {
    CipherSuites[Index] = (UINT16)List[Index];
  }

  *CipherCount = Count;
  return EFI_SUCCESS;
}

/**
  Get the list of TLS key exchange groups supported by the MbedTLS library.

  Returns the IANA named group identifiers for elliptic curves and key
  exchange groups that MbedTLS actually supports at runtime.

  @param[out]     Groups      Buffer for UINT16 IANA named group IDs.
  @param[in,out]  GroupCount  On input, max entries. On output, actual count.

  @retval EFI_SUCCESS           Group list returned successfully.
  @retval EFI_INVALID_PARAMETER GroupCount is NULL.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small, GroupCount updated.
**/
EFI_STATUS
EFIAPI
TlsGetSupportedGroups (
  OUT    UINT16  *Groups      OPTIONAL,
  IN OUT UINTN   *GroupCount
  )
{
  //
  // MbedTLS supported groups based on compiled-in ECP curves.
  // Only classic groups are supported - no PQC (ML-KEM).
  //
  STATIC CONST UINT16  SupportedGroups[] = {
 #ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
    0x0017,   // secp256r1
 #endif
 #ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
    0x0018,   // secp384r1
 #endif
 #ifdef MBEDTLS_ECP_DP_SECP521R1_ENABLED
    0x0019,   // secp521r1
 #endif
 #ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
    0x001D,   // x25519
 #endif
 #ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
    0x001E,   // x448
 #endif
  };

  UINTN  Count;

  if (GroupCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Count = ARRAY_SIZE (SupportedGroups);

  if ((Groups == NULL) || (*GroupCount < Count)) {
    *GroupCount = Count;
    if (Groups == NULL) {
      return EFI_SUCCESS;
    }

    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (Groups, SupportedGroups, Count * sizeof (UINT16));
  *GroupCount = Count;
  return EFI_SUCCESS;
}

/**
  Get the list of TLS signature schemes supported by the MbedTLS library.

  Returns the IANA TLS SignatureScheme identifiers for signature algorithms
  that MbedTLS actually supports. No PQC (ML-DSA) schemes are included.

  @param[out]     SigAlgs     Buffer for UINT16 IANA SignatureScheme IDs.
  @param[in,out]  SigAlgCount On input, max entries. On output, actual count.

  @retval EFI_SUCCESS           Signature scheme list returned successfully.
  @retval EFI_INVALID_PARAMETER SigAlgCount is NULL.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small, SigAlgCount updated.
**/
EFI_STATUS
EFIAPI
TlsGetSupportedSignatureSchemes (
  OUT    UINT16  *SigAlgs     OPTIONAL,
  IN OUT UINTN   *SigAlgCount
  )
{
  //
  // MbedTLS supported signature schemes based on compiled-in algorithms.
  // Only classic schemes - no PQC (ML-DSA).
  //
  STATIC CONST UINT16  SupportedSigAlgs[] = {
 #ifdef MBEDTLS_ECDSA_C
    0x0403,   // ecdsa_secp256r1_sha256
    0x0503,   // ecdsa_secp384r1_sha384
    0x0603,   // ecdsa_secp521r1_sha512
 #endif
    //
    // RSA-PSS schemes (TLS 1.3)
    //
    0x0804,   // rsa_pss_rsae_sha256
    0x0805,   // rsa_pss_rsae_sha384
    0x0806,   // rsa_pss_rsae_sha512
    //
    // RSA PKCS#1 v1.5 schemes (TLS 1.2)
    //
    0x0401,   // rsa_pkcs1_sha256
    0x0501,   // rsa_pkcs1_sha384
    0x0601,   // rsa_pkcs1_sha512
  };

  UINTN  Count;

  if (SigAlgCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Count = ARRAY_SIZE (SupportedSigAlgs);

  if ((SigAlgs == NULL) || (*SigAlgCount < Count)) {
    *SigAlgCount = Count;
    if (SigAlgs == NULL) {
      return EFI_SUCCESS;
    }

    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (SigAlgs, SupportedSigAlgs, Count * sizeof (UINT16));
  *SigAlgCount = Count;
  return EFI_SUCCESS;
}
