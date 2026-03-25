/** @file
  SSL/TLS Initialization Library Wrapper Implementation over OpenSSL.

Copyright (c) 2016 - 2017, Intel Corporation. All rights reserved.<BR>
(C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalTlsLib.h"

/**
  Initializes the OpenSSL library.

  This function registers ciphers and digests used directly and indirectly
  by SSL/TLS, and initializes the readable error messages.
  This function must be called before any other action takes places.

  @retval TRUE   The OpenSSL library has been initialized.
  @retval FALSE  Failed to initialize the OpenSSL library.

**/
BOOLEAN
EFIAPI
TlsInitialize (
  VOID
  )
{
  INTN  Ret;

  //
  // Performs initialization of crypto and ssl library, and loads required
  // algorithms.
  //
  Ret = OPENSSL_init_ssl (
          OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
          NULL
          );
  if (Ret != 1) {
    return FALSE;
  }

  //
  // Initialize the pseudorandom number generator.
  //
  return RandomSeed (NULL, 0);
}

/**
  Free an allocated SSL_CTX object.

  @param[in]  TlsCtx    Pointer to the SSL_CTX object to be released.

**/
VOID
EFIAPI
TlsCtxFree (
  IN   VOID  *TlsCtx
  )
{
  if (TlsCtx == NULL) {
    return;
  }

  if (TlsCtx != NULL) {
    SSL_CTX_free ((SSL_CTX *)(TlsCtx));
  }
}

/**
  Creates a new SSL_CTX object as framework to establish TLS/SSL enabled
  connections.

  @param[in]  MajorVer    Major Version of TLS/SSL Protocol.
  @param[in]  MinorVer    Minor Version of TLS/SSL Protocol.

  @return  Pointer to an allocated SSL_CTX object.
           If the creation failed, TlsCtxNew() returns NULL.

**/
VOID *
EFIAPI
TlsCtxNew (
  IN     UINT8  MajorVer,
  IN     UINT8  MinorVer
  )
{
  SSL_CTX  *TlsCtx;
  UINT16   ProtoVersion;

  ProtoVersion = (MajorVer << 8) | MinorVer;

  TlsCtx = SSL_CTX_new (SSLv23_client_method ());
  if (TlsCtx == NULL) {
    return NULL;
  }

  //
  // Ensure SSLv3 is disabled
  //
  SSL_CTX_set_options (TlsCtx, SSL_OP_NO_SSLv3);

  //
  // Treat as minimum accepted versions by setting the minimal bound.
  // Client can use higher TLS version if server supports it
  //
  SSL_CTX_set_min_proto_version (TlsCtx, ProtoVersion);

  return (VOID *)TlsCtx;
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

  //
  // Free the internal TLS and related BIO objects.
  //
  if (TlsConn->Ssl != NULL) {
    SSL_free (TlsConn->Ssl);
  }

  OPENSSL_free (Tls);
}

/**
  Create a new TLS object for a connection.

  This function creates a new TLS object for a connection. The new object
  inherits the setting of the underlying context TlsCtx: connection method,
  options, verification setting.

  @param[in]  TlsCtx    Pointer to the SSL_CTX object.

  @return  Pointer to an allocated SSL object.
           If the creation failed, TlsNew() returns NULL.

**/
VOID *
EFIAPI
TlsNew (
  IN     VOID  *TlsCtx
  )
{
  TLS_CONNECTION  *TlsConn;
  SSL_CTX         *SslCtx;
  X509_STORE      *X509Store;

  TlsConn = NULL;

  //
  // Allocate one new TLS_CONNECTION object
  //
  TlsConn = (TLS_CONNECTION *)OPENSSL_malloc (sizeof (TLS_CONNECTION));
  if (TlsConn == NULL) {
    return NULL;
  }

  TlsConn->Ssl = NULL;

  //
  // Create a new SSL Object
  //
  TlsConn->Ssl = SSL_new ((SSL_CTX *)TlsCtx);
  if (TlsConn->Ssl == NULL) {
    TlsFree ((VOID *)TlsConn);
    return NULL;
  }

  //
  // This retains compatibility with previous version of OpenSSL.
  //
  SSL_set_security_level (TlsConn->Ssl, 3);

  //
  // Initialize the created SSL Object
  //
  SSL_set_info_callback (TlsConn->Ssl, NULL);

  TlsConn->InBio = NULL;

  //
  // Set up Reading BIO for TLS connection
  //
  TlsConn->InBio = BIO_new (BIO_s_mem ());
  if (TlsConn->InBio == NULL) {
    TlsFree ((VOID *)TlsConn);
    return NULL;
  }

  //
  // Sets the behaviour of memory BIO when it is empty. It will set the
  // read retry flag.
  //
  BIO_set_mem_eof_return (TlsConn->InBio, -1);

  TlsConn->OutBio = NULL;

  //
  // Set up Writing BIO for TLS connection
  //
  TlsConn->OutBio = BIO_new (BIO_s_mem ());
  if (TlsConn->OutBio == NULL) {
    TlsFree ((VOID *)TlsConn);
    return NULL;
  }

  //
  // Sets the behaviour of memory BIO when it is empty. It will set the
  // write retry flag.
  //
  BIO_set_mem_eof_return (TlsConn->OutBio, -1);

  ASSERT (TlsConn->Ssl != NULL && TlsConn->InBio != NULL && TlsConn->OutBio != NULL);

  //
  // Connects the InBio and OutBio for the read and write operations.
  //
  SSL_set_bio (TlsConn->Ssl, TlsConn->InBio, TlsConn->OutBio);

  //
  // Create new X509 store if needed
  //
  SslCtx    = SSL_get_SSL_CTX (TlsConn->Ssl);
  X509Store = SSL_CTX_get_cert_store (SslCtx);
  if (X509Store == NULL) {
    X509Store = X509_STORE_new ();
    if (X509Store == NULL) {
      TlsFree ((VOID *)TlsConn);
      return NULL;
    }

    SSL_CTX_set1_verify_cert_store (SslCtx, X509Store);
    X509_STORE_free (X509Store);
  }

  //
  // Set X509_STORE flags used in certificate validation
  //
  X509_STORE_set_flags (
    X509Store,
    X509_V_FLAG_PARTIAL_CHAIN
    );
  return (VOID *)TlsConn;
}

/**
  Get the list of TLS protocol versions supported by the TLS library.

  The supported versions are determined by the compile-time OpenSSL
  configuration. Currently TLS 1.0, 1.1, and 1.2 are supported
  (TLS 1.3 is disabled via no-tls1_3 in the OpenSSL build).

  @param[out]     Versions      Buffer for UINT16 version values.
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
  //
  // Supported TLS versions in the current OpenSSL build.
  // TLS 1.3 (0x0304) is excluded because OpenSSL is compiled with no-tls1_3.
  //
  STATIC CONST UINT16  SupportedVersions[] = {
    0x0301,  // TLS 1.0
    0x0302,  // TLS 1.1
    0x0303,  // TLS 1.2
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
  Get the list of TLS cipher suites supported by the TLS library.

  Creates a temporary SSL_CTX and SSL object to query the default cipher
  list at security level 3 (matching TlsNew()), then extracts the IANA
  cipher suite identifiers.

  @param[out]     CipherSuites  Buffer for UINT16 IANA cipher suite IDs.
  @param[in,out]  CipherCount   On input, max entries. On output, actual count.

  @retval EFI_SUCCESS           Cipher suite list returned successfully.
  @retval EFI_INVALID_PARAMETER CipherCount is NULL.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small, CipherCount updated.
  @retval EFI_UNSUPPORTED       Failed to create TLS context.
**/
EFI_STATUS
EFIAPI
TlsGetSupportedCipherSuites (
  OUT    UINT16  *CipherSuites  OPTIONAL,
  IN OUT UINTN   *CipherCount
  )
{
  SSL_CTX             *Ctx;
  SSL                 *Ssl;
  STACK_OF (SSL_CIPHER) *Ciphers;
  CONST SSL_CIPHER    *Cipher;
  UINTN               Count;
  UINTN               Index;

  if (CipherCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Create a temporary SSL_CTX with TLS 1.0 as minimum (same as production).
  //
  Ctx = SSL_CTX_new (SSLv23_client_method ());
  if (Ctx == NULL) {
    return EFI_UNSUPPORTED;
  }

  SSL_CTX_set_options (Ctx, SSL_OP_NO_SSLv3);
  SSL_CTX_set_min_proto_version (Ctx, TLS1_VERSION);

  Ssl = SSL_new (Ctx);
  if (Ssl == NULL) {
    SSL_CTX_free (Ctx);
    return EFI_UNSUPPORTED;
  }

  //
  // Set security level 3 to match what TlsNew() uses in production.
  //
  SSL_set_security_level (Ssl, 3);

  //
  // Get the cipher list after security level filtering.
  //
  Ciphers = SSL_get_ciphers (Ssl);
  Count   = (Ciphers != NULL) ? (UINTN)sk_SSL_CIPHER_num (Ciphers) : 0;

  if ((CipherSuites == NULL) || (*CipherCount < Count)) {
    *CipherCount = Count;
    SSL_free (Ssl);
    SSL_CTX_free (Ctx);
    if (CipherSuites == NULL) {
      return EFI_SUCCESS;
    }

    return EFI_BUFFER_TOO_SMALL;
  }

  for (Index = 0; Index < Count; Index++) {
    Cipher              = sk_SSL_CIPHER_value (Ciphers, (int)Index);
    CipherSuites[Index] = (UINT16)SSL_CIPHER_get_protocol_id (Cipher);
  }

  *CipherCount = Count;

  SSL_free (Ssl);
  SSL_CTX_free (Ctx);

  return EFI_SUCCESS;
}
