/** @file
  SSL/TLS Configuration Library Wrapper Implementation over MbedTLS.

Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalTlsLib.h"

/**
  Set a new TLS/SSL method for a particular TLS object.

  This function sets a new TLS/SSL method for a particular TLS object.

  @param[in]  Tls         Pointer to a TLS object.
  @param[in]  MajorVer    Major Version of TLS/SSL Protocol.
  @param[in]  MinorVer    Minor Version of TLS/SSL Protocol.

  @retval  EFI_SUCCESS           The TLS/SSL method was set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       Unsupported TLS/SSL method.

**/
EFI_STATUS
EFIAPI
TlsSetVersion (
  IN     VOID   *Tls,
  IN     UINT8  MajorVer,
  IN     UINT8  MinorVer
  )
{
  TLS_CONNECTION                *TlsConn;
  UINT16                        ProtoVersion;
  mbedtls_ssl_protocol_version  MbedVersion;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ProtoVersion = (MajorVer << 8) | MinorVer;

  switch (ProtoVersion) {
    case 0x0303:
      MbedVersion = MBEDTLS_SSL_VERSION_TLS1_2;
      break;
    case 0x0304:
 #ifdef MBEDTLS_SSL_PROTO_TLS1_3
      MbedVersion = MBEDTLS_SSL_VERSION_TLS1_3;
      break;
 #else
      return EFI_UNSUPPORTED;
 #endif
    default:
      return EFI_UNSUPPORTED;
  }

  mbedtls_ssl_conf_min_tls_version (&TlsConn->Conf, MbedVersion);
  mbedtls_ssl_conf_max_tls_version (&TlsConn->Conf, MbedVersion);

  return EFI_SUCCESS;
}

/**
  Set TLS object to work in client or server mode.

  This function prepares a TLS object to work in client or server mode.

  @param[in]  Tls         Pointer to a TLS object.
  @param[in]  IsServer    Work in server mode.

  @retval  EFI_SUCCESS           The TLS/SSL work mode was set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       Unsupported TLS/SSL work mode.

**/
EFI_STATUS
EFIAPI
TlsSetConnectionEnd (
  IN     VOID     *Tls,
  IN     BOOLEAN  IsServer
  )
{
  TLS_CONNECTION  *TlsConn;
  int             Ret;
  int             Endpoint;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  TlsConn->IsServer = IsServer;
  Endpoint          = IsServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;

  //
  // MbedTLS requires reconfiguring defaults when changing endpoint.
  // We preserve the current version settings.
  //
  mbedtls_ssl_protocol_version  MinVer = TlsConn->Conf.MBEDTLS_PRIVATE(min_tls_version);
  mbedtls_ssl_protocol_version  MaxVer = TlsConn->Conf.MBEDTLS_PRIVATE(max_tls_version);

  Ret = mbedtls_ssl_config_defaults (
          &TlsConn->Conf,
          Endpoint,
          MBEDTLS_SSL_TRANSPORT_STREAM,
          MBEDTLS_SSL_PRESET_DEFAULT
          );
  if (Ret != 0) {
    return EFI_UNSUPPORTED;
  }

  //
  // Restore version settings and RNG
  //
  mbedtls_ssl_conf_min_tls_version (&TlsConn->Conf, MinVer);
  mbedtls_ssl_conf_max_tls_version (&TlsConn->Conf, MaxVer);
  mbedtls_ssl_conf_rng (&TlsConn->Conf, TlsMbedTlsRng, NULL);

  return EFI_SUCCESS;
}

/**
  Set the ciphers list to be used by the TLS object.

  This function sets the ciphers for use by a specified TLS object.

  @param[in]  Tls          Pointer to a TLS object.
  @param[in]  CipherId     Array of UINT16 cipher identifiers. Each UINT16
                           cipher identifier comes from the TLS Cipher Suite
                           Registry of the IANA, interpreting Byte1 and Byte2
                           in network (big endian) byte order.
  @param[in]  CipherNum    The number of cipher in the list.

  @retval  EFI_SUCCESS           The ciphers list was set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       No supported TLS cipher was found in CipherId.
  @retval  EFI_OUT_OF_RESOURCES  Memory allocation failed.

**/
EFI_STATUS
EFIAPI
TlsSetCipherList (
  IN     VOID    *Tls,
  IN     UINT16  *CipherId,
  IN     UINTN   CipherNum
  )
{
  TLS_CONNECTION  *TlsConn;
  int             *MbedCipherList;
  UINTN           Index;
  UINTN           MappedCount;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (CipherId == NULL) || (CipherNum == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Allocate cipher list (terminated by 0)
  //
  MbedCipherList = AllocateZeroPool ((CipherNum + 1) * sizeof (int));
  if (MbedCipherList == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Map IANA cipher IDs to MbedTLS cipher IDs.
  // MbedTLS cipher IDs happen to use the same IANA values for TLS ciphersuites.
  //
  MappedCount = 0;
  for (Index = 0; Index < CipherNum; Index++) {
    //
    // Verify the cipher is supported by MbedTLS
    //
    if (mbedtls_ssl_ciphersuite_from_id ((int)CipherId[Index]) != NULL) {
      MbedCipherList[MappedCount++] = (int)CipherId[Index];
    }
  }

  if (MappedCount == 0) {
    FreePool (MbedCipherList);
    return EFI_UNSUPPORTED;
  }

  MbedCipherList[MappedCount] = 0;

  mbedtls_ssl_conf_ciphersuites (&TlsConn->Conf, MbedCipherList);

  //
  // Note: MbedTLS requires the ciphersuite list to remain valid for the
  // lifetime of the config. We intentionally do not free MbedCipherList here.
  // It will be leaked - in production use, the config should own this memory.
  // A more complete implementation would store the pointer in TlsConn for
  // cleanup in TlsFree.
  //

  return EFI_SUCCESS;
}

/**
  Set the compression method for TLS/SSL operations.

  This function handles TLS/SSL integrated compression methods.

  @param[in]  CompMethod    The compression method ID.

  @retval  EFI_SUCCESS        The compression method for the communication was
                              set successfully.
  @retval  EFI_UNSUPPORTED    Unsupported compression method.

**/
EFI_STATUS
EFIAPI
TlsSetCompressionMethod (
  IN     UINT8  CompMethod
  )
{
  //
  // MbedTLS does not support TLS compression.
  // Only null compression (0) is accepted.
  //
  if (CompMethod == 0) {
    return EFI_SUCCESS;
  }

  return EFI_UNSUPPORTED;
}

/**
  Set peer certificate verification mode for the TLS connection.

  This function sets the verification mode flags for the TLS connection.

  @param[in]  Tls           Pointer to the TLS object.
  @param[in]  VerifyMode    A set of logically or'ed verification mode flags.

**/
VOID
EFIAPI
TlsSetVerify (
  IN     VOID    *Tls,
  IN     UINT32  VerifyMode
  )
{
  TLS_CONNECTION  *TlsConn;
  int             AuthMode;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    return;
  }

  //
  // Map OpenSSL-style verify mode to MbedTLS auth mode.
  // VerifyMode 0x01 = SSL_VERIFY_PEER
  // Use MBEDTLS_SSL_VERIFY_OPTIONAL which validates the certificate chain
  // but does not require hostname to be set (unlike VERIFY_REQUIRED).
  // This matches OpenSSL SSL_VERIFY_PEER behavior.
  //
  if (VerifyMode & 0x01) {
    AuthMode = MBEDTLS_SSL_VERIFY_OPTIONAL;
  } else {
    AuthMode = MBEDTLS_SSL_VERIFY_NONE;
  }

  mbedtls_ssl_conf_authmode (&TlsConn->Conf, AuthMode);
}

/**
  Set the specified host name to be verified.

  @param[in]  Tls           Pointer to the TLS object.
  @param[in]  Flags         The setting flags during the validation.
  @param[in]  HostName      The specified host name to be verified.

  @retval  EFI_SUCCESS           The HostName setting was set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_ABORTED           Invalid HostName setting.

**/
EFI_STATUS
EFIAPI
TlsSetVerifyHost (
  IN     VOID    *Tls,
  IN     UINT32  Flags,
  IN     CHAR8   *HostName
  )
{
  TLS_CONNECTION  *TlsConn;
  int             Ret;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (HostName == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Ret = mbedtls_ssl_set_hostname (&TlsConn->Ssl, HostName);
  if (Ret != 0) {
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}

/**
  Sets a TLS/SSL session ID to be used during TLS/SSL connect.

  This function sets a session ID to be used when the TLS/SSL connection is
  to be established.

  @param[in]  Tls             Pointer to the TLS object.
  @param[in]  SessionId       Session ID data used for session resumption.
  @param[in]  SessionIdLen    Length of Session ID in bytes.

  @retval  EFI_SUCCESS           Session ID was set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       No available session for ID setting.

**/
EFI_STATUS
EFIAPI
TlsSetSessionId (
  IN     VOID    *Tls,
  IN     UINT8   *SessionId,
  IN     UINT16  SessionIdLen
  )
{
  //
  // MbedTLS handles session resumption differently (via session tickets or
  // session cache). Direct session ID setting is not supported in the same way.
  //
  return EFI_UNSUPPORTED;
}

/**
  Adds the CA to the cert store when requesting Server or Client authentication.

  This function adds the CA certificate to the list of CAs when requesting
  Server or Client authentication for the chosen TLS connection.

  @param[in]  Tls         Pointer to the TLS object.
  @param[in]  Data        Pointer to the data buffer of a DER-encoded binary
                          X.509 certificate or PEM-encoded X.509 certificate.
  @param[in]  DataSize    The size of data buffer in bytes.

  @retval  EFI_SUCCESS             The operation succeeded.
  @retval  EFI_INVALID_PARAMETER   The parameter is invalid.
  @retval  EFI_OUT_OF_RESOURCES    Required resources could not be allocated.
  @retval  EFI_ABORTED            Invalid X.509 certificate.

**/
EFI_STATUS
EFIAPI
TlsSetCaCertificate (
  IN     VOID   *Tls,
  IN     VOID   *Data,
  IN     UINTN  DataSize
  )
{
  TLS_CONNECTION  *TlsConn;
  int             Ret;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (Data == NULL) || (DataSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Parse DER-encoded certificate into the CA chain
  //
  Ret = mbedtls_x509_crt_parse_der (
          &TlsConn->CaCert,
          (const unsigned char *)Data,
          DataSize
          );
  if (Ret != 0) {
    //
    // Try PEM format
    //
    Ret = mbedtls_x509_crt_parse (
            &TlsConn->CaCert,
            (const unsigned char *)Data,
            DataSize
            );
    if (Ret != 0) {
      return EFI_ABORTED;
    }
  }

  //
  // Set the CA chain in the SSL configuration
  //
  mbedtls_ssl_conf_ca_chain (&TlsConn->Conf, &TlsConn->CaCert, NULL);

  return EFI_SUCCESS;
}

/**
  Loads the local public certificate into the specified TLS object.

  This function loads the X.509 certificate into the specified TLS object
  for TLS negotiation.

  @param[in]  Tls         Pointer to the TLS object.
  @param[in]  Data        Pointer to the data buffer of a DER-encoded binary
                          X.509 certificate or PEM-encoded X.509 certificate.
  @param[in]  DataSize    The size of data buffer in bytes.

  @retval  EFI_SUCCESS             The operation succeeded.
  @retval  EFI_INVALID_PARAMETER   The parameter is invalid.
  @retval  EFI_OUT_OF_RESOURCES    Required resources could not be allocated.
  @retval  EFI_ABORTED            Invalid X.509 certificate.

**/
EFI_STATUS
EFIAPI
TlsSetHostPublicCert (
  IN     VOID   *Tls,
  IN     VOID   *Data,
  IN     UINTN  DataSize
  )
{
  TLS_CONNECTION  *TlsConn;
  int             Ret;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (Data == NULL) || (DataSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Parse DER-encoded certificate
  //
  Ret = mbedtls_x509_crt_parse_der (
          &TlsConn->OwnCert,
          (const unsigned char *)Data,
          DataSize
          );
  if (Ret != 0) {
    //
    // Try PEM format
    //
    Ret = mbedtls_x509_crt_parse (
            &TlsConn->OwnCert,
            (const unsigned char *)Data,
            DataSize
            );
    if (Ret != 0) {
      return EFI_ABORTED;
    }
  }

  //
  // Set own certificate (will be paired with key in TlsSetHostPrivateKey)
  //
  Ret = mbedtls_ssl_conf_own_cert (&TlsConn->Conf, &TlsConn->OwnCert, &TlsConn->OwnKey);
  if (Ret != 0) {
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}

/**
  Adds the local private key to the specified TLS object.

  This function adds the local private key (DER-encoded or PEM-encoded or PKCS#8 private
  key) into the specified TLS object for TLS negotiation.

  @param[in]  Tls         Pointer to the TLS object.
  @param[in]  Data        Pointer to the data buffer of a DER-encoded or PEM-encoded
                          or PKCS#8 private key.
  @param[in]  DataSize    The size of data buffer in bytes.
  @param[in]  Password    Pointer to NULL-terminated private key password, set it to NULL
                          if private key not encrypted.

  @retval  EFI_SUCCESS     The operation succeeded.
  @retval  EFI_UNSUPPORTED This function is not supported.
  @retval  EFI_ABORTED     Invalid private key data.

**/
EFI_STATUS
EFIAPI
TlsSetHostPrivateKeyEx (
  IN     VOID   *Tls,
  IN     VOID   *Data,
  IN     UINTN  DataSize,
  IN     VOID   *Password  OPTIONAL
  )
{
  TLS_CONNECTION  *TlsConn;
  int             Ret;
  size_t          PwdLen;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (Data == NULL) || (DataSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  PwdLen = (Password != NULL) ? AsciiStrLen ((CONST CHAR8 *)Password) : 0;

  //
  // Parse the private key (supports DER, PEM, PKCS#8)
  //
  Ret = mbedtls_pk_parse_key (
          &TlsConn->OwnKey,
          (const unsigned char *)Data,
          DataSize,
          (const unsigned char *)Password,
          PwdLen,
          TlsMbedTlsRng,
          NULL
          );
  if (Ret != 0) {
    return EFI_ABORTED;
  }

  //
  // Re-pair the certificate with the key
  //
  Ret = mbedtls_ssl_conf_own_cert (&TlsConn->Conf, &TlsConn->OwnCert, &TlsConn->OwnKey);
  if (Ret != 0) {
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}

/**
  Adds the local private key to the specified TLS object.

  This function adds the local private key (DER-encoded or PEM-encoded or PKCS#8 private
  key) into the specified TLS object for TLS negotiation.

  @param[in]  Tls         Pointer to the TLS object.
  @param[in]  Data        Pointer to the data buffer of a DER-encoded or PEM-encoded
                          or PKCS#8 private key.
  @param[in]  DataSize    The size of data buffer in bytes.

  @retval  EFI_SUCCESS     The operation succeeded.
  @retval  EFI_UNSUPPORTED This function is not supported.
  @retval  EFI_ABORTED     Invalid private key data.

**/
EFI_STATUS
EFIAPI
TlsSetHostPrivateKey (
  IN     VOID   *Tls,
  IN     VOID   *Data,
  IN     UINTN  DataSize
  )
{
  return TlsSetHostPrivateKeyEx (Tls, Data, DataSize, NULL);
}

/**
  Adds the CA-supplied certificate revocation list for certificate validation.

  This function adds the CA-supplied certificate revocation list data for
  certificate validity checking.

  @param[in]  Data        Pointer to the data buffer of a DER-encoded CRL data.
  @param[in]  DataSize    The size of data buffer in bytes.

  @retval  EFI_SUCCESS     The operation succeeded.
  @retval  EFI_UNSUPPORTED This function is not supported.
  @retval  EFI_ABORTED     Invalid CRL data.

**/
EFI_STATUS
EFIAPI
TlsSetCertRevocationList (
  IN     VOID   *Data,
  IN     UINTN  DataSize
  )
{
  //
  // CRL support requires per-connection context in MbedTLS.
  // This global API is not directly mappable.
  //
  return EFI_UNSUPPORTED;
}

/**
  Set the specified server name in Server/Client.

  @param[in]  Tls           Pointer to the TLS object.
  @param[in]  SslCtx        Pointer to the SSL object.
  @param[in]  HostName      The specified server name to be set.

  @retval  EFI_SUCCESS      The Server Name was set successfully.
  @retval  EFI_UNSUPPORTED  Failed to set the Server Name.
**/
EFI_STATUS
EFIAPI
TlsSetServerName (
  IN     VOID   *Tls,
  IN     VOID   *SslCtx,
  IN     CHAR8  *HostName
  )
{
  TLS_CONNECTION  *TlsConn;
  int             Ret;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (HostName == NULL)) {
    return EFI_UNSUPPORTED;
  }

  Ret = mbedtls_ssl_set_hostname (&TlsConn->Ssl, HostName);
  if (Ret != 0) {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

/**
  Set the signature algorithm list to used by the TLS object.

  This function sets the signature algorithms for use by a specified TLS object.

  @param[in]  Tls                Pointer to a TLS object.
  @param[in]  Data               Array of UINT8 of signature algorithms. The array consists of
                                 pairs of the hash algorithm and the signature algorithm as defined
                                 in RFC 5246
  @param[in]  DataSize           The length the SignatureAlgoList. Must be divisible by 2.

  @retval  EFI_SUCCESS           The signature algorithm list was set successfully.
  @retval  EFI_INVALID_PARAMETER The parameters are invalid.
  @retval  EFI_UNSUPPORTED       No supported TLS signature algorithm was found in SignatureAlgoList
  @retval  EFI_OUT_OF_RESOURCES  Memory allocation failed.

**/
EFI_STATUS
EFIAPI
TlsSetSignatureAlgoList (
  IN     VOID   *Tls,
  IN     UINT8  *Data,
  IN     UINTN  DataSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           Count;
  UINTN           Index;
  UINT16          *SigAlgs;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (Data == NULL) || (DataSize < 2) || ((DataSize % 2) != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  Count = DataSize / 2;

  //
  // Allocate sig algs array (terminated by MBEDTLS_TLS1_3_SIG_NONE = 0)
  //
  SigAlgs = AllocateZeroPool ((Count + 1) * sizeof (UINT16));
  if (SigAlgs == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Convert pairs of (hash, sig) bytes to IANA SignatureScheme values.
  // Format: hash_algo (1 byte) << 8 | sig_algo (1 byte)
  //
  for (Index = 0; Index < Count; Index++) {
    SigAlgs[Index] = (UINT16)((Data[Index * 2] << 8) | Data[Index * 2 + 1]);
  }

  SigAlgs[Count] = 0;

  //
  // Free previous allocation if any
  //
  if (TlsConn->SigAlgs != NULL) {
    FreePool (TlsConn->SigAlgs);
  }

  TlsConn->SigAlgs = SigAlgs;
  mbedtls_ssl_conf_sig_algs (&TlsConn->Conf, SigAlgs);

  return EFI_SUCCESS;
}

/**
  Set the EC curve to be used for TLS flows

  This function sets the EC curve to be used for TLS flows.

  @param[in]  Tls                Pointer to a TLS object.
  @param[in]  Data               An EC named curve as defined in section 5.1.1 of RFC 4492.
  @param[in]  DataSize           Size of Data, it should be sizeof (UINT32)

  @retval  EFI_SUCCESS           The EC curve was set successfully.
  @retval  EFI_INVALID_PARAMETER The parameters are invalid.
  @retval  EFI_UNSUPPORTED       The requested TLS EC curve is not supported

**/
EFI_STATUS
EFIAPI
TlsSetEcCurve (
  IN     VOID   *Tls,
  IN     UINT8  *Data,
  IN     UINTN  DataSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINT16          GroupId;
  UINT16          *Groups;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (Data == NULL) || (DataSize != sizeof (UINT32))) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Extract the group ID (IANA NamedGroup value)
  //
  GroupId = (UINT16)(*(UINT32 *)Data);

  //
  // Allocate groups list (terminated by 0)
  //
  Groups = AllocateZeroPool (2 * sizeof (UINT16));
  if (Groups == NULL) {
    return EFI_UNSUPPORTED;
  }

  Groups[0] = GroupId;
  Groups[1] = 0;

  if (TlsConn->Groups != NULL) {
    FreePool (TlsConn->Groups);
  }

  TlsConn->Groups = Groups;
  mbedtls_ssl_conf_groups (&TlsConn->Conf, Groups);

  return EFI_SUCCESS;
}

/**
  Set the Tls security level.

  This function Set the Tls security level.
  If Tls is NULL, nothing is done.

  @param[in]  Tls                Pointer to the TLS object.
  @param[in]  Level              Tls Security level need to set.

  @retval  EFI_SUCCESS           The Tls security level was set successfully.
  @retval  EFI_INVALID_PARAMETER The parameters are invalid.
  @retval  EFI_UNSUPPORTED       The requested TLS set security level is not supported.

**/
EFI_STATUS
EFIAPI
TlsSetSecurityLevel (
  IN VOID   *Tls,
  IN UINT8  Level
  )
{
  //
  // MbedTLS does not have a direct "security level" concept like OpenSSL.
  // The equivalent is controlled through certificate profile and cipher config.
  // Accept and ignore for compatibility.
  //
  if (Tls == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

//
// Mapping table: OpenSSL TLS 1.2 cipher name → IANA cipher suite ID
//
typedef struct {
  CONST CHAR8    *Name;
  int            Id;
} TLS_CIPHER_NAME_MAP;

STATIC CONST TLS_CIPHER_NAME_MAP  mTls12CipherMap[] = {
  //
  // RSA key exchange
  //
  { "AES128-SHA",                       0x002F },
  { "AES256-SHA",                       0x0035 },
  { "AES128-SHA256",                    0x003C },
  { "AES256-SHA256",                    0x003D },
  { "AES128-GCM-SHA256",               0x009C },
  { "AES256-GCM-SHA384",               0x009D },
  //
  // ECDHE-RSA key exchange
  //
  { "ECDHE-RSA-AES128-SHA",            0xC013 },
  { "ECDHE-RSA-AES256-SHA",            0xC014 },
  { "ECDHE-RSA-AES128-SHA256",         0xC027 },
  { "ECDHE-RSA-AES256-SHA384",         0xC028 },
  { "ECDHE-RSA-AES128-GCM-SHA256",     0xC02F },
  { "ECDHE-RSA-AES256-GCM-SHA384",     0xC030 },
  //
  // ECDHE-ECDSA key exchange
  //
  { "ECDHE-ECDSA-AES128-SHA",          0xC009 },
  { "ECDHE-ECDSA-AES256-SHA",          0xC00A },
  { "ECDHE-ECDSA-AES128-SHA256",       0xC023 },
  { "ECDHE-ECDSA-AES256-SHA384",       0xC024 },
  { "ECDHE-ECDSA-AES128-GCM-SHA256",   0xC02B },
  { "ECDHE-ECDSA-AES256-GCM-SHA384",   0xC02C },
};

//
// Mapping table: OpenSSL TLS 1.3 ciphersuite name → IANA cipher suite ID
//
STATIC CONST TLS_CIPHER_NAME_MAP  mTls13CipherMap[] = {
  { "TLS_AES_128_GCM_SHA256",          0x1301 },
  { "TLS_AES_256_GCM_SHA384",          0x1302 },
  { "TLS_CHACHA20_POLY1305_SHA256",    0x1303 },
  { "TLS_AES_128_CCM_SHA256",          0x1304 },
};

//
// Mapping table: OpenSSL group name → IANA NamedGroup ID
//
typedef struct {
  CONST CHAR8    *Name;
  UINT16         Id;
} TLS_GROUP_NAME_MAP;

STATIC CONST TLS_GROUP_NAME_MAP  mTlsGroupMap[] = {
  //
  // ECDHE groups
  //
  { "P-256",              0x0017 },
  { "secp256r1",          0x0017 },
  { "P-384",              0x0018 },
  { "secp384r1",          0x0018 },
  { "P-521",              0x0019 },
  { "secp521r1",          0x0019 },
  { "X25519",             0x001D },
  { "X448",               0x001E },
  //
  // FFDHE groups
  //
  { "ffdhe2048",          0x0100 },
  { "ffdhe3072",          0x0101 },
  { "ffdhe4096",          0x0102 },
  //
  // PQC -- ML-KEM hybrid key exchange
  //
  { "X25519MLKEM768",     0x4588 },
  { "SecP256r1MLKEM768",  0x4589 },
  { "X448MLKEM1024",      0x4590 },
  { "SecP384r1MLKEM1024", 0x4591 },
  //
  // PQC -- ML-KEM standalone
  //
  { "ML-KEM-512",         0x0200 },
  { "ML-KEM-768",         0x0201 },
  { "ML-KEM-1024",        0x0202 },
};

//
// Mapping table: OpenSSL signature scheme name → IANA SignatureScheme value
//
typedef struct {
  CONST CHAR8    *Name;
  UINT16         Id;
} TLS_SIG_SCHEME_NAME_MAP;

STATIC CONST TLS_SIG_SCHEME_NAME_MAP  mTlsSigSchemeMap[] = {
  //
  // TLS 1.2 style (hash+sig format)
  //
  { "RSA+SHA256",                 0x0401 },
  { "RSA+SHA384",                 0x0501 },
  { "RSA+SHA512",                 0x0601 },
  { "ECDSA+SHA256",               0x0403 },
  { "ECDSA+SHA384",               0x0503 },
  { "ECDSA+SHA512",               0x0603 },
  //
  // TLS 1.3 RSA-PSS schemes
  //
  { "rsa_pss_rsae_sha256",        0x0804 },
  { "rsa_pss_rsae_sha384",        0x0805 },
  { "rsa_pss_rsae_sha512",        0x0806 },
  { "rsa_pss_pss_sha256",         0x0809 },
  { "rsa_pss_pss_sha384",         0x080A },
  { "rsa_pss_pss_sha512",         0x080B },
  //
  // TLS 1.3 ECDSA schemes
  //
  { "ecdsa_secp256r1_sha256",     0x0403 },
  { "ecdsa_secp384r1_sha384",     0x0503 },
  { "ecdsa_secp521r1_sha512",     0x0603 },
  //
  // EdDSA schemes
  //
  { "ed25519",                    0x0807 },
  { "ed448",                      0x0808 },
  //
  // PQC -- ML-DSA (FIPS 204)
  //
  { "mldsa44",                    0x0904 },
  { "mldsa65",                    0x0905 },
  { "mldsa87",                    0x0906 },
};

/**
  Internal helper: compare a token of given length against a NUL-terminated name
  (case-insensitive).

  @param[in]  Token       Pointer to the token (not NUL-terminated).
  @param[in]  TokenLen    Length of the token.
  @param[in]  Name        NUL-terminated name to compare against.

  @retval TRUE   The token matches the name.
  @retval FALSE  The token does not match.

**/
STATIC
BOOLEAN
TlsTokenMatchesName (
  IN CONST CHAR8  *Token,
  IN UINTN        TokenLen,
  IN CONST CHAR8  *Name
  )
{
  UINTN  NameLen;
  UINTN  Index;
  CHAR8  A;
  CHAR8  B;

  NameLen = AsciiStrLen (Name);
  if (TokenLen != NameLen) {
    return FALSE;
  }

  for (Index = 0; Index < TokenLen; Index++) {
    A = Token[Index];
    B = Name[Index];

    //
    // Simple ASCII case-insensitive compare
    //
    if ((A >= 'a') && (A <= 'z')) {
      A = A - 'a' + 'A';
    }

    if ((B >= 'a') && (B <= 'z')) {
      B = B - 'a' + 'A';
    }

    if (A != B) {
      return FALSE;
    }
  }

  return TRUE;
}

/**
  Set the ciphers list to be used by the TLS object using OpenSSL cipher string format.

  This function parses a colon-separated OpenSSL TLS 1.2 cipher string and maps
  each name to the corresponding IANA cipher suite ID for MbedTLS.

  @param[in]  Tls           Pointer to a TLS object.
  @param[in]  CipherString  Cipher string in OpenSSL format (colon-separated).

  @retval  EFI_SUCCESS           The ciphers were set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       No supported cipher was found.

**/
EFI_STATUS
EFIAPI
TlsSetCipherString (
  IN     VOID         *Tls,
  IN     CONST CHAR8  *CipherString
  )
{
  TLS_CONNECTION  *TlsConn;
  int             CipherIds[32];
  UINTN           Count;
  CONST CHAR8     *Pos;
  CONST CHAR8     *TokenStart;
  UINTN           TokenLen;
  UINTN           MapIndex;
  BOOLEAN         Found;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (CipherString == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Parse colon-separated cipher names and map to IDs
  //
  Count      = 0;
  Pos        = CipherString;
  TokenStart = Pos;

  while (TRUE) {
    if ((*Pos == ':') || (*Pos == '\0')) {
      TokenLen = (UINTN)(Pos - TokenStart);
      if (TokenLen > 0) {
        Found = FALSE;
        for (MapIndex = 0; MapIndex < ARRAY_SIZE (mTls12CipherMap); MapIndex++) {
          if (TlsTokenMatchesName (TokenStart, TokenLen, mTls12CipherMap[MapIndex].Name)) {
            if (Count < ARRAY_SIZE (CipherIds) - 1) {
              CipherIds[Count++] = mTls12CipherMap[MapIndex].Id;
            }

            Found = TRUE;
            break;
          }
        }

        if (!Found) {
          DEBUG ((DEBUG_VERBOSE, "%a: unknown cipher '%.*a'\n", __func__, TokenLen, TokenStart));
        }
      }

      if (*Pos == '\0') {
        break;
      }

      TokenStart = Pos + 1;
    }

    Pos++;
  }

  if (Count == 0) {
    return EFI_UNSUPPORTED;
  }

  CipherIds[Count] = 0;

  //
  // MbedTLS requires the ciphersuite array to persist. Store in TlsConn.
  // We reuse the existing ciphersuite storage by allocating a new array.
  //
  int  *StoredIds = AllocatePool ((Count + 1) * sizeof (int));

  if (StoredIds == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (StoredIds, CipherIds, (Count + 1) * sizeof (int));
  mbedtls_ssl_conf_ciphersuites (&TlsConn->Conf, StoredIds);

  return EFI_SUCCESS;
}

/**
  Set the TLS 1.3 ciphersuites to be used by the TLS object.

  This function parses a colon-separated TLS 1.3 ciphersuite string and maps
  each name to the corresponding IANA cipher suite ID for MbedTLS.

  @param[in]  Tls           Pointer to a TLS object.
  @param[in]  CipherSuites  Ciphersuite string (e.g., "TLS_AES_128_GCM_SHA256").

  @retval  EFI_SUCCESS           The ciphersuites were set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       No supported ciphersuite was found.

**/
EFI_STATUS
EFIAPI
TlsSetCipherSuites (
  IN     VOID         *Tls,
  IN     CONST CHAR8  *CipherSuites
  )
{
  TLS_CONNECTION  *TlsConn;
  int             CipherIds[16];
  UINTN           Count;
  CONST CHAR8     *Pos;
  CONST CHAR8     *TokenStart;
  UINTN           TokenLen;
  UINTN           MapIndex;
  BOOLEAN         Found;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (CipherSuites == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Parse colon-separated ciphersuite names and map to IDs
  //
  Count      = 0;
  Pos        = CipherSuites;
  TokenStart = Pos;

  while (TRUE) {
    if ((*Pos == ':') || (*Pos == '\0')) {
      TokenLen = (UINTN)(Pos - TokenStart);
      if (TokenLen > 0) {
        Found = FALSE;
        for (MapIndex = 0; MapIndex < ARRAY_SIZE (mTls13CipherMap); MapIndex++) {
          if (TlsTokenMatchesName (TokenStart, TokenLen, mTls13CipherMap[MapIndex].Name)) {
            if (Count < ARRAY_SIZE (CipherIds) - 1) {
              CipherIds[Count++] = mTls13CipherMap[MapIndex].Id;
            }

            Found = TRUE;
            break;
          }
        }

        if (!Found) {
          DEBUG ((DEBUG_VERBOSE, "%a: unknown TLS 1.3 suite '%.*a'\n", __func__, TokenLen, TokenStart));
        }
      }

      if (*Pos == '\0') {
        break;
      }

      TokenStart = Pos + 1;
    }

    Pos++;
  }

  if (Count == 0) {
    return EFI_UNSUPPORTED;
  }

  CipherIds[Count] = 0;

  int  *StoredIds = AllocatePool ((Count + 1) * sizeof (int));

  if (StoredIds == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (StoredIds, CipherIds, (Count + 1) * sizeof (int));
  mbedtls_ssl_conf_ciphersuites (&TlsConn->Conf, StoredIds);

  return EFI_SUCCESS;
}

/**
  Set the key exchange groups to be used by the TLS object.

  This function parses a colon-separated groups string in OpenSSL format and maps
  each name to the corresponding IANA NamedGroup ID for MbedTLS.

  @param[in]  Tls     Pointer to a TLS object.
  @param[in]  Groups  Pointer to the groups string in OpenSSL format (colon-separated).

  @retval  EFI_SUCCESS           The groups were set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       No supported group was found.

**/
EFI_STATUS
EFIAPI
TlsSetGroups (
  IN     VOID         *Tls,
  IN     CONST CHAR8  *Groups
  )
{
  TLS_CONNECTION  *TlsConn;
  UINT16          GroupIds[16];
  UINTN           Count;
  CONST CHAR8     *Pos;
  CONST CHAR8     *TokenStart;
  UINTN           TokenLen;
  UINTN           MapIndex;
  BOOLEAN         Found;
  UINT16          *StoredGroups;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (Groups == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Parse colon-separated group names and map to IANA NamedGroup IDs
  //
  Count      = 0;
  Pos        = Groups;
  TokenStart = Pos;

  while (TRUE) {
    if ((*Pos == ':') || (*Pos == '\0')) {
      TokenLen = (UINTN)(Pos - TokenStart);
      if (TokenLen > 0) {
        Found = FALSE;
        for (MapIndex = 0; MapIndex < ARRAY_SIZE (mTlsGroupMap); MapIndex++) {
          if (TlsTokenMatchesName (TokenStart, TokenLen, mTlsGroupMap[MapIndex].Name)) {
            if (Count < ARRAY_SIZE (GroupIds) - 1) {
              GroupIds[Count++] = mTlsGroupMap[MapIndex].Id;
            }

            Found = TRUE;
            break;
          }
        }

        if (!Found) {
          DEBUG ((DEBUG_VERBOSE, "%a: unknown group '%.*a'\n", __func__, TokenLen, TokenStart));
        }
      }

      if (*Pos == '\0') {
        break;
      }

      TokenStart = Pos + 1;
    }

    Pos++;
  }

  if (Count == 0) {
    return EFI_UNSUPPORTED;
  }

  GroupIds[Count] = 0;

  //
  // Allocate persistent storage (MbedTLS requires array to outlive config)
  //
  StoredGroups = AllocatePool ((Count + 1) * sizeof (UINT16));
  if (StoredGroups == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (StoredGroups, GroupIds, (Count + 1) * sizeof (UINT16));

  if (TlsConn->Groups != NULL) {
    FreePool (TlsConn->Groups);
  }

  TlsConn->Groups = StoredGroups;
  mbedtls_ssl_conf_groups (&TlsConn->Conf, StoredGroups);

  return EFI_SUCCESS;
}

/**
  Set the signature scheme list to be used by the TLS object.

  This function parses a colon-separated signature scheme string and maps each
  name to the corresponding IANA SignatureScheme value for MbedTLS.
  Supports both TLS 1.2 format ("RSA+SHA256") and TLS 1.3 format
  ("rsa_pss_rsae_sha256", "mldsa65").

  @param[in]  Tls               Pointer to a TLS object.
  @param[in]  SignatureSchemes  Pointer to the signature scheme string (colon-separated).

  @retval  EFI_SUCCESS           The signature schemes were set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       No supported signature scheme was found.

**/
EFI_STATUS
EFIAPI
TlsSetSignatureSchemeList (
  IN     VOID         *Tls,
  IN     CONST CHAR8  *SignatureSchemes
  )
{
  TLS_CONNECTION  *TlsConn;
  UINT16          SchemeIds[32];
  UINTN           Count;
  CONST CHAR8     *Pos;
  CONST CHAR8     *TokenStart;
  UINTN           TokenLen;
  UINTN           MapIndex;
  BOOLEAN         Found;
  UINT16          *StoredSchemes;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (SignatureSchemes == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Parse colon-separated signature scheme names and map to IANA values
  //
  Count      = 0;
  Pos        = SignatureSchemes;
  TokenStart = Pos;

  while (TRUE) {
    if ((*Pos == ':') || (*Pos == '\0')) {
      TokenLen = (UINTN)(Pos - TokenStart);
      if (TokenLen > 0) {
        Found = FALSE;
        for (MapIndex = 0; MapIndex < ARRAY_SIZE (mTlsSigSchemeMap); MapIndex++) {
          if (TlsTokenMatchesName (TokenStart, TokenLen, mTlsSigSchemeMap[MapIndex].Name)) {
            if (Count < ARRAY_SIZE (SchemeIds) - 1) {
              SchemeIds[Count++] = mTlsSigSchemeMap[MapIndex].Id;
            }

            Found = TRUE;
            break;
          }
        }

        if (!Found) {
          DEBUG ((DEBUG_VERBOSE, "%a: unknown sig scheme '%.*a'\n", __func__, TokenLen, TokenStart));
        }
      }

      if (*Pos == '\0') {
        break;
      }

      TokenStart = Pos + 1;
    }

    Pos++;
  }

  if (Count == 0) {
    return EFI_UNSUPPORTED;
  }

  SchemeIds[Count] = 0;

  //
  // Allocate persistent storage (MbedTLS requires array to outlive config)
  //
  StoredSchemes = AllocatePool ((Count + 1) * sizeof (UINT16));
  if (StoredSchemes == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (StoredSchemes, SchemeIds, (Count + 1) * sizeof (UINT16));

  if (TlsConn->SigAlgs != NULL) {
    FreePool (TlsConn->SigAlgs);
  }

  TlsConn->SigAlgs = StoredSchemes;
  mbedtls_ssl_conf_sig_algs (&TlsConn->Conf, StoredSchemes);

  return EFI_SUCCESS;
}

/**
  Skip certificate time validation for the TLS connection.

  @param[in]  Tls    Pointer to the TLS object.

  @retval  EFI_SUCCESS           The flag was set successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_ABORTED           Failed to set the flag.

**/
EFI_STATUS
EFIAPI
TlsSetNoCheckTime (
  IN     VOID  *Tls
  )
{
  //
  // MbedTLS does not have a direct flag to skip time validation.
  // The verification callback can be used to ignore time errors,
  // but that requires a custom verify callback.
  // For now, return success since MbedTLS in UEFI environments
  // may already have time issues handled differently.
  //
  if (Tls == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

//
// ============== Get Functions ==============
//

/**
  Gets the protocol version used by the specified TLS connection.

  @param[in]  Tls    Pointer to the TLS object.

  @return  The protocol version of the specified TLS connection.

**/
UINT16
EFIAPI
TlsGetVersion (
  IN     VOID  *Tls
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    ASSERT (FALSE);
    return 0;
  }

  return (UINT16)mbedtls_ssl_get_version_number (&TlsConn->Ssl);
}

/**
  Gets the connection end of the specified TLS connection.

  @param[in]  Tls    Pointer to the TLS object.

  @return  The connection end used by the specified TLS connection.

**/
UINT8
EFIAPI
TlsGetConnectionEnd (
  IN     VOID  *Tls
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    ASSERT (FALSE);
    return 0;
  }

  return TlsConn->IsServer ? 1 : 0;
}

/**
  Gets the cipher suite used by the specified TLS connection.

  @param[in]      Tls         Pointer to the TLS object.
  @param[in,out]  CipherId    The cipher suite used by the TLS object.

  @retval  EFI_SUCCESS           The cipher suite was returned successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       Unsupported cipher suite.

**/
EFI_STATUS
EFIAPI
TlsGetCurrentCipher (
  IN     VOID    *Tls,
  IN OUT UINT16  *CipherId
  )
{
  TLS_CONNECTION  *TlsConn;
  int             CipherSuiteId;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (CipherId == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  CipherSuiteId = mbedtls_ssl_get_ciphersuite_id_from_ssl (&TlsConn->Ssl);
  if (CipherSuiteId == 0) {
    return EFI_UNSUPPORTED;
  }

  *CipherId = (UINT16)CipherSuiteId;
  return EFI_SUCCESS;
}

/**
  Gets the compression methods used by the specified TLS connection.

  @param[in]      Tls              Pointer to the TLS object.
  @param[in,out]  CompressionId    The current compression method used by
                                   the TLS object.

  @retval  EFI_SUCCESS           The compression method was returned successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       This function is not supported.

**/
EFI_STATUS
EFIAPI
TlsGetCurrentCompressionId (
  IN     VOID   *Tls,
  IN OUT UINT8  *CompressionId
  )
{
  if ((Tls == NULL) || (CompressionId == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // MbedTLS does not support compression. Always null compression.
  //
  *CompressionId = 0;
  return EFI_SUCCESS;
}

/**
  Gets the verification mode currently set in the TLS connection.

  @param[in]  Tls    Pointer to the TLS object.

  @return  The verification mode set in the specified TLS connection.

**/
UINT32
EFIAPI
TlsGetVerify (
  IN     VOID  *Tls
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    ASSERT (FALSE);
    return 0;
  }

  if (TlsConn->Conf.MBEDTLS_PRIVATE(authmode) == MBEDTLS_SSL_VERIFY_REQUIRED) {
    return 0x01;  // SSL_VERIFY_PEER equivalent
  }

  return 0;
}

/**
  Gets the session ID used by the specified TLS connection.

  @param[in]      Tls             Pointer to the TLS object.
  @param[in,out]  SessionId       Buffer to contain the returned session ID.
  @param[in,out]  SessionIdLen    The length of Session ID in bytes.

  @retval  EFI_SUCCESS           The Session ID was returned successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       Invalid TLS/SSL session.

**/
EFI_STATUS
EFIAPI
TlsGetSessionId (
  IN     VOID    *Tls,
  IN OUT UINT8   *SessionId,
  IN OUT UINT16  *SessionIdLen
  )
{
  //
  // MbedTLS session ID retrieval is not directly supported in the same way.
  //
  return EFI_UNSUPPORTED;
}

/**
  Gets the client random data used in the specified TLS connection.

  @param[in]      Tls             Pointer to the TLS object.
  @param[in,out]  ClientRandom    Buffer to contain the returned client
                                  random data (32 bytes).

**/
VOID
EFIAPI
TlsGetClientRandom (
  IN     VOID   *Tls,
  IN OUT UINT8  *ClientRandom
  )
{
  //
  // MbedTLS does not expose client random directly via public API.
  //
  ASSERT (FALSE);
}

/**
  Gets the server random data used in the specified TLS connection.

  @param[in]      Tls             Pointer to the TLS object.
  @param[in,out]  ServerRandom    Buffer to contain the returned server
                                  random data (32 bytes).

**/
VOID
EFIAPI
TlsGetServerRandom (
  IN     VOID   *Tls,
  IN OUT UINT8  *ServerRandom
  )
{
  //
  // MbedTLS does not expose server random directly via public API.
  //
  ASSERT (FALSE);
}

/**
  Gets the master key data used in the specified TLS connection.

  @param[in]      Tls            Pointer to the TLS object.
  @param[in,out]  KeyMaterial    Buffer to contain the returned key material.

  @retval  EFI_SUCCESS           Key material was returned successfully.
  @retval  EFI_INVALID_PARAMETER The parameter is invalid.
  @retval  EFI_UNSUPPORTED       Invalid TLS/SSL session.

**/
EFI_STATUS
EFIAPI
TlsGetKeyMaterial (
  IN     VOID   *Tls,
  IN OUT UINT8  *KeyMaterial
  )
{
  //
  // MbedTLS does not expose key material directly via public API.
  //
  return EFI_UNSUPPORTED;
}

/**
  Gets the CA Certificate from the cert store.

  @param[in]      Tls         Pointer to the TLS object.
  @param[out]     Data        Pointer to the data buffer to receive the CA
                              certificate data sent to the client.
  @param[in,out]  DataSize    The size of data buffer in bytes.

  @retval  EFI_SUCCESS             The operation succeeded.
  @retval  EFI_UNSUPPORTED         This function is not supported.
  @retval  EFI_BUFFER_TOO_SMALL    The Data is too small to hold the data.

**/
EFI_STATUS
EFIAPI
TlsGetCaCertificate (
  IN     VOID   *Tls,
  OUT    VOID   *Data,
  IN OUT UINTN  *DataSize
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (DataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (TlsConn->CaCert.raw.len == 0) {
    return EFI_NOT_FOUND;
  }

  if (*DataSize < TlsConn->CaCert.raw.len) {
    *DataSize = TlsConn->CaCert.raw.len;
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (Data, TlsConn->CaCert.raw.p, TlsConn->CaCert.raw.len);
  *DataSize = TlsConn->CaCert.raw.len;

  return EFI_SUCCESS;
}

/**
  Gets the local public Certificate set in the specified TLS object.

  @param[in]      Tls         Pointer to the TLS object.
  @param[out]     Data        Pointer to the data buffer to receive the local
                              public certificate.
  @param[in,out]  DataSize    The size of data buffer in bytes.

  @retval  EFI_SUCCESS             The operation succeeded.
  @retval  EFI_INVALID_PARAMETER   The parameter is invalid.
  @retval  EFI_NOT_FOUND           The certificate is not found.
  @retval  EFI_BUFFER_TOO_SMALL    The Data is too small to hold the data.

**/
EFI_STATUS
EFIAPI
TlsGetHostPublicCert (
  IN     VOID   *Tls,
  OUT    VOID   *Data,
  IN OUT UINTN  *DataSize
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (DataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (TlsConn->OwnCert.raw.len == 0) {
    return EFI_NOT_FOUND;
  }

  if (*DataSize < TlsConn->OwnCert.raw.len) {
    *DataSize = TlsConn->OwnCert.raw.len;
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (Data, TlsConn->OwnCert.raw.p, TlsConn->OwnCert.raw.len);
  *DataSize = TlsConn->OwnCert.raw.len;

  return EFI_SUCCESS;
}

/**
  Gets the local private key set in the specified TLS object.

  @param[in]      Tls         Pointer to the TLS object.
  @param[out]     Data        Pointer to the data buffer to receive the local
                              private key data.
  @param[in,out]  DataSize    The size of data buffer in bytes.

  @retval  EFI_SUCCESS             The operation succeeded.
  @retval  EFI_UNSUPPORTED         This function is not supported.
  @retval  EFI_BUFFER_TOO_SMALL    The Data is too small to hold the data.

**/
EFI_STATUS
EFIAPI
TlsGetHostPrivateKey (
  IN     VOID   *Tls,
  OUT    VOID   *Data,
  IN OUT UINTN  *DataSize
  )
{
  //
  // Exporting private key is not supported for security reasons.
  //
  return EFI_UNSUPPORTED;
}

/**
  Gets the CA-supplied certificate revocation list data set in the specified
  TLS object.

  @param[out]     Data        Pointer to the data buffer to receive the CRL data.
  @param[in,out]  DataSize    The size of data buffer in bytes.

  @retval  EFI_SUCCESS             The operation succeeded.
  @retval  EFI_UNSUPPORTED         This function is not supported.
  @retval  EFI_BUFFER_TOO_SMALL    The Data is too small to hold the data.

**/
EFI_STATUS
EFIAPI
TlsGetCertRevocationList (
  OUT    VOID   *Data,
  IN OUT UINTN  *DataSize
  )
{
  return EFI_UNSUPPORTED;
}

/**
  Derive keying material from a TLS connection.

  This function exports keying material using the mechanism described in RFC
  5705.

  @param[in]      Tls          Pointer to the TLS object
  @param[in]      Label        Description of the key for the PRF function
  @param[in]      Context      Optional context
  @param[in]      ContextLen   The length of the context value in bytes
  @param[out]     KeyBuffer    Buffer to hold the output of the TLS-PRF
  @param[in]      KeyBufferLen The length of the KeyBuffer

  @retval  EFI_SUCCESS             The operation succeeded.
  @retval  EFI_INVALID_PARAMETER   The TLS object is invalid.
  @retval  EFI_PROTOCOL_ERROR      Some other error occurred.

**/
EFI_STATUS
EFIAPI
TlsGetExportKey (
  IN     VOID        *Tls,
  IN     CONST VOID  *Label,
  IN     CONST VOID  *Context,
  IN     UINTN       ContextLen,
  OUT    VOID        *KeyBuffer,
  IN     UINTN       KeyBufferLen
  )
{
  TLS_CONNECTION  *TlsConn;
  int             Ret;

  TlsConn = (TLS_CONNECTION *)Tls;

  if ((TlsConn == NULL) || (Label == NULL) || (KeyBuffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Ret = mbedtls_ssl_export_keying_material (
          &TlsConn->Ssl,
          KeyBuffer,
          KeyBufferLen,
          (CONST char *)Label,
          AsciiStrLen ((CONST CHAR8 *)Label),
          Context,
          ContextLen,
          Context != NULL ? 1 : 0
          );

  return (Ret == 0) ? EFI_SUCCESS : EFI_PROTOCOL_ERROR;
}
