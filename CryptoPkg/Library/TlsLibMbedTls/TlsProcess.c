/** @file
  SSL/TLS Process Library Wrapper Implementation over MbedTLS.
  The process includes the TLS handshake and packet I/O.

Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalTlsLib.h"

/**
  Checks if the TLS handshake was done.

  This function will check if the specified TLS handshake was done.

  @param[in]  Tls    Pointer to the TLS object for handshake state checking.

  @retval  TRUE     The TLS handshake was done.
  @retval  FALSE    The TLS handshake was not done.

**/
BOOLEAN
EFIAPI
TlsInHandshake (
  IN     VOID  *Tls
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    return FALSE;
  }

  //
  // MbedTLS state MBEDTLS_SSL_HANDSHAKE_OVER means handshake is complete.
  //
  return (TlsConn->Ssl.MBEDTLS_PRIVATE(state) != MBEDTLS_SSL_HANDSHAKE_OVER);
}

/**
  Perform a TLS/SSL handshake.

  This function will perform a TLS/SSL handshake.

  @param[in]       Tls            Pointer to the TLS object for handshake operation.
  @param[in]       BufferIn       Pointer to the most recently received TLS Handshake packet.
  @param[in]       BufferInSize   Packet size in bytes for the most recently received TLS
                                  Handshake packet.
  @param[out]      BufferOut      Pointer to the buffer to hold the built packet.
  @param[in, out]  BufferOutSize  Pointer to the buffer size in bytes. On input, it is
                                  the buffer size provided by the caller. On output, it
                                  is the buffer size in fact needed to contain the
                                  packet.

  @retval EFI_SUCCESS             The required TLS packet is built successfully.
  @retval EFI_INVALID_PARAMETER   One or more of the following conditions is TRUE:
                                  Tls is NULL.
                                  BufferIn is NULL but BufferInSize is NOT 0.
                                  BufferInSize is 0 but BufferIn is NOT NULL.
                                  BufferOutSize is NULL.
                                  BufferOut is NULL if *BufferOutSize is not zero.
  @retval EFI_BUFFER_TOO_SMALL    BufferOutSize is too small to hold the response packet.
  @retval EFI_ABORTED             Something wrong during handshake.

**/
EFI_STATUS
EFIAPI
TlsDoHandshake (
  IN     VOID   *Tls,
  IN     UINT8  *BufferIn  OPTIONAL,
  IN     UINTN  BufferInSize  OPTIONAL,
  OUT UINT8     *BufferOut  OPTIONAL,
  IN OUT UINTN  *BufferOutSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           PendingBufferSize;
  int             Ret;

  TlsConn           = (TLS_CONNECTION *)Tls;
  PendingBufferSize = 0;

  if ((TlsConn == NULL) ||
      (BufferOutSize == NULL) ||
      ((BufferIn == NULL) && (BufferInSize != 0)) ||
      ((BufferIn != NULL) && (BufferInSize == 0)) ||
      ((BufferOut == NULL) && (*BufferOutSize != 0)))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // If there's incoming data, feed it into the input buffer
  //
  if ((BufferIn != NULL) && (BufferInSize > 0)) {
    if (TlsConn->InBufEnd + BufferInSize > TlsConn->InBufSize) {
      //
      // Compact buffer first
      //
      if (TlsConn->InBufStart > 0) {
        CopyMem (
          TlsConn->InBuf,
          TlsConn->InBuf + TlsConn->InBufStart,
          TlsConn->InBufEnd - TlsConn->InBufStart
          );
        TlsConn->InBufEnd  -= TlsConn->InBufStart;
        TlsConn->InBufStart = 0;
      }

      if (TlsConn->InBufEnd + BufferInSize > TlsConn->InBufSize) {
        return EFI_BUFFER_TOO_SMALL;
      }
    }

    CopyMem (TlsConn->InBuf + TlsConn->InBufEnd, BufferIn, BufferInSize);
    TlsConn->InBufEnd += BufferInSize;
  }

  //
  // Reset output buffer position for new output
  //
  TlsConn->OutBufStart = 0;
  TlsConn->OutBufEnd   = 0;

  //
  // Perform one step of the handshake
  //
  Ret = mbedtls_ssl_handshake (&TlsConn->Ssl);

  if ((Ret != 0) &&
      (Ret != MBEDTLS_ERR_SSL_WANT_READ) &&
      (Ret != MBEDTLS_ERR_SSL_WANT_WRITE))
  {
    DEBUG ((
      DEBUG_ERROR,
      "%a: mbedtls_ssl_handshake returned -0x%x\n",
      __func__,
      (unsigned int)-Ret
      ));
    //
    // Still return any output data (e.g., Alert messages)
    //
    PendingBufferSize = TlsConn->OutBufEnd - TlsConn->OutBufStart;
    if (PendingBufferSize > 0) {
      if (PendingBufferSize > *BufferOutSize) {
        *BufferOutSize = PendingBufferSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      CopyMem (BufferOut, TlsConn->OutBuf + TlsConn->OutBufStart, PendingBufferSize);
      *BufferOutSize       = PendingBufferSize;
      TlsConn->OutBufStart = 0;
      TlsConn->OutBufEnd   = 0;
    } else {
      *BufferOutSize = 0;
    }

    return EFI_ABORTED;
  }

  //
  // Get pending output data
  //
  PendingBufferSize = TlsConn->OutBufEnd - TlsConn->OutBufStart;

  if (PendingBufferSize > *BufferOutSize) {
    *BufferOutSize = PendingBufferSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  if (PendingBufferSize > 0) {
    CopyMem (BufferOut, TlsConn->OutBuf + TlsConn->OutBufStart, PendingBufferSize);
    *BufferOutSize       = PendingBufferSize;
    TlsConn->OutBufStart = 0;
    TlsConn->OutBufEnd   = 0;
  } else {
    *BufferOutSize = 0;
  }

  return EFI_SUCCESS;
}

/**
  Handle Alert message recorded in BufferIn. If BufferIn is NULL and BufferInSize is zero,
  TLS session has errors and the response packet needs to be Alert message based on error type.

  @param[in]       Tls            Pointer to the TLS object for state checking.
  @param[in]       BufferIn       Pointer to the most recently received TLS Alert packet.
  @param[in]       BufferInSize   Packet size in bytes for the most recently received TLS
                                  Alert packet.
  @param[out]      BufferOut      Pointer to the buffer to hold the built packet.
  @param[in, out]  BufferOutSize  Pointer to the buffer size in bytes. On input, it is
                                  the buffer size provided by the caller. On output, it
                                  is the buffer size in fact needed to contain the
                                  packet.

  @retval EFI_SUCCESS             The required TLS packet is built successfully.
  @retval EFI_INVALID_PARAMETER   One or more of the following conditions is TRUE:
                                  Tls is NULL.
                                  BufferIn is NULL but BufferInSize is NOT 0.
                                  BufferInSize is 0 but BufferIn is NOT NULL.
                                  BufferOutSize is NULL.
                                  BufferOut is NULL if *BufferOutSize is not zero.
  @retval EFI_ABORTED             An error occurred.
  @retval EFI_BUFFER_TOO_SMALL    BufferOutSize is too small to hold the response packet.

**/
EFI_STATUS
EFIAPI
TlsHandleAlert (
  IN     VOID   *Tls,
  IN     UINT8  *BufferIn  OPTIONAL,
  IN     UINTN  BufferInSize  OPTIONAL,
  OUT UINT8     *BufferOut  OPTIONAL,
  IN OUT UINTN  *BufferOutSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           PendingBufferSize;

  TlsConn = (TLS_CONNECTION *)Tls;

  if ((TlsConn == NULL) ||
      (BufferOutSize == NULL) ||
      ((BufferIn == NULL) && (BufferInSize != 0)) ||
      ((BufferIn != NULL) && (BufferInSize == 0)) ||
      ((BufferOut == NULL) && (*BufferOutSize != 0)))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Feed incoming alert data if provided
  //
  if ((BufferIn != NULL) && (BufferInSize > 0)) {
    if (TlsConn->InBufEnd + BufferInSize <= TlsConn->InBufSize) {
      CopyMem (TlsConn->InBuf + TlsConn->InBufEnd, BufferIn, BufferInSize);
      TlsConn->InBufEnd += BufferInSize;
    }

    //
    // Reset output
    //
    TlsConn->OutBufStart = 0;
    TlsConn->OutBufEnd   = 0;

    //
    // Attempt to read which will process the alert
    //
    UINT8  TempBuf[256];
    mbedtls_ssl_read (&TlsConn->Ssl, TempBuf, sizeof (TempBuf));
  }

  //
  // Get any output data (alert response)
  //
  PendingBufferSize = TlsConn->OutBufEnd - TlsConn->OutBufStart;

  if (PendingBufferSize > *BufferOutSize) {
    *BufferOutSize = PendingBufferSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  if (PendingBufferSize > 0) {
    CopyMem (BufferOut, TlsConn->OutBuf + TlsConn->OutBufStart, PendingBufferSize);
    *BufferOutSize       = PendingBufferSize;
    TlsConn->OutBufStart = 0;
    TlsConn->OutBufEnd   = 0;
  } else {
    *BufferOutSize = 0;
  }

  return EFI_SUCCESS;
}

/**
  Build the CloseNotify packet.

  @param[in]       Tls            Pointer to the TLS object for state checking.
  @param[in, out]  Buffer         Pointer to the buffer to hold the built packet.
  @param[in, out]  BufferSize     Pointer to the buffer size in bytes. On input, it is
                                  the buffer size provided by the caller. On output, it
                                  is the buffer size in fact needed to contain the
                                  packet.

  @retval EFI_SUCCESS             The required TLS packet is built successfully.
  @retval EFI_INVALID_PARAMETER   One or more of the following conditions is TRUE:
                                  Tls is NULL.
                                  BufferSize is NULL.
                                  Buffer is NULL if *BufferSize is not zero.
  @retval EFI_BUFFER_TOO_SMALL    BufferSize is too small to hold the response packet.

**/
EFI_STATUS
EFIAPI
TlsCloseNotify (
  IN     VOID   *Tls,
  IN OUT UINT8  *Buffer,
  IN OUT UINTN  *BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           PendingBufferSize;

  TlsConn = (TLS_CONNECTION *)Tls;

  if ((TlsConn == NULL) ||
      (BufferSize == NULL) ||
      ((Buffer == NULL) && (*BufferSize != 0)))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Reset output buffer
  //
  TlsConn->OutBufStart = 0;
  TlsConn->OutBufEnd   = 0;

  //
  // Send close_notify alert
  //
  mbedtls_ssl_close_notify (&TlsConn->Ssl);

  PendingBufferSize = TlsConn->OutBufEnd - TlsConn->OutBufStart;

  if (PendingBufferSize > *BufferSize) {
    *BufferSize = PendingBufferSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  if (PendingBufferSize > 0) {
    CopyMem (Buffer, TlsConn->OutBuf + TlsConn->OutBufStart, PendingBufferSize);
    *BufferSize          = PendingBufferSize;
    TlsConn->OutBufStart = 0;
    TlsConn->OutBufEnd   = 0;
  } else {
    *BufferSize = 0;
  }

  return EFI_SUCCESS;
}

/**
  Attempts to read bytes from one TLS object and places the data in Buffer.

  This function will attempt to read BufferSize bytes from the TLS object
  and places the data in Buffer.

  @param[in]      Tls           Pointer to the TLS object.
  @param[in,out]  Buffer        Pointer to the buffer to store the data.
  @param[in]      BufferSize    The size of Buffer in bytes.

  @retval  >0    The amount of data successfully read from the TLS object.
  @retval  <=0   No data was successfully read.

**/
INTN
EFIAPI
TlsCtrlTrafficOut (
  IN     VOID   *Tls,
  IN OUT VOID   *Buffer,
  IN     UINTN  BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           Available;
  UINTN           CopySize;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (TlsConn->OutBuf == NULL)) {
    return -1;
  }

  Available = TlsConn->OutBufEnd - TlsConn->OutBufStart;
  if (Available == 0) {
    return 0;
  }

  CopySize = (BufferSize < Available) ? BufferSize : Available;
  CopyMem (Buffer, TlsConn->OutBuf + TlsConn->OutBufStart, CopySize);
  TlsConn->OutBufStart += CopySize;

  //
  // Compact if fully consumed
  //
  if (TlsConn->OutBufStart == TlsConn->OutBufEnd) {
    TlsConn->OutBufStart = 0;
    TlsConn->OutBufEnd   = 0;
  }

  return (INTN)CopySize;
}

/**
  Attempts to write data from the buffer to TLS object.

  This function will attempt to write BufferSize bytes data from the Buffer
  to the TLS object.

  @param[in]  Tls           Pointer to the TLS object.
  @param[in]  Buffer        Pointer to the data buffer.
  @param[in]  BufferSize    The size of Buffer in bytes.

  @retval  >0    The amount of data successfully written to the TLS object.
  @retval <=0    No data was successfully written.

**/
INTN
EFIAPI
TlsCtrlTrafficIn (
  IN     VOID   *Tls,
  IN     VOID   *Buffer,
  IN     UINTN  BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           Available;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (TlsConn->InBuf == NULL)) {
    return -1;
  }

  //
  // Compact buffer if needed
  //
  if (TlsConn->InBufStart > 0) {
    UINTN  Existing = TlsConn->InBufEnd - TlsConn->InBufStart;
    if (Existing > 0) {
      CopyMem (TlsConn->InBuf, TlsConn->InBuf + TlsConn->InBufStart, Existing);
    }

    TlsConn->InBufEnd  -= TlsConn->InBufStart;
    TlsConn->InBufStart = 0;
  }

  Available = TlsConn->InBufSize - TlsConn->InBufEnd;
  if (BufferSize > Available) {
    BufferSize = Available;
  }

  if (BufferSize == 0) {
    return 0;
  }

  CopyMem (TlsConn->InBuf + TlsConn->InBufEnd, Buffer, BufferSize);
  TlsConn->InBufEnd += BufferSize;

  return (INTN)BufferSize;
}

/**
  Attempts to read bytes from the specified TLS connection into the buffer.

  This function tries to read BufferSize bytes data from the specified TLS
  connection into the Buffer.

  @param[in]      Tls           Pointer to the TLS connection for data reading.
  @param[in,out]  Buffer        Pointer to the data buffer.
  @param[in]      BufferSize    The size of Buffer in bytes.

  @retval  >0    The read operation was successful, and return value is the
                 number of bytes actually read from the TLS connection.
  @retval  <=0   The read operation was not successful.

**/
INTN
EFIAPI
TlsRead (
  IN     VOID   *Tls,
  IN OUT VOID   *Buffer,
  IN     UINTN  BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;
  int             Ret;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    return -1;
  }

  Ret = mbedtls_ssl_read (&TlsConn->Ssl, (unsigned char *)Buffer, BufferSize);
  if (Ret == MBEDTLS_ERR_SSL_WANT_READ || Ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return 0;
  }

  return (INTN)Ret;
}

/**
  Attempts to write data to a TLS connection.

  This function tries to write BufferSize bytes data from the Buffer into the
  specified TLS connection.

  @param[in]  Tls           Pointer to the TLS connection for data writing.
  @param[in]  Buffer        Pointer to the data buffer.
  @param[in]  BufferSize    The size of Buffer in bytes.

  @retval  >0    The write operation was successful, and return value is the
                 number of bytes actually written to the TLS connection.
  @retval <=0    The write operation was not successful.

**/
INTN
EFIAPI
TlsWrite (
  IN     VOID   *Tls,
  IN     VOID   *Buffer,
  IN     UINTN  BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;
  int             Ret;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    return -1;
  }

  Ret = mbedtls_ssl_write (&TlsConn->Ssl, (const unsigned char *)Buffer, BufferSize);
  if (Ret == MBEDTLS_ERR_SSL_WANT_READ || Ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return 0;
  }

  return (INTN)Ret;
}

/**
  Shutdown a TLS connection.

  Shutdown the TLS connection without releasing the resources, meaning a new
  connection can be started without calling TlsNew() and without setting
  certificates etc.

  @param[in]       Tls            Pointer to the TLS object to shutdown.

  @retval EFI_SUCCESS             The TLS is shutdown successfully.
  @retval EFI_INVALID_PARAMETER   Tls is NULL.
  @retval EFI_PROTOCOL_ERROR      Some other error occurred.

**/
EFI_STATUS
EFIAPI
TlsShutdown (
  IN     VOID  *Tls
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Reset the SSL session for potential reuse
  //
  mbedtls_ssl_session_reset (&TlsConn->Ssl);

  //
  // Clear I/O buffers
  //
  TlsConn->InBufStart  = 0;
  TlsConn->InBufEnd    = 0;
  TlsConn->OutBufStart = 0;
  TlsConn->OutBufEnd   = 0;

  return EFI_SUCCESS;
}
