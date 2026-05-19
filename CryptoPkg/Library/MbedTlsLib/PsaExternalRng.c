/** @file
  PSA External RNG implementation for EDK2.

  Implements mbedtls_psa_external_get_random() using EDK2's RandomBytes()
  from BaseCryptLib. This allows MbedTLS PSA Crypto to function without
  the entropy module.

Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BaseCryptLib.h>
#include <psa/crypto.h>

/**
  External RNG function for PSA Crypto.

  @param[in]   context        Pointer to the external RNG context (unused).
  @param[out]  output         Buffer to fill with random data.
  @param[in]   output_size    Number of bytes requested.
  @param[out]  output_length  Number of bytes actually generated.

  @retval  PSA_SUCCESS       Random data generated successfully.
  @retval  PSA_ERROR_INSUFFICIENT_ENTROPY  RNG failure.

**/
psa_status_t
mbedtls_psa_external_get_random (
  mbedtls_psa_external_random_context_t  *context,
  uint8_t                                *output,
  size_t                                 output_size,
  size_t                                 *output_length
  )
{
  if (RandomBytes (output, (UINTN)output_size)) {
    *output_length = output_size;
    return PSA_SUCCESS;
  }

  return PSA_ERROR_INSUFFICIENT_ENTROPY;
}
