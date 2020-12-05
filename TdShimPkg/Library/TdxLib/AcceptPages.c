#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <IndustryStandard/Tdx.h>
#include <Library/TdxLib.h>
#include <Library/BaseMemoryLib.h>

#include "InternalTdxLib.h"

UINT64  mNumberOfDuplicatedAcceptedPages;

UINT64
EFIAPI
TdAcceptPages (
  IN UINT64  StartAddress,
  IN UINT64  NumberOfPages
  )
{
  UINT64  Address;
  UINT64  Status;

  // Determine if we need to accept pages before use
  //
  if (FixedPcdGetBool(PcdUseTdxAcceptPage) == FALSE) {
     return EFI_SUCCESS;
  }

  Address = StartAddress;

  while (NumberOfPages--) {
    Status = TdAcceptPage(Address);
    if (Status != TDX_EXIT_REASON_SUCCESS) {
        if ((Status & ~0xFFULL) == TDX_EXIT_REASON_PAGE_ALREADY_ACCEPTED) {
          ++mNumberOfDuplicatedAcceptedPages;
          DEBUG((DEBUG_INFO, "Address %llx already accepted. Total number of already accepted pages %ld\n",
            Address, mNumberOfDuplicatedAcceptedPages));
        } else {
          DEBUG((DEBUG_ERROR, "Address %llx failed to be accepted. Error = %ld\n",
            Address, Status));
          ASSERT(Status == TDX_EXIT_REASON_SUCCESS);
        }
    }
    Address += EFI_PAGE_SIZE;
  }
  return EFI_SUCCESS;
}

