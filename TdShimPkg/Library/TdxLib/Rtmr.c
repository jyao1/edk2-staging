#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/TdxLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Include/TcgTdx.h>
#include <IndustryStandard/Tdx.h>
//
// MRTD     => PCR[0]
// RTMR[0]  => PCR[1,7]
// RTMR[1]  => PCR[2,3,4,5,6]
// RTMR[2]  => PCR[8~15]
// RTMR[3]  => TBD
PCR_TDVF_EXTEND_MAP mPcrTdvfExtendMaps[PCR_COUNT] = {
// pcr      reg       indx  index_in_event_log 
  {0 , REG_TYPE_MRTD, 0,    0},
  {1 , REG_TYPE_RTMR, 0,    1},
  {2 , REG_TYPE_RTMR, 1,    2},
  {3 , REG_TYPE_RTMR, 1,    2},
  {4 , REG_TYPE_RTMR, 1,    2},
  {5 , REG_TYPE_RTMR, 1,    2},
  {6 , REG_TYPE_RTMR, 1,    2},
  {7 , REG_TYPE_RTMR, 0,    1},
  {8 , REG_TYPE_RTMR, 2,    3},
  {9 , REG_TYPE_RTMR, 2,    3},
  {10, REG_TYPE_RTMR, 2,    3},
  {11, REG_TYPE_RTMR, 2,    3},
  {12, REG_TYPE_RTMR, 2,    3},
  {13, REG_TYPE_RTMR, 2,    3},
  {14, REG_TYPE_RTMR, 2,    3},
  {15, REG_TYPE_RTMR, 2,    3},
};

UINT32 GetMappedIndexInEventLog(UINT32 PCRIndex)
{
  PCR_TDVF_EXTEND_MAP       *PcrTdxMap;

  ASSERT(PCRIndex >= 0 && PCRIndex < PCR_COUNT);
  PcrTdxMap = (PCR_TDVF_EXTEND_MAP*)&mPcrTdvfExtendMaps[PCRIndex];
  return PcrTdxMap->EventlogIndex;
}


/**
  This command is used to cause an update to the indicated PCR.
  The digests parameter contains one or more tagged digest value identified by an algorithm ID.
  For each digest, the PCR associated with pcrHandle is Extended into the bank identified by the tag (hashAlg).

  @param[in] PcrHandle   Handle of the PCR
  @param[in] Digests     List of tagged digest values to be extended

  @retval EFI_SUCCESS      Operation completed successfully.
  @retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
EFIAPI
ExtendTdRtmr(
  IN  UINT32  *Data,
  IN  UINT32  DataLen,
  IN  UINT8   PcrIndex
  )
{
  EFI_STATUS            Status;
  UINT64                *Buffer;
  UINT64                TdCallStatus;
  UINT64                Index;
  PCR_TDVF_EXTEND_MAP   PcrTdvfExtendMap;

  Status = EFI_SUCCESS;

  ASSERT(PcrIndex >= 0 && PcrIndex < PCR_COUNT);
  ASSERT(DataLen == SHA384_DIGEST_SIZE);

  PcrTdvfExtendMap = mPcrTdvfExtendMaps[PcrIndex];
  ASSERT(PcrTdvfExtendMap.Pcr == PcrIndex);

  if(PcrTdvfExtendMap.RegType == REG_TYPE_RTMR){
    Index = PcrTdvfExtendMap.Index;
  }else{
    DEBUG((DEBUG_INFO, "PCR[%d] is not mapped to TDVF RTMR\n", PcrIndex));
    return EFI_UNSUPPORTED;
  }

  // Allocate 64B aligned mem to hold the sha384 hash value
  //
  Buffer = AllocateAlignedPages(EFI_SIZE_TO_PAGES(SHA384_DIGEST_SIZE), 64);
  if(Data == NULL){
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem(Buffer, Data, SHA384_DIGEST_SIZE);

  DEBUG((DEBUG_INFO, "Extend to Rtmr[%d]. Pcr=%d\n", Index, PcrIndex));

  // call TdExtendRtmr
  //TdCallStatus = TdExtendRtmr(Buffer, Index);
  TdCallStatus = TdCall(TDCALL_TDEXTENDRTMR, (UINT64)Buffer, Index, 0, 0);

  if(TdCallStatus == TDX_EXIT_REASON_SUCCESS){
    Status = EFI_SUCCESS;
  }else if(TdCallStatus == TDX_EXIT_REASON_OPERAND_INVALID){
    Status = EFI_INVALID_PARAMETER;
  }else{
    Status = EFI_DEVICE_ERROR;
  }

  if(Status != EFI_SUCCESS){
    DEBUG((DEBUG_ERROR, "Error returned from TdExtendRtmr call - 0x%lx\n", TdCallStatus));
  }else{
    DEBUG((DEBUG_INFO, "Success returned from TdExtendRtmr call.\n"));
  }

  FreeAlignedPages(Buffer, EFI_SIZE_TO_PAGES(SHA384_DIGEST_SIZE));

  return Status;
}
