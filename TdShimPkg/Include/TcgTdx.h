#ifndef __TCG_TDX_H__
#define __TCG_TDX_H__

#include <Uefi/UefiBaseType.h>
#include <Uefi/UefiMultiPhase.h>
#include <IndustryStandard/Tpm20.h>
#include <IndustryStandard/UefiTcgPlatform.h>
//#include <IndustryStandard/Tdx.h>

#define TCG_TDX_EVENT_DATA_SIGNATURE  SIGNATURE_32 ('T', 'D', 'X', 'S')

#define TDX_CMD_EXTEND_RTMR   1
#define TDX_CMD_TDREPORT      2

#pragma pack(1)
typedef struct {
  UINT32            count;
  TPMI_ALG_HASH     hashAlg;
  BYTE              sha384[SHA384_DIGEST_SIZE];
} TDX_DIGEST_VALUE;

/* TDX Commands and Params definition*/
typedef struct{
  UINT8   index;
  UINT8   hash[SHA384_DIGEST_SIZE];
}TDX_EXTEND_RTMR_PARAMS;

typedef struct{
  UINT8   *additional_data;
  UINT32  size;
}TDX_TDREPORT_PARAMS;

typedef union{
  TDX_EXTEND_RTMR_PARAMS  extend_params;
  TDX_TDREPORT_PARAMS     tdreport_params;
}TDX_PARAMS;

typedef struct{
  UINT8       command;
  TDX_PARAMS  params;
} TDX_COMMANDS;

#pragma pack()

// e15c982b-8df9-4a09-a34e-e1683d1777cc

typedef struct {
  UINT32            Signature;       
  UINT8             *HashData;
  UINTN             HashDataLen;
} TDX_EVENT;

EFI_STATUS
TdxMeasureFvImage (
  IN EFI_PHYSICAL_ADDRESS           FvBase,
  IN UINT64                         FvLength,
  IN UINT8                          PcrIndex
  );

EFI_STATUS
CreateTdxExtendEvent (
  IN      TCG_PCRINDEX              PCRIndex,
  IN      TCG_EVENTTYPE             EventType,
  IN      UINT8                     *EventData,
  IN      UINTN                     EventSize,
  IN      UINT8                     *HashData,
  IN      UINTN                     HashDataLen
  );

/**
  This function extends one of the RTMR measurement register 
  in TDCS with the provided extension data in memory.

  @param[in]  Data      64B-aligned guest physical address of a 48B extension data
  @param[in]  DataLen   Must be 48
  @param[in]  PcrIndex  PCR Index is mapped to RTMR index

  @return EFI_SUCCESS
  @return EFI_INVALID_PARAMETER
  @return EFI_DEVICE_ERROR

**/
EFI_STATUS
EFIAPI
ExtendTdRtmr(
  IN  UINT32  *Data,
  IN  UINT32  DataLen,
  IN  UINT8   PcrIndex
  );

/**
  This function retrieve TDREPORT_STRUCT structure from TDX.
  The struct contains the measurements/configuration information of 
  the guest TD that called the function, measurements/configuratio 
  information of the TDX-SEAM module and a REPORTMACSTRUCT. 
  The REPORTMACSTRUCT is integrity protected with a MAC and 
  contains the hash of the measurements and configuration 
  as well as additional REPORTDATA provided by the TD software.
 
  Additional REPORTDATA, a 64-byte value, is provided by the 
  guest TD to be included in the TDREPORT

  @param[in]  *Report             Holds the TEREPORT_STRUCT
  @param[in]  ReportSize          Size of the report. It must be larger than 1024B
  @param[in]  *AdditionalData     Point to the additional data.
  @param[in]  AdditionalDataSize  Size of the additional data.
                                  If AdditionalData != NULL, then this value must be 64B

  @return EFI_SUCCESS
  @return EFI_INVALID_PARAMETER
  @return EFI_DEVICE_ERROR

**/
EFI_STATUS
EFIAPI
DoTdReport(
  IN UINT8   *Report,
  IN UINT32  ReportSize,
  IN UINT8   *AdditionalData,
  IN UINT32  AdditionalDataSize
);

// MRTD/RTMR maps to PCRIndex
#define REG_TYPE_NA    0
#define REG_TYPE_MRTD  1
#define REG_TYPE_RTMR  2
#define PCR_COUNT      16

typedef struct {
  UINT8     Pcr;          // PCR index
  UINT8     RegType;      // RTMR or MRTD
  UINT8     Index;        // index in RTMR/MRTD
  UINT8     EventlogIndex;// index in EventLog
}PCR_TDVF_EXTEND_MAP;

/**
 TPM PCRs are mapped to MRTD/RTMR
 This API is used to get the mapped index in Event log
 according to the PCRIndex
**/
UINT32 GetMappedIndexInEventLog(UINT32 PCRIndex);

#define TD_TCG2_PROTOCOL_GUID  \
  {0x96751a3d, 0x72f4, 0x41a6, { 0xa7, 0x94, 0xed, 0x5d, 0x0e, 0x67, 0xae, 0x6b }}
extern EFI_GUID gTdTcg2ProtocolGuid;


#endif
