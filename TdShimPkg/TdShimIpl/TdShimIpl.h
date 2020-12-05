/** @file
  Main SEC phase code.

  Copyright (c) 2008, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/BaseLib.h>
#include <Uefi/UefiSpec.h>

#define MP_CPU_PROTECTED_MODE_MAILBOX_APICID_INVALID    0xFFFFFFFF
#define MP_CPU_PROTECTED_MODE_MAILBOX_APICID_BROADCAST  0xFFFFFFFE

typedef enum {
  MpProtectedModeWakeupCommandNoop = 0,
  MpProtectedModeWakeupCommandWakeup = 1,
  MpProtectedModeWakeupCommandSleep = 2,
  MpProtectedModeWakeupCommandAcceptPages = 3,
} MP_CPU_PROTECTED_MODE_WAKEUP_CMD;

#pragma pack (1)

//
// Describes the CPU MAILBOX control structure use to 
// wakeup cpus spinning in long mode
//
typedef struct {
  UINT16                  Command;
  UINT16                  Resv;
  UINT32                  ApicId;
  UINT64                  WakeUpVector;
  UINT8                   ResvForOs[2032];
  //
  // Arguments available for wakeup code
  //
  UINT64                  WakeUpArgs1;
  UINT64                  WakeUpArgs2;
  UINT64                  WakeUpArgs3;
  UINT64                  WakeUpArgs4;
  UINT8                   Pad1[0xe0];
  UINT64                  NumCpusArriving;
  UINT8                   Pad2[0xf8];
  UINT64                  NumCpusExiting;
  UINT32                  Tallies[256];
} MP_WAKEUP_MAILBOX;


//
// AP relocation code information including code address and size,
// this structure will be shared be C code and assembly code.
// It is natural aligned by design.
//
typedef struct {
  UINT8             *RelocateApLoopFuncAddress;
  UINTN             RelocateApLoopFuncSize;
} MP_RELOCATION_MAP;

#pragma pack()
#pragma pack(push, 4)
#define EFI_METADATA_GUID \
   { 0xe9eaf9f3, 0x168e, 0x44d5, { 0xa8, 0xeb, 0x7f, 0x4d, 0x87, 0x38, 0xf6, 0xae } }

typedef struct {
  EFI_GUID guid;
  UINT64  mailbox_base_address;
  UINT64  mailbox_size;
  UINT64  hob_base_address;
  UINT64  hob_size;
  UINT64  stack_base_address;
  UINT64  stack_size;
  UINT64  heap_base_address;
  UINT64  heap_size;
  UINT64  bfv_base_address;
  UINT32  bfv_size;
  UINT32  rsvd;
  UINT32  sig;
}tdvf_metadata_t;
#pragma pack(pop)

#pragma pack (1)

#define HANDOFF_TABLE_DESC  "TdxTable"
typedef struct {
  UINT8                             TableDescriptionSize;
  UINT8                             TableDescription[sizeof(HANDOFF_TABLE_DESC)];
  UINT64                            NumberOfTables;
  EFI_CONFIGURATION_TABLE           TableEntry[1];
} TDX_HANDOFF_TABLE_POINTERS2;

#pragma pack ()

volatile VOID *
EFIAPI
GetMailBox(
  VOID
  );

UINT32
EFIAPI
GetNumCpus(
  VOID
  );

EFI_STATUS
EFIAPI
DxeLoadCore (
  IN INTN FvInstance
  );

VOID
EFIAPI
SecStartupPhase2 (
  IN VOID                     *Context
  );


VOID
EFIAPI
MpSendWakeupCommand(
  IN UINT16 Command,
  IN UINT64 WakeupVector,
  IN UINT64 WakeupArgs1,
  IN UINT64 WakeupArgs2,
  IN UINT64 WakeupArgs3,
  IN UINT64 WakeupArgs4
);

VOID
EFIAPI
MpSerializeStart (
  VOID
  );

VOID
EFIAPI
MpSerializeEnd (
  VOID
  );

VOID
EFIAPI
MpAcceptMemoryResourceRange (
  IN EFI_PHYSICAL_ADDRESS        PhysicalAddress,
  IN EFI_PHYSICAL_ADDRESS        PhysicalEnd
  );

VOID
EFIAPI
ProcessHobList (
  IN CONST VOID             *HobStart
  );

VOID
EFIAPI
TransferHobList (
  IN CONST VOID             *HobStart
  );

tdvf_metadata_t *
EFIAPI
InitializeMetaData(
  VOID
  );

VOID
EFIAPI
LogHobList (
  IN CONST VOID             *HobStart
  );

EFI_STATUS
TdxMeasureFvImage (
  IN EFI_PHYSICAL_ADDRESS           FvBase,
  IN UINT64                         FvLength,
  IN UINT8                          PcrIndex
  );

EFI_PHYSICAL_ADDRESS
EFIAPI
AllocateRelocationMemory(
  UINT32  Size
  );

VOID
EFIAPI
AsmGetRelocationMap (
  OUT MP_RELOCATION_MAP    *AddressMap
  );


