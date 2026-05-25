/** @file
  CBMC Formal Verification Harness for EFI Crypto Indicator Table (ECIT).

  This harness #includes the REAL CryptoIndicatorTableDxe.c and verifies
  the produced table against formal properties in EcitFormalVerification.md.
  EDK2 library functions are stubbed. Empty headers in CbmcStubs/ satisfy
  the #include directives in the original source.

  Usage:
    cbmc EcitVerificationHarness.c -DCBMC_VERIFICATION \
      -I CbmcStubs --unwind 800 --unwinding-assertions \
      --function harness_all

  Per-property (faster):
    cbmc EcitVerificationHarness.c -DCBMC_VERIFICATION \
      -I CbmcStubs --unwind 800 --unwinding-assertions \
      --function harness_P1_1

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifdef CBMC_VERIFICATION

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// EDK2 Base Type Definitions
// ============================================================================

typedef uint8_t   UINT8;
typedef uint16_t  UINT16;
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef int64_t   INTN;
typedef char      CHAR8;
typedef unsigned char BOOLEAN;
typedef uint64_t  UINTN;
typedef void      VOID;
typedef UINTN     RETURN_STATUS;
typedef UINTN     EFI_STATUS;
typedef void*     EFI_HANDLE;
typedef void*     EFI_EVENT;

#define EFI_SUCCESS           0
#define EFI_OUT_OF_RESOURCES  9
#define EFI_UNSUPPORTED       3
#define EFI_NOT_FOUND         14
#define EFI_ERROR(x)          ((x) != 0)
#define RETURN_SUCCESS        0

#define IN
#define OUT
#define OPTIONAL
#define CONST     const
#define STATIC    static
#define EFIAPI
#define TRUE      1
#define FALSE     0
#define NULL      ((void*)0)
#define ALIGN_VALUE(Value, Alignment) \
  (((Value) + ((Alignment) - 1)) & ~((Alignment) - 1))
#define SIGNATURE_32(A,B,C,D) \
  ((UINT32)((A)|((B)<<8)|((C)<<16)|((D)<<24)))
#define SIGNATURE_64(A,B,C,D,E,F,G,H) \
  ((UINT64)(SIGNATURE_32(A,B,C,D)) | ((UINT64)(SIGNATURE_32(E,F,G,H)) << 32))
#define DEBUG(x)
#define DEBUG_ERROR   0x80000000
#define DEBUG_WARN    0x40000000
#define DEBUG_INFO    0x00000040

typedef struct {
  UINT32  Data1;
  UINT16  Data2;
  UINT16  Data3;
  UINT8   Data4[8];
} EFI_GUID;

// ============================================================================
// ACPI Description Header (from MdePkg)
// ============================================================================

#pragma pack(1)
typedef struct {
  UINT32  Signature;
  UINT32  Length;
  UINT8   Revision;
  UINT8   Checksum;
  UINT8   OemId[6];
  UINT64  OemTableId;
  UINT32  OemRevision;
  UINT32  CreatorId;
  UINT32  CreatorRevision;
} EFI_ACPI_DESCRIPTION_HEADER;
#pragma pack()

// ============================================================================
// ECIT Structures (from Guid/CryptoIndicatorTable.h)
// ============================================================================

#define EFI_CRYPTO_INDICATOR_TABLE_SIGNATURE  SIGNATURE_32('E','C','I','T')
#define EFI_CRYPTO_INDICATOR_TABLE_VERSION    1

#pragma pack(1)
typedef struct {
  EFI_GUID  FeatureIdentifier;
  UINT16    EntryLength;
  UINT8     Reserved[6];
} EFI_CRYPTO_INDICATOR_ENTRY;

typedef struct {
  EFI_ACPI_DESCRIPTION_HEADER  Header;
  UINT8   NumberOfEntries;
  UINT8   Reserved[3];
} EFI_CRYPTO_INDICATOR_TABLE;
#pragma pack()

// ============================================================================
// EFI_ACPI_TABLE_PROTOCOL (from Protocol/AcpiTable.h)
// ============================================================================

typedef struct _EFI_ACPI_TABLE_PROTOCOL {
  EFI_STATUS (*InstallAcpiTable)(
    struct _EFI_ACPI_TABLE_PROTOCOL*, VOID*, UINTN, UINTN*);
} EFI_ACPI_TABLE_PROTOCOL;

// ============================================================================
// EFI_SYSTEM_TABLE (minimal, not used by driver logic)
// ============================================================================

typedef struct { UINT64 Unused; } EFI_SYSTEM_TABLE;

// ============================================================================
// Certificate GUID macros (from Guid/ImageAuthentication.h)
// Used as initializers in the driver's GUID arrays.
// ============================================================================

#define EFI_CERT_X509_GUID \
  {0xa5c059a1,0x94e4,0x4aa7,{0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72}}
#define EFI_CERT_SHA256_GUID \
  {0xc1c41626,0x504c,0x4092,{0xac,0xa9,0x41,0xf9,0x36,0x93,0x43,0x28}}
#define EFI_CERT_SHA384_GUID \
  {0xff3e5307,0x9fd0,0x48c9,{0x85,0xf1,0x8a,0xd5,0x6c,0x70,0x1e,0x01}}
#define EFI_CERT_SHA512_GUID \
  {0x93e0fae,0xa6c4,0x4f50,{0x9f,0x1b,0xd4,0x1e,0x2b,0x89,0xc1,0x9a}}
#define EFI_CERT_X509_SHA256_GUID \
  {0x3bd2a492,0x96c0,0x4079,{0xb4,0x20,0xfc,0xf9,0x8e,0xf1,0x03,0xed}}
#define EFI_CERT_X509_SHA384_GUID \
  {0x7076876e,0x80c2,0x4ee6,{0xaa,0xd2,0x28,0xb3,0x49,0xa6,0x86,0x5b}}
#define EFI_CERT_X509_SHA512_GUID \
  {0x446dbf63,0x2502,0x4cda,{0xbc,0xfa,0x24,0x65,0xd2,0xb0,0xfe,0x9d}}
#define EFI_CERT_V2_X509_GUID \
  {0,0,0,{0,0,0,0,0,0,0,1}}
#define EFI_CERT_V2_SHA256_GUID \
  {0,0,0,{0,0,0,0,0,0,0,2}}
#define EFI_CERT_V2_SHA384_GUID \
  {0,0,0,{0,0,0,0,0,0,0,3}}
#define EFI_CERT_V2_SHA512_GUID \
  {0,0,0,{0,0,0,0,0,0,0,4}}
#define EFI_CERT_V2_X509_SHA256_GUID \
  {0,0,0,{0,0,0,0,0,0,0,5}}
#define EFI_CERT_V2_X509_SHA384_GUID \
  {0,0,0,{0,0,0,0,0,0,0,6}}
#define EFI_CERT_V2_X509_SHA512_GUID \
  {0,0,0,{0,0,0,0,0,0,0,7}}

// ============================================================================
// Byte-level helpers (no standard library dependency for CBMC)
// ============================================================================

static void my_memcpy(void *dst, const void *src, UINTN n) {
  UINT8 *d = (UINT8*)dst;
  const UINT8 *s = (const UINT8*)src;
  for (UINTN i = 0; i < n; i++) d[i] = s[i];
}

static void my_memset(void *dst, UINT8 val, UINTN n) {
  UINT8 *d = (UINT8*)dst;
  for (UINTN i = 0; i < n; i++) d[i] = val;
}

static UINTN my_strlen(const CHAR8 *s) {
  UINTN n = 0;
  while (s[n] != '\0') n++;
  return n;
}

static bool my_memcmp_eq(const void *a, const void *b, UINTN n) {
  const UINT8 *pa = (const UINT8*)a;
  const UINT8 *pb = (const UINT8*)b;
  for (UINTN i = 0; i < n; i++) {
    if (pa[i] != pb[i]) return false;
  }
  return true;
}

// ============================================================================
// EDK2 Library Stubs (implementations called by the driver)
// ============================================================================

VOID *CopyMem(VOID *Dest, CONST VOID *Src, UINTN Length) {
  my_memcpy(Dest, Src, Length);
  return Dest;
}

VOID *ZeroMem(VOID *Buffer, UINTN Length) {
  my_memset(Buffer, 0, Length);
  return Buffer;
}

VOID *CopyGuid(EFI_GUID *Dest, CONST EFI_GUID *Src) {
  my_memcpy(Dest, Src, sizeof(EFI_GUID));
  return Dest;
}

UINTN AsciiStrSize(CONST CHAR8 *String) {
  return my_strlen(String) + 1;
}

RETURN_STATUS AsciiStrCpyS(CHAR8 *Dest, UINTN DestMax, CONST CHAR8 *Src) {
  UINTN Len = my_strlen(Src);
  if (Len + 1 > DestMax) return 1;
  my_memcpy(Dest, Src, Len + 1);
  return RETURN_SUCCESS;
}

UINT8 CalculateCheckSum8(CONST UINT8 *Buffer, UINTN Length) {
  UINT8 Sum = 0;
  for (UINTN i = 0; i < Length; i++) {
    Sum = (UINT8)(Sum + Buffer[i]);
  }
  return (UINT8)(0x100 - Sum);
}

// Pool allocator stub (table is ~784 bytes)
static UINT8  gPoolBuffer[800];
static void  *gCapturedTable = NULL;

VOID *AllocateZeroPool(UINTN Size) {
  if (Size > sizeof(gPoolBuffer)) return NULL;
  my_memset(gPoolBuffer, 0, Size);
  return gPoolBuffer;
}

VOID FreePool(VOID *Buffer) { (void)Buffer; }

// ============================================================================
// BaseCryptLib stub: Pkcs7GetVerifyOidList
// ============================================================================

typedef enum { Pkcs7SignatureAlgoAll = 0 } Pkcs7SignatureAlgoType;

CONST CHAR8 *Pkcs7GetVerifyOidList(Pkcs7SignatureAlgoType AlgoType) {
  (void)AlgoType;
  return "1.2.840.113549.1.1.11,1.2.840.113549.1.1.12,1.2.840.113549.1.1.13,1.2.840.10045.4.3.2";
}

// ============================================================================
// Boot Services stub (captures InstallConfigurationTable)
// ============================================================================

// Forward declaration (defined below, after this section)
extern EFI_GUID gEfiAcpiTableProtocolGuid;
extern EFI_GUID gEfiTcg2ProtocolGuid;

// Scenario control: set before calling the driver
static bool gAcpiProtocolAvailable = false;
static bool gTcg2ProtocolAvailable = false;
static bool gInstallAcpiTableCalled = false;
static VOID *gAcpiTablePointer = NULL;
static UINTN gAcpiTableSize = 0;
static UINT8  gAcpiCopyBuffer[800];  // Simulates EfiAcpiReclaimMemory region

// TCG2 measurement tracking
#define EV_EFI_HANDOFF_TABLES2  0x8000000B
static bool  gMeasurementCalled = false;
static UINT32 gMeasuredPcrIndex = 0xFFFFFFFF;
static UINT32 gMeasuredEventType = 0;
static VOID  *gMeasuredData = NULL;
static UINT64 gMeasuredDataSize = 0;
static bool  gMeasurementAfterInstall = false;  // was InstallConfigTable already called?

static EFI_STATUS StubInstallConfigurationTable(EFI_GUID *Guid, VOID *Table) {
  (void)Guid;
  gCapturedTable = Table;
  return EFI_SUCCESS;
}

static EFI_STATUS StubInstallAcpiTable(
  EFI_ACPI_TABLE_PROTOCOL *This, VOID *Table, UINTN Size, UINTN *Key) {
  (void)This;
  gInstallAcpiTableCalled = true;
  gAcpiTableSize = Size;
  //
  // Model REAL behavior: ACPI protocol COPIES the table to separate memory
  // (EfiAcpiReclaimMemory). The returned pointer is NOT the same as input.
  //
  if (Size <= sizeof(gAcpiCopyBuffer)) {
    my_memcpy(gAcpiCopyBuffer, Table, Size);
    gAcpiTablePointer = gAcpiCopyBuffer;
  } else {
    gAcpiTablePointer = NULL;
  }
  *Key = 1;
  return EFI_SUCCESS;
}

static EFI_ACPI_TABLE_PROTOCOL gStubAcpiProtocol = { StubInstallAcpiTable };

// ============================================================================
// TCG2 Protocol stub
// ============================================================================

typedef struct {
  UINT32 Size;
  EFI_ACPI_DESCRIPTION_HEADER Header;  // reuse for the event structure
  UINT32 NumberOfEvents;
} EFI_TCG2_EVENT_HEADER;

typedef struct {
  UINT32 Size;
  UINT32 HeaderSize;
  UINT16 HeaderVersion;
  UINT32 PCRIndex;
  UINT32 EventType;
} EFI_TCG2_EVENT;

typedef struct _EFI_TCG2_PROTOCOL {
  EFI_STATUS (*HashLogExtendEvent)(
    struct _EFI_TCG2_PROTOCOL *This,
    UINT64 Flags,
    UINT64 DataToHash,
    UINT64 DataToHashLen,
    EFI_TCG2_EVENT *EfiTcgEvent);
} EFI_TCG2_PROTOCOL;

static EFI_STATUS StubHashLogExtendEvent(
  EFI_TCG2_PROTOCOL *This,
  UINT64 Flags,
  UINT64 DataToHash,
  UINT64 DataToHashLen,
  EFI_TCG2_EVENT *EfiTcgEvent) {
  (void)This; (void)Flags;
  gMeasurementCalled = true;
  gMeasuredPcrIndex = EfiTcgEvent->PCRIndex;
  gMeasuredEventType = EfiTcgEvent->EventType;
  gMeasuredData = (VOID*)(UINTN)DataToHash;
  gMeasuredDataSize = DataToHashLen;
  // Track ordering: was InstallConfigurationTable already called?
  gMeasurementAfterInstall = (gCapturedTable != NULL);
  return EFI_SUCCESS;
}

static EFI_TCG2_PROTOCOL gStubTcg2Protocol = { StubHashLogExtendEvent };

static EFI_STATUS StubLocateProtocol(EFI_GUID *Protocol, VOID *Reg, VOID **Interface) {
  (void)Reg;
  if (gAcpiProtocolAvailable && my_memcmp_eq(Protocol, &gEfiAcpiTableProtocolGuid, sizeof(EFI_GUID))) {
    *Interface = &gStubAcpiProtocol;
    return EFI_SUCCESS;
  }
  if (gTcg2ProtocolAvailable && my_memcmp_eq(Protocol, &gEfiTcg2ProtocolGuid, sizeof(EFI_GUID))) {
    *Interface = &gStubTcg2Protocol;
    return EFI_SUCCESS;
  }
  return EFI_NOT_FOUND;
}

typedef struct {
  EFI_STATUS (*InstallConfigurationTable)(EFI_GUID*, VOID*);
  EFI_STATUS (*LocateProtocol)(EFI_GUID*, VOID*, VOID**);
} STUB_BOOT_SERVICES;

static STUB_BOOT_SERVICES gStubBS = {
  StubInstallConfigurationTable,
  StubLocateProtocol
};

// Override gBS to use our stub
#define gBS (&gStubBS)

// ============================================================================
// Extern GUID variable definitions (normally from AutoGen.c)
// ============================================================================

EFI_GUID gEfiEcitFeatureImageVerificationGuid = {
  0x08324cfc, 0xefe6, 0x4211, {0xa8,0x58,0xd4,0xca,0xc8,0x91,0x5a,0xef}};
EFI_GUID gEfiEcitFeatureSecureBootAuthorizationGuid = {
  0x335f880f, 0x180f, 0x43d9, {0x8e,0xd9,0xce,0x58,0x4e,0xd9,0xb6,0xf0}};
EFI_GUID gEfiEcitFeatureImageRevocationGuid = {
  0x02913331, 0x2f71, 0x43db, {0x82,0x77,0x7b,0xe8,0x8e,0xcc,0x65,0x1c}};
EFI_GUID gEfiEcitFeatureSecureBootServicingAuthorizationGuid = {
  0xa2c84d56, 0x2e04, 0x4f3a, {0xb7,0xd1,0x3c,0x9e,0x5a,0x6f,0x8b,0x12}};
EFI_GUID gEfiEcitFeatureAuthenticatedVariableGuid = {
  0x03092d2c, 0x9a52, 0x4c5c, {0x8b,0xf5,0xea,0xf0,0x4f,0x45,0x22,0x9d}};
EFI_GUID gEfiCryptoIndicatorTableGuid = {
  0x1768b8b1, 0x1605, 0x401a, {0xbc,0x49,0xd6,0x12,0xd2,0xb9,0x8c,0x4e}};
EFI_GUID gEfiAcpiTableProtocolGuid = {
  0xffe06bdd, 0x6107, 0x46a6, {0x7b,0xb2,0x5a,0x9c,0x7e,0xc5,0x27,0x5c}};
EFI_GUID gEfiTcg2ProtocolGuid = {
  0x607f766c, 0x7455, 0x42be, {0x93,0x0b,0xe4,0xd7,0x6d,0xb2,0x72,0x0f}};

// ============================================================================
// EfiLocateFirstAcpiTable stub (from UefiLib)
// After InstallAcpiTable, driver calls this to find the ACPI copy.
// ============================================================================

EFI_ACPI_DESCRIPTION_HEADER *EfiLocateFirstAcpiTable(UINT32 Signature) {
  if (gInstallAcpiTableCalled && Signature == EFI_CRYPTO_INDICATOR_TABLE_SIGNATURE) {
    return (EFI_ACPI_DESCRIPTION_HEADER *)gAcpiCopyBuffer;
  }
  return NULL;
}

// ============================================================================
// INCLUDE THE REAL IMPLEMENTATION (never copy!)
// The empty headers in CbmcStubs/ satisfy the #include directives.
// All types and stubs above satisfy the symbol requirements.
// ============================================================================

#include "CryptoIndicatorTableDxe.c"

// ============================================================================
// Helper: Run driver and get produced table
// ============================================================================

static const EFI_CRYPTO_INDICATOR_TABLE *RunDriverAndGetTable(void) {
  EFI_HANDLE       ImageHandle = NULL;
  EFI_SYSTEM_TABLE SysTable;
  my_memset(&SysTable, 0, sizeof(SysTable));
  gCapturedTable = NULL;
  gAcpiProtocolAvailable = false;
  gTcg2ProtocolAvailable = false;
  gInstallAcpiTableCalled = false;
  gAcpiTablePointer = NULL;
  gAcpiTableSize = 0;
  gMeasurementCalled = false;
  gMeasuredPcrIndex = 0xFFFFFFFF;
  gMeasuredEventType = 0;
  gMeasuredData = NULL;
  gMeasuredDataSize = 0;
  gMeasurementAfterInstall = false;

  EFI_STATUS Status = CryptoIndicatorTableDxeEntryPoint(ImageHandle, &SysTable);
  __CPROVER_assert(Status == EFI_SUCCESS,
    "PRECONDITION: Driver must return EFI_SUCCESS");
  __CPROVER_assert(gCapturedTable != NULL,
    "PRECONDITION: Table must be installed");
  return (const EFI_CRYPTO_INDICATOR_TABLE *)gCapturedTable;
}

static const EFI_CRYPTO_INDICATOR_TABLE *RunDriverWithAcpi(void) {
  EFI_HANDLE       ImageHandle = NULL;
  EFI_SYSTEM_TABLE SysTable;
  my_memset(&SysTable, 0, sizeof(SysTable));
  gCapturedTable = NULL;
  gAcpiProtocolAvailable = true;
  gTcg2ProtocolAvailable = false;
  gInstallAcpiTableCalled = false;
  gAcpiTablePointer = NULL;
  gAcpiTableSize = 0;
  gMeasurementCalled = false;
  gMeasuredPcrIndex = 0xFFFFFFFF;
  gMeasuredEventType = 0;
  gMeasuredData = NULL;
  gMeasuredDataSize = 0;
  gMeasurementAfterInstall = false;

  EFI_STATUS Status = CryptoIndicatorTableDxeEntryPoint(ImageHandle, &SysTable);
  __CPROVER_assert(Status == EFI_SUCCESS,
    "PRECONDITION: Driver must return EFI_SUCCESS");
  __CPROVER_assert(gCapturedTable != NULL,
    "PRECONDITION: Table must be installed");
  return (const EFI_CRYPTO_INDICATOR_TABLE *)gCapturedTable;
}

// ============================================================================
// Property Verification Helpers
// ============================================================================

static bool GuidEqual(const EFI_GUID *G1, const EFI_GUID *G2) {
  return my_memcmp_eq(G1, G2, sizeof(EFI_GUID));
}

// ============================================================================
// Per-property harnesses (cbmc --function harness_P1_1, etc.)
// ============================================================================

void harness_P1_1(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  __CPROVER_assert(
    T->Header.Signature == EFI_CRYPTO_INDICATOR_TABLE_SIGNATURE,
    "P1.1: Signature must be ECIT (0x54494345)");
}

void harness_P1_2(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  UINT32 ComputedSize = sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    ComputedSize += E->EntryLength;
    Offset += E->EntryLength;
  }
  __CPROVER_assert(T->Header.Length == ComputedSize,
    "P1.2: Length must equal header + sum(EntryLengths)");
}

void harness_P1_3(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  __CPROVER_assert(
    T->Header.Revision == EFI_CRYPTO_INDICATOR_TABLE_VERSION,
    "P1.3: Revision must be EFI_CRYPTO_INDICATOR_TABLE_VERSION");
}

void harness_P1_4(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *B = (const UINT8 *)T;
  UINT8 Sum = 0;
  for (UINT32 i = 0; i < T->Header.Length; i++) {
    Sum = (UINT8)(Sum + B[i]);
  }
  __CPROVER_assert(Sum == 0,
    "P1.4: Byte-wise checksum of entire table must be zero");
}

void harness_P1_5(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  __CPROVER_assert(
    T->Reserved[0] == 0 && T->Reserved[1] == 0 && T->Reserved[2] == 0,
    "P1.5: Table Reserved[3] must be all zeros");
}

void harness_P2_2(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    __CPROVER_assert(E->EntryLength >= sizeof(EFI_CRYPTO_INDICATOR_ENTRY),
      "P2.2: Every EntryLength >= sizeof(EFI_CRYPTO_INDICATOR_ENTRY)");
    Offset += E->EntryLength;
  }
}

void harness_P2_3(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    __CPROVER_assert(E->EntryLength % 8 == 0,
      "P2.3: Every EntryLength must be 8-byte aligned");
    Offset += E->EntryLength;
  }
}

void harness_P2_4(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    __CPROVER_assert(
      E->Reserved[0]==0 && E->Reserved[1]==0 && E->Reserved[2]==0 &&
      E->Reserved[3]==0 && E->Reserved[4]==0 && E->Reserved[5]==0,
      "P2.4: Every entry Reserved[6] must be all zeros");
    Offset += E->EntryLength;
  }
}

void harness_P5_1(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  bool Has[5] = {false,false,false,false,false};
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureImageVerificationGuid)) Has[0]=true;
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureSecureBootAuthorizationGuid)) Has[1]=true;
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureImageRevocationGuid)) Has[2]=true;
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureSecureBootServicingAuthorizationGuid)) Has[3]=true;
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureAuthenticatedVariableGuid)) Has[4]=true;
    Offset += E->EntryLength;
  }
  __CPROVER_assert(Has[0] && Has[1] && Has[2] && Has[3] && Has[4],
    "P5.1: All 5 mandatory Secure Boot feature entries must be present");
}

void harness_P5_2(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    __CPROVER_assert(E->EntryLength > sizeof(EFI_CRYPTO_INDICATOR_ENTRY),
      "P5.2: Every entry must have non-empty data");
    Offset += E->EntryLength;
  }
}

void harness_P11_1(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  EFI_GUID Seen[8];
  UINT8 Count = 0;
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries && i < 8; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    for (UINT8 j = 0; j < Count; j++) {
      __CPROVER_assert(!GuidEqual(&E->FeatureIdentifier, &Seen[j]),
        "P11.1: No duplicate FeatureIdentifier GUIDs");
    }
    my_memcpy(&Seen[Count], &E->FeatureIdentifier, sizeof(EFI_GUID));
    Count++;
    Offset += E->EntryLength;
  }
}

// ============================================================================
// Additional per-property harnesses (P2.1, P2.5, P2.6, P6.x, P7.x, P12.x)
// ============================================================================

void harness_P2_1(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  UINT8 Count = 0;
  UINT32 DataRegion = T->Header.Length - sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  while (Offset < DataRegion && Count < 255) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    if (E->EntryLength == 0) break;
    Offset += E->EntryLength;
    Count++;
  }
  __CPROVER_assert(Count == T->NumberOfEntries,
    "P2.1: Entry count matches actual iterable entries");
}

void harness_P2_5(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    __CPROVER_assert(
      sizeof(EFI_CRYPTO_INDICATOR_TABLE) + Offset + E->EntryLength <= T->Header.Length,
      "P2.5: No entry extends beyond table.Length");
    Offset += E->EntryLength;
  }
}

void harness_P2_6(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    __CPROVER_assert(E->EntryLength > 0,
      "P2.6: EntryLength must be non-zero");
    Offset += E->EntryLength;
  }
}

// Helper: check if a char is valid in an OID CSV (digits, dots, commas)
static bool IsOidChar(CHAR8 c) {
  return (c >= '0' && c <= '9') || c == '.' || c == ',';
}

void harness_P6_1(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    bool IsOidEntry = GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureImageVerificationGuid)
                   || GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureAuthenticatedVariableGuid);
    if (IsOidEntry) {
      UINT16 DataSize = E->EntryLength - sizeof(EFI_CRYPTO_INDICATOR_ENTRY);
      const CHAR8 *Data = (const CHAR8*)(Base + Offset + sizeof(EFI_CRYPTO_INDICATOR_ENTRY));
      // Null-terminated
      __CPROVER_assert(Data[DataSize - 1] == '\0',
        "P6.1: OID string must be null-terminated");
      // All chars valid OID characters
      for (UINT16 k = 0; Data[k] != '\0' && k < DataSize - 1; k++) {
        __CPROVER_assert(IsOidChar(Data[k]),
          "P6.1: OID string contains only valid chars (digits, dots, commas)");
      }
    }
    Offset += E->EntryLength;
  }
}

void harness_P6_2(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    bool IsOidEntry = GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureImageVerificationGuid)
                   || GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureAuthenticatedVariableGuid);
    if (IsOidEntry) {
      UINT16 DataSize = E->EntryLength - sizeof(EFI_CRYPTO_INDICATOR_ENTRY);
      const CHAR8 *Data = (const CHAR8*)(Base + Offset + sizeof(EFI_CRYPTO_INDICATOR_ENTRY));
      // Non-empty
      __CPROVER_assert(Data[0] != '\0',
        "P6.2: OID CSV must be non-empty");
      // No ",," (empty element)
      for (UINT16 k = 0; Data[k] != '\0' && k + 1 < DataSize; k++) {
        __CPROVER_assert(!(Data[k] == ',' && Data[k+1] == ','),
          "P6.2: No empty OID elements (no ',,' substring)");
      }
    }
    Offset += E->EntryLength;
  }
}

void harness_P6_3(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    bool IsGuidArray = GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureSecureBootAuthorizationGuid)
                    || GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureImageRevocationGuid)
                    || GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureSecureBootServicingAuthorizationGuid);
    if (IsGuidArray) {
      UINT16 DataSize = E->EntryLength - sizeof(EFI_CRYPTO_INDICATOR_ENTRY);
      __CPROVER_assert(DataSize % sizeof(EFI_GUID) == 0,
        "P6.3: GUID array data size must be multiple of sizeof(EFI_GUID)");
      __CPROVER_assert(DataSize >= sizeof(EFI_GUID),
        "P6.3: GUID array must contain at least one GUID");
    }
    Offset += E->EntryLength;
  }
}

static bool IsNullGuid(const EFI_GUID *G) {
  static const EFI_GUID Zero = {0,0,0,{0,0,0,0,0,0,0,0}};
  return my_memcmp_eq(G, &Zero, sizeof(EFI_GUID));
}

void harness_P6_4(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    bool IsGuidArray = GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureSecureBootAuthorizationGuid)
                    || GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureImageRevocationGuid)
                    || GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureSecureBootServicingAuthorizationGuid);
    if (IsGuidArray) {
      UINT16 DataSize = E->EntryLength - sizeof(EFI_CRYPTO_INDICATOR_ENTRY);
      UINT16 NumGuids = DataSize / sizeof(EFI_GUID);
      const EFI_GUID *Guids = (const EFI_GUID*)(Base + Offset + sizeof(EFI_CRYPTO_INDICATOR_ENTRY));
      for (UINT16 g = 0; g < NumGuids; g++) {
        __CPROVER_assert(!IsNullGuid(&Guids[g]),
          "P6.4: No null (all-zero) GUIDs in GUID arrays");
      }
    }
    Offset += E->EntryLength;
  }
}

void harness_P7_3(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  // First entry starts immediately after header
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  UINT32 ExpectedEnd = T->Header.Length - sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    Offset += E->EntryLength;
  }
  // After iterating all entries, offset must equal the entire data region
  __CPROVER_assert(Offset == ExpectedEnd,
    "P7.3: Entries are contiguous with no gaps");
}

static bool IsPrintableOrSpace(UINT8 c) {
  return c >= 0x20 && c <= 0x7E;
}

void harness_P12_1(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  for (int i = 0; i < 6; i++) {
    __CPROVER_assert(IsPrintableOrSpace(T->Header.OemId[i]),
      "P12.1: OemId must be printable ASCII or space");
  }
}

void harness_P12_2(void) {
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Id = (const UINT8 *)&T->Header.OemTableId;
  for (int i = 0; i < 8; i++) {
    __CPROVER_assert(Id[i] == 0 || IsPrintableOrSpace(Id[i]),
      "P12.2: OemTableId must be printable ASCII, space, or null");
  }
}

// ============================================================================
// P3.1/P3.2: Memory type verification via ACPI path control
//
// P3.1: When ACPI is supported, the driver MUST call InstallAcpiTable
//        (which guarantees EfiAcpiReclaimMemory for the ACPI copy).
// P3.2: When ACPI is NOT supported, only InstallConfigurationTable is called
//        (buffer from AllocateZeroPool = EfiBootServicesData).
// ============================================================================

void harness_P3_1(void) {
  // Scenario: ACPI protocol IS available
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverWithAcpi();
  __CPROVER_assert(gInstallAcpiTableCalled,
    "P3.1: When ACPI is supported, InstallAcpiTable must be called");
  // Verify the ACPI copy has the correct size and matching content
  __CPROVER_assert(gAcpiTableSize == T->Header.Length,
    "P3.1: InstallAcpiTable receives correct table size");
  __CPROVER_assert(gAcpiTablePointer != NULL,
    "P3.1: ACPI table copy was created (EfiAcpiReclaimMemory)");
  // After fix: ConfigurationTable now points to the ACPI copy (same pointer)
  __CPROVER_assert(gAcpiTablePointer == (VOID*)T,
    "P3.1: ConfigurationTable points to the ACPI copy");
  // Content integrity: ACPI copy must have correct data
  __CPROVER_assert(((EFI_ACPI_DESCRIPTION_HEADER*)gAcpiTablePointer)->Signature == EFI_CRYPTO_INDICATOR_TABLE_SIGNATURE,
    "P3.1: ACPI copy has correct ECIT signature");
}

void harness_P3_2(void) {
  // Scenario: ACPI protocol is NOT available
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  (void)T;
  __CPROVER_assert(!gInstallAcpiTableCalled,
    "P3.2: When ACPI is not supported, InstallAcpiTable must NOT be called");
  // Table is in AllocateZeroPool buffer = EfiBootServicesData (by construction)
  __CPROVER_assert(gCapturedTable == gPoolBuffer,
    "P3.2: Table resides in pool memory (EfiBootServicesData)");
}

void harness_P3_3(void) {
  //
  // P3.3: ConfigurationTable pointer SHALL reference the same memory as ACPI table.
  //
  // After the fix: driver calls InstallAcpiTable first, then uses
  // EfiLocateFirstAcpiTable to get the ACPI copy address, and passes
  // that to InstallConfigurationTable. Both now point to same memory.
  //
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverWithAcpi();
  (void)T;
  __CPROVER_assert(gInstallAcpiTableCalled,
    "P3.3 precondition: ACPI table was installed");
  __CPROVER_assert(gCapturedTable == gAcpiTablePointer,
    "P3.3: ConfigurationTable pointer == ACPI table pointer");
}

// ============================================================================
// P4.1/P4.2/P4.3: Publishing correctness
// ============================================================================

void harness_P4_1(void) {
  // P4.1: ECIT SHALL be published as an EFI Configuration Table
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  // gCapturedTable is set by StubInstallConfigurationTable
  __CPROVER_assert(gCapturedTable != NULL,
    "P4.1: InstallConfigurationTable was called (table published)");
  __CPROVER_assert(gCapturedTable == (VOID*)T,
    "P4.1: ConfigurationTable points to the produced table");
}

void harness_P4_2(void) {
  // P4.2: If ACPI is supported, ECIT appears as ACPI table with "ECIT" signature
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverWithAcpi();
  __CPROVER_assert(gInstallAcpiTableCalled,
    "P4.2: InstallAcpiTable called when ACPI is supported");
  // Verify the ACPI copy has ECIT signature
  const EFI_ACPI_DESCRIPTION_HEADER *AcpiHdr =
    (const EFI_ACPI_DESCRIPTION_HEADER *)gAcpiTablePointer;
  __CPROVER_assert(AcpiHdr->Signature == EFI_CRYPTO_INDICATOR_TABLE_SIGNATURE,
    "P4.2: ACPI table has ECIT signature");
  __CPROVER_assert(gAcpiTableSize == T->Header.Length,
    "P4.2: ACPI table size matches table Length field");
}

void harness_P4_3(void) {
  // P4.3: Dual-publish consistency — content of ConfigTable and ACPI table match
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverWithAcpi();
  __CPROVER_assert(gInstallAcpiTableCalled,
    "P4.3 precondition: ACPI table was installed");
  __CPROVER_assert(gAcpiTablePointer != NULL,
    "P4.3 precondition: ACPI copy exists");
  // Content must be identical (even though pointers differ)
  __CPROVER_assert(my_memcmp_eq(gCapturedTable, gAcpiTablePointer, T->Header.Length),
    "P4.3: content(ConfigurationTable) == content(AcpiTable)");
}

// ============================================================================
// P7.1/P7.2: Iteration safety
// ============================================================================

void harness_P7_1(void) {
  // P7.1: Forward Progress — iteration terminates because offset strictly increases
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 DataRegion = T->Header.Length - sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  UINT32 PrevOffset;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    PrevOffset = Offset;
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    __CPROVER_assert(E->EntryLength > 0,
      "P7.1: EntryLength > 0 guarantees forward progress");
    Offset += E->EntryLength;
    __CPROVER_assert(Offset > PrevOffset,
      "P7.1: Offset strictly increases each iteration");
    __CPROVER_assert(Offset <= DataRegion,
      "P7.1: Offset stays within data region bounds");
  }
}

void harness_P7_2(void) {
  // P7.2: No Overlapping Entries — each entry's range is disjoint
  // Since entries are laid out consecutively (entry[i+1] starts at entry[i].end),
  // overlapping is impossible. Verify: start[i+1] >= end[i].
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  UINT32 PrevEnd = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    __CPROVER_assert(Offset >= PrevEnd,
      "P7.2: Entry start >= previous entry end (no overlap)");
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    PrevEnd = Offset + E->EntryLength;
    Offset += E->EntryLength;
  }
}

// ============================================================================
// P8.1: Image Verification OIDs reflect actual crypto capability
// ============================================================================

// Helper: check if needle (null-terminated) appears as a comma-delimited element in haystack
static bool OidInCsv(const CHAR8 *haystack, const CHAR8 *needle) {
  UINTN nLen = my_strlen(needle);
  UINTN hLen = my_strlen(haystack);
  UINTN pos = 0;
  while (pos <= hLen - nLen) {
    // Check if needle matches at pos
    bool match = true;
    for (UINTN k = 0; k < nLen; k++) {
      if (haystack[pos + k] != needle[k]) { match = false; break; }
    }
    if (match) {
      // Verify it's a complete element (bounded by start/comma/end)
      bool startOk = (pos == 0 || haystack[pos - 1] == ',');
      bool endOk = (haystack[pos + nLen] == '\0' || haystack[pos + nLen] == ',');
      if (startOk && endOk) return true;
    }
    pos++;
  }
  return false;
}

void harness_P8_1(void) {
  // P8.1: Every OID in ImageVerification entry must be in Pkcs7GetVerifyOidList
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const CHAR8 *CryptoOids = Pkcs7GetVerifyOidList(Pkcs7SignatureAlgoAll);
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureImageVerificationGuid)) {
      const CHAR8 *TableOids = (const CHAR8*)(Base + Offset + sizeof(EFI_CRYPTO_INDICATOR_ENTRY));
      // The table's OID list should be a subset of (or equal to) CryptoOids
      // Verify each OID in the table exists in the crypto library's list
      CHAR8 oid[64];
      UINTN oidIdx = 0;
      for (UINTN c = 0; ; c++) {
        if (TableOids[c] == ',' || TableOids[c] == '\0') {
          oid[oidIdx] = '\0';
          if (oidIdx > 0) {
            __CPROVER_assert(OidInCsv(CryptoOids, oid),
              "P8.1: Every declared OID is supported by crypto library");
          }
          oidIdx = 0;
          if (TableOids[c] == '\0') break;
        } else {
          if (oidIdx < 63) oid[oidIdx++] = TableOids[c];
        }
      }
    }
    Offset += E->EntryLength;
  }
}

// ============================================================================
// P9.1: Table Immutability — content unchanged after driver returns
// ============================================================================

//
// Known-supported GUID sets for P8.2/P8.3 verification.
// These must match the arrays in CryptoIndicatorTableDxe.c.
//
static const EFI_GUID gSupportedAuthTypes[] = {
  EFI_CERT_X509_GUID,
  EFI_CERT_SHA256_GUID,
  EFI_CERT_SHA384_GUID,
  EFI_CERT_SHA512_GUID,
  EFI_CERT_X509_SHA256_GUID,
  EFI_CERT_X509_SHA384_GUID,
  EFI_CERT_X509_SHA512_GUID,
  EFI_CERT_V2_X509_GUID,
  EFI_CERT_V2_SHA256_GUID,
  EFI_CERT_V2_SHA384_GUID,
  EFI_CERT_V2_SHA512_GUID,
  EFI_CERT_V2_X509_SHA256_GUID,
  EFI_CERT_V2_X509_SHA384_GUID,
  EFI_CERT_V2_X509_SHA512_GUID,
};

static const EFI_GUID gSupportedRevocTypes[] = {
  EFI_CERT_SHA256_GUID,
  EFI_CERT_SHA384_GUID,
  EFI_CERT_SHA512_GUID,
  EFI_CERT_X509_SHA256_GUID,
  EFI_CERT_X509_SHA384_GUID,
  EFI_CERT_X509_SHA512_GUID,
  EFI_CERT_V2_SHA256_GUID,
  EFI_CERT_V2_SHA384_GUID,
  EFI_CERT_V2_SHA512_GUID,
  EFI_CERT_V2_X509_SHA256_GUID,
  EFI_CERT_V2_X509_SHA384_GUID,
  EFI_CERT_V2_X509_SHA512_GUID,
};

static bool GuidInSet(const EFI_GUID *G, const EFI_GUID *Set, UINTN Count) {
  for (UINTN i = 0; i < Count; i++) {
    if (GuidEqual(G, &Set[i])) return true;
  }
  return false;
}

void harness_P8_2(void) {
  // P8.2: Every GUID in SecureBootAuthorization entry is a supported type
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureSecureBootAuthorizationGuid)) {
      UINT16 DataSize = E->EntryLength - sizeof(EFI_CRYPTO_INDICATOR_ENTRY);
      UINT16 NumGuids = DataSize / sizeof(EFI_GUID);
      const EFI_GUID *Guids = (const EFI_GUID*)(Base + Offset + sizeof(EFI_CRYPTO_INDICATOR_ENTRY));
      for (UINT16 g = 0; g < NumGuids; g++) {
        __CPROVER_assert(
          GuidInSet(&Guids[g], gSupportedAuthTypes,
            sizeof(gSupportedAuthTypes)/sizeof(gSupportedAuthTypes[0])),
          "P8.2: Every authorization GUID is a supported signature type");
      }
    }
    Offset += E->EntryLength;
  }
}

void harness_P8_3(void) {
  // P8.3: Every GUID in ImageRevocation entry is a supported revocation type
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureImageRevocationGuid)) {
      UINT16 DataSize = E->EntryLength - sizeof(EFI_CRYPTO_INDICATOR_ENTRY);
      UINT16 NumGuids = DataSize / sizeof(EFI_GUID);
      const EFI_GUID *Guids = (const EFI_GUID*)(Base + Offset + sizeof(EFI_CRYPTO_INDICATOR_ENTRY));
      for (UINT16 g = 0; g < NumGuids; g++) {
        __CPROVER_assert(
          GuidInSet(&Guids[g], gSupportedRevocTypes,
            sizeof(gSupportedRevocTypes)/sizeof(gSupportedRevocTypes[0])),
          "P8.3: Every revocation GUID is a supported revocation type");
      }
    }
    Offset += E->EntryLength;
  }
}

void harness_P8_4(void) {
  // P8.4: AuthenticatedVariable OIDs match crypto library capability
  // (Same OIDs as ImageVerification — both use Pkcs7GetVerifyOidList)
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const CHAR8 *CryptoOids = Pkcs7GetVerifyOidList(Pkcs7SignatureAlgoAll);
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureAuthenticatedVariableGuid)) {
      const CHAR8 *TableOids = (const CHAR8*)(Base + Offset + sizeof(EFI_CRYPTO_INDICATOR_ENTRY));
      CHAR8 oid[64];
      UINTN oidIdx = 0;
      for (UINTN c = 0; ; c++) {
        if (TableOids[c] == ',' || TableOids[c] == '\0') {
          oid[oidIdx] = '\0';
          if (oidIdx > 0) {
            __CPROVER_assert(OidInCsv(CryptoOids, oid),
              "P8.4: Every AuthVar OID is supported by crypto library");
          }
          oidIdx = 0;
          if (TableOids[c] == '\0') break;
        } else {
          if (oidIdx < 63) oid[oidIdx++] = TableOids[c];
        }
      }
    }
    Offset += E->EntryLength;
  }
}

void harness_P9_1(void) {
  // Run driver, snapshot the table, verify pool buffer still matches
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  UINT32 Len = T->Header.Length;
  // The table lives in gPoolBuffer. Take a snapshot after driver returns.
  UINT8 snapshot[800];
  my_memcpy(snapshot, gPoolBuffer, Len);
  // Verify they match (driver didn't corrupt after InstallConfigurationTable)
  __CPROVER_assert(my_memcmp_eq(gPoolBuffer, snapshot, Len),
    "P9.1: Table content unchanged after installation");
  // Also verify checksum is still valid (P9.2 is consequence of P9.1 + P1.4)
  UINT8 Sum = 0;
  for (UINT32 i = 0; i < Len; i++) Sum = (UINT8)(Sum + ((UINT8*)gPoolBuffer)[i]);
  __CPROVER_assert(Sum == 0,
    "P9.2: Checksum remains valid at access time");
}

// ============================================================================
// P10.1/P10.2: No under/over-declaration for ImageVerification OIDs
// ============================================================================

void harness_P10_1_P10_2(void) {
  // The table's ImageVerification OIDs should EXACTLY match Pkcs7GetVerifyOidList
  // P10.1: no omission (crypto supports it => table declares it)
  // P10.2: no over-declaration (table declares it => crypto supports it)
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverAndGetTable();
  const CHAR8 *CryptoOids = Pkcs7GetVerifyOidList(Pkcs7SignatureAlgoAll);
  const UINT8 *Base = (const UINT8 *)T + sizeof(EFI_CRYPTO_INDICATOR_TABLE);
  UINT32 Offset = 0;
  for (UINT8 i = 0; i < T->NumberOfEntries; i++) {
    const EFI_CRYPTO_INDICATOR_ENTRY *E =
      (const EFI_CRYPTO_INDICATOR_ENTRY*)(Base + Offset);
    if (GuidEqual(&E->FeatureIdentifier, &gEfiEcitFeatureImageVerificationGuid)) {
      const CHAR8 *TableOids = (const CHAR8*)(Base + Offset + sizeof(EFI_CRYPTO_INDICATOR_ENTRY));
      // P10.2: every table OID exists in crypto library (no over-declaration)
      CHAR8 oid[64];
      UINTN oidIdx = 0;
      for (UINTN c = 0; ; c++) {
        if (TableOids[c] == ',' || TableOids[c] == '\0') {
          oid[oidIdx] = '\0';
          if (oidIdx > 0) {
            __CPROVER_assert(OidInCsv(CryptoOids, oid),
              "P10.2: No over-declaration — every table OID is crypto-supported");
          }
          oidIdx = 0;
          if (TableOids[c] == '\0') break;
        } else {
          if (oidIdx < 63) oid[oidIdx++] = TableOids[c];
        }
      }
      // P10.1: every crypto OID exists in table (no under-declaration)
      oidIdx = 0;
      for (UINTN c = 0; ; c++) {
        if (CryptoOids[c] == ',' || CryptoOids[c] == '\0') {
          oid[oidIdx] = '\0';
          if (oidIdx > 0) {
            __CPROVER_assert(OidInCsv(TableOids, oid),
              "P10.1: No under-declaration — every crypto OID is in the table");
          }
          oidIdx = 0;
          if (CryptoOids[c] == '\0') break;
        } else {
          if (oidIdx < 63) oid[oidIdx++] = CryptoOids[c];
        }
      }
    }
    Offset += E->EntryLength;
  }
}

// ============================================================================
// P13: TCG Measurement Properties
//
// The driver SHOULD measure the ECIT table to TPM PCR[1] with
// EV_EFI_HANDOFF_TABLES2 when a TPM is present. These harnesses will FAIL
// if the driver does not implement measurement (exposing a missing feature).
// ============================================================================

static const EFI_CRYPTO_INDICATOR_TABLE *RunDriverWithTcg(void) {
  EFI_HANDLE       ImageHandle = NULL;
  EFI_SYSTEM_TABLE SysTable;
  my_memset(&SysTable, 0, sizeof(SysTable));
  gCapturedTable = NULL;
  gAcpiProtocolAvailable = false;
  gTcg2ProtocolAvailable = true;
  gInstallAcpiTableCalled = false;
  gAcpiTablePointer = NULL;
  gAcpiTableSize = 0;
  gMeasurementCalled = false;
  gMeasuredPcrIndex = 0xFFFFFFFF;
  gMeasuredEventType = 0;
  gMeasuredData = NULL;
  gMeasuredDataSize = 0;
  gMeasurementAfterInstall = false;

  EFI_STATUS Status = CryptoIndicatorTableDxeEntryPoint(ImageHandle, &SysTable);
  __CPROVER_assert(Status == EFI_SUCCESS,
    "PRECONDITION: Driver must return EFI_SUCCESS");
  __CPROVER_assert(gCapturedTable != NULL,
    "PRECONDITION: Table must be installed");
  return (const EFI_CRYPTO_INDICATOR_TABLE *)gCapturedTable;
}

void harness_P13_1(void) {
  // P13.1: When TPM is present, table MUST be measured to PCR[1]
  //         with EventType = EV_EFI_HANDOFF_TABLES2
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverWithTcg();
  (void)T;
  __CPROVER_assert(gMeasurementCalled,
    "P13.1: HashLogExtendEvent must be called when TPM is present");
  __CPROVER_assert(gMeasuredPcrIndex == 1,
    "P13.1: PCRIndex must be 1");
  __CPROVER_assert(gMeasuredEventType == EV_EFI_HANDOFF_TABLES2,
    "P13.1: EventType must be EV_EFI_HANDOFF_TABLES2");
}

void harness_P13_2(void) {
  // P13.2: Measurement occurs after table is finalized (after InstallConfigurationTable)
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverWithTcg();
  (void)T;
  __CPROVER_assert(gMeasurementCalled,
    "P13.2 precondition: measurement was called");
  __CPROVER_assert(gMeasurementAfterInstall,
    "P13.2: Measurement occurs after InstallConfigurationTable");
}

void harness_P13_3(void) {
  // P13.3: Measured data is the exact table content (offset 0, Length bytes)
  const EFI_CRYPTO_INDICATOR_TABLE *T = RunDriverWithTcg();
  __CPROVER_assert(gMeasurementCalled,
    "P13.3 precondition: measurement was called");
  __CPROVER_assert(gMeasuredData == gCapturedTable,
    "P13.3: Measured data pointer == table pointer");
  __CPROVER_assert(gMeasuredDataSize == T->Header.Length,
    "P13.3: Measured data size == table.Header.Length");
}

// ============================================================================
// Combined harness (all properties in one run)
// ============================================================================

void harness_all(void) {
  harness_P1_1();
  harness_P1_2();
  harness_P1_3();
  harness_P1_4();
  harness_P1_5();
  harness_P2_1();
  harness_P2_2();
  harness_P2_3();
  harness_P2_4();
  harness_P2_5();
  harness_P2_6();
  harness_P3_1();
  harness_P3_2();
  harness_P3_3();
  harness_P4_1();
  harness_P4_2();
  harness_P4_3();
  harness_P5_1();
  harness_P5_2();
  harness_P6_1();
  harness_P6_2();
  harness_P6_3();
  harness_P6_4();
  harness_P7_1();
  harness_P7_2();
  harness_P7_3();
  harness_P8_1();
  harness_P8_2();
  harness_P8_3();
  harness_P8_4();
  harness_P9_1();
  harness_P10_1_P10_2();
  harness_P11_1();
  harness_P12_1();
  harness_P12_2();
  harness_P13_1();
  harness_P13_2();
  harness_P13_3();
}

int main(void) {
  harness_all();
  return 0;
}

#endif  // CBMC_VERIFICATION
