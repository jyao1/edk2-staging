/** @file
  Responsibility of this file is to load the DXE Core from a Firmware Volume.

Copyright (c) 2016 HP Development Company, L.P.
Copyright (c) 2006 - 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PeCoffGetEntryPointLib.h>

#include <Guid/MemoryTypeInformation.h>
#include <Guid/MemoryAllocationHob.h>

#include <Register/Intel/Cpuid.h>
#include <Library/PrePiLib.h>
#include "X64/PageTables.h"
#include <Library/ReportStatusCodeLib.h>

#include "TdShimIpl.h"

#define STACK_SIZE  0x20000

EFI_MEMORY_TYPE_INFORMATION mDefaultMemoryTypeInformation[] = {
  { EfiACPIMemoryNVS,       0x004 },
  { EfiACPIReclaimMemory,   0x008 },
  { EfiReservedMemoryType,  0x004 },
  { EfiRuntimeServicesData, 0x024 },
  { EfiRuntimeServicesCode, 0x030 },
  { EfiBootServicesCode,    0x180 },
  { EfiBootServicesData,    0xF00 },
  { EfiMaxMemoryType,       0x000 }
};


/**
   Transfers control to DxeCore.

   This function performs a CPU architecture specific operations to execute
   the entry point of DxeCore

   @param DxeCoreEntryPoint         The entry point of DxeCore.

**/
VOID
HandOffToDxeCore (
  IN EFI_PHYSICAL_ADDRESS   DxeCoreEntryPoint
  )
{
  VOID                            *BaseOfStack;
  VOID                            *TopOfStack;
  UINTN                           PageTables;

  //
  // Clear page 0 and mark it as allocated if NULL pointer detection is enabled.
  //
  if (IsNullDetectionEnabled ()) {
    ClearFirst4KPage (GetHobList());
    BuildMemoryAllocationHob (0, EFI_PAGES_TO_SIZE (1), EfiBootServicesData);
  }


  //
  // Allocate 128KB for the Stack
  //
  BaseOfStack = AllocatePages (EFI_SIZE_TO_PAGES (STACK_SIZE));
  ASSERT (BaseOfStack != NULL);

  //
  // Compute the top of the stack we were allocated. Pre-allocate a UINTN
  // for safety.
  //
  TopOfStack = (VOID *) ((UINTN) BaseOfStack + EFI_SIZE_TO_PAGES (STACK_SIZE) * EFI_PAGE_SIZE - CPU_STACK_ALIGNMENT);
  TopOfStack = ALIGN_POINTER (TopOfStack, CPU_STACK_ALIGNMENT);

  PageTables = 0;
  if (FeaturePcdGet (PcdDxeIplBuildPageTables)) {
    //
    // Create page table and save PageMapLevel4 to CR3
    //
    PageTables = CreateIdentityMappingPageTables ((EFI_PHYSICAL_ADDRESS) (UINTN) BaseOfStack, 
      STACK_SIZE);
  } else {
    //
    // Set NX for stack feature also require PcdDxeIplBuildPageTables be TRUE
    // for the DxeIpl and the DxeCore are both X64.
    //
    ASSERT (PcdGetBool (PcdSetNxForStack) == FALSE);
    ASSERT (PcdGetBool (PcdCpuStackGuard) == FALSE);
  }

  if (FeaturePcdGet (PcdDxeIplBuildPageTables)) {
    AsmWriteCr3 (PageTables);
  }

  //
  // Update the contents of BSP stack HOB to reflect the real stack info passed to DxeCore.
  //
  UpdateStackHob ((EFI_PHYSICAL_ADDRESS)(UINTN) BaseOfStack, STACK_SIZE);

  //
  // Transfer the control to the entry point of DxeCore.
  //
  SwitchStack (
    (SWITCH_STACK_ENTRY_POINT)(UINTN)DxeCoreEntryPoint,
    GetHobList(),
    NULL,
    TopOfStack
    );
}

/**
  Locates a section within a series of sections
  with the specified section type.

  The Instance parameter indicates which instance of the section
  type to return. (0 is first instance, 1 is second...)

  @param[in]   Sections        The sections to search
  @param[in]   SizeOfSections  Total size of all sections
  @param[in]   SectionType     The section type to locate
  @param[in]   Instance        The section instance number
  @param[out]  FoundSection    The FFS section if found

  @retval EFI_SUCCESS           The file and section was found
  @retval EFI_NOT_FOUND         The file and section was not found
  @retval EFI_VOLUME_CORRUPTED  The firmware volume was corrupted

**/
EFI_STATUS
FindFfsSectionInstance (
  IN  VOID                             *Sections,
  IN  UINTN                            SizeOfSections,
  IN  EFI_SECTION_TYPE                 SectionType,
  IN  UINTN                            Instance,
  OUT EFI_COMMON_SECTION_HEADER        **FoundSection
  )
{
  EFI_PHYSICAL_ADDRESS        CurrentAddress;
  UINT32                      Size;
  EFI_PHYSICAL_ADDRESS        EndOfSections;
  EFI_COMMON_SECTION_HEADER   *Section;
  EFI_PHYSICAL_ADDRESS        EndOfSection;

  //
  // Loop through the FFS file sections within the PEI Core FFS file
  //
  EndOfSection = (EFI_PHYSICAL_ADDRESS)(UINTN) Sections;
  EndOfSections = EndOfSection + SizeOfSections;
  for (;;) {
    if (EndOfSection == EndOfSections) {
      break;
    }
    CurrentAddress = (EndOfSection + 3) & ~(3ULL);
    if (CurrentAddress >= EndOfSections) {
      return EFI_VOLUME_CORRUPTED;
    }

    Section = (EFI_COMMON_SECTION_HEADER*)(UINTN) CurrentAddress;

    Size = SECTION_SIZE (Section);
    if (Size < sizeof (*Section)) {
      return EFI_VOLUME_CORRUPTED;
    }

    EndOfSection = CurrentAddress + Size;
    if (EndOfSection > EndOfSections) {
      return EFI_VOLUME_CORRUPTED;
    }

    //
    // Look for the requested section type
    //
    if (Section->Type == SectionType) {
      if (Instance == 0) {
        *FoundSection = Section;
        return EFI_SUCCESS;
      } else {
        Instance--;
      }
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Locates a section within a series of sections
  with the specified section type.

  @param[in]   Sections        The sections to search
  @param[in]   SizeOfSections  Total size of all sections
  @param[in]   SectionType     The section type to locate
  @param[out]  FoundSection    The FFS section if found

  @retval EFI_SUCCESS           The file and section was found
  @retval EFI_NOT_FOUND         The file and section was not found
  @retval EFI_VOLUME_CORRUPTED  The firmware volume was corrupted

**/
EFI_STATUS
FindFfsSectionInSections (
  IN  VOID                             *Sections,
  IN  UINTN                            SizeOfSections,
  IN  EFI_SECTION_TYPE                 SectionType,
  OUT EFI_COMMON_SECTION_HEADER        **FoundSection
  )
{
  return FindFfsSectionInstance (
           Sections,
           SizeOfSections,
           SectionType,
           0,
           FoundSection
           );
}

/**
  Locates a FFS file with the specified file type and a section
  within that file with the specified section type.

  @param[in]   Fv            The firmware volume to search
  @param[in]   FileType      The file type to locate
  @param[in]   SectionType   The section type to locate
  @param[out]  FoundSection  The FFS section if found

  @retval EFI_SUCCESS           The file and section was found
  @retval EFI_NOT_FOUND         The file and section was not found
  @retval EFI_VOLUME_CORRUPTED  The firmware volume was corrupted

**/
EFI_STATUS
FindFfsFileAndSection (
  IN  EFI_FIRMWARE_VOLUME_HEADER       *Fv,
  IN  EFI_FV_FILETYPE                  FileType,
  IN  EFI_SECTION_TYPE                 SectionType,
  OUT EFI_COMMON_SECTION_HEADER        **FoundSection
  )
{
  EFI_STATUS                  Status;
  EFI_PHYSICAL_ADDRESS        CurrentAddress;
  EFI_PHYSICAL_ADDRESS        EndOfFirmwareVolume;
  EFI_FFS_FILE_HEADER         *File;
  UINT32                      Size;
  EFI_PHYSICAL_ADDRESS        EndOfFile;

  if (Fv->Signature != EFI_FVH_SIGNATURE) {
    DEBUG ((EFI_D_ERROR, "FV at %p does not have FV header signature\n", Fv));
    return EFI_VOLUME_CORRUPTED;
  }

  CurrentAddress = (EFI_PHYSICAL_ADDRESS)(UINTN) Fv;
  EndOfFirmwareVolume = CurrentAddress + Fv->FvLength;

  //
  // Loop through the FFS files in the Boot Firmware Volume
  //
  for (EndOfFile = CurrentAddress + Fv->HeaderLength; ; ) {

    CurrentAddress = (EndOfFile + 7) & ~(7ULL);
    if (CurrentAddress > EndOfFirmwareVolume) {
      return EFI_VOLUME_CORRUPTED;
    }

    File = (EFI_FFS_FILE_HEADER*)(UINTN) CurrentAddress;
    Size = FFS_FILE_SIZE (File);
    if (Size < (sizeof (*File) + sizeof (EFI_COMMON_SECTION_HEADER))) {
      return EFI_VOLUME_CORRUPTED;
    }

    EndOfFile = CurrentAddress + Size;
    if (EndOfFile > EndOfFirmwareVolume) {
      return EFI_VOLUME_CORRUPTED;
    }

    //
    // Look for the request file type
    //
    if (File->Type != FileType) {
      continue;
    }

    Status = FindFfsSectionInSections (
               (VOID*) (File + 1),
               (UINTN) EndOfFile - (UINTN) (File + 1),
               SectionType,
               FoundSection
               );
    if (!EFI_ERROR (Status) || (Status == EFI_VOLUME_CORRUPTED)) {
      return Status;
    }
  }
}



EFI_STATUS
FindHypervisorFwImageBaseInFv (
  IN  EFI_FIRMWARE_VOLUME_HEADER        *Fv,
  OUT  EFI_PHYSICAL_ADDRESS             *HypervisorFwImageBase
  )
{
  EFI_STATUS                  Status;
  EFI_COMMON_SECTION_HEADER   *Section;

  Status = FindFfsFileAndSection (
             Fv,
             EFI_FV_FILETYPE_DXE_CORE,
             EFI_SECTION_PE32,
             &Section
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Unable to find Hypervisor FW image\n"));
    return Status;
  }

  *HypervisorFwImageBase = (EFI_PHYSICAL_ADDRESS)(UINTN)(Section + 1);
  return EFI_SUCCESS;
}

/*
  Find and return Hypervisor FW entry point.
**/
VOID
FindAndReportEntryPoints (
  IN  EFI_FIRMWARE_VOLUME_HEADER       *FirmwareVolumePtr,
  OUT UINTN                            *HypervisorFwEntryPoint,
  OUT UINTN                            *BaseAddress
  )
{
  EFI_STATUS                       Status;
  VOID                             *BaseHypervisorFw;
  EFI_PHYSICAL_ADDRESS             HypervisorFwImageBase;
  PE_COFF_LOADER_IMAGE_CONTEXT     ImageContext;
  UINTN                            Pages;

  *HypervisorFwEntryPoint = 0;
  FindHypervisorFwImageBaseInFv (FirmwareVolumePtr, &HypervisorFwImageBase);

  if (*(UINT16 *)(UINTN)HypervisorFwImageBase == EFI_IMAGE_DOS_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "PE FW Image\n"));
    ImageContext.Handle = (VOID *)(UINTN)HypervisorFwImageBase;
    ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;
    Status = PeCoffLoaderGetImageInfo(&ImageContext);
    if (ImageContext.SectionAlignment > EFI_PAGE_SIZE) {
      Pages = EFI_SIZE_TO_PAGES ((UINTN) (ImageContext.ImageSize + ImageContext.SectionAlignment));
    } else {
      Pages = EFI_SIZE_TO_PAGES ((UINTN) ImageContext.ImageSize);
    }

    BaseHypervisorFw = AllocatePages (Pages);
    *BaseAddress = (UINTN)BaseHypervisorFw;
  
    ImageContext.ImageAddress = (PHYSICAL_ADDRESS)(UINTN)BaseHypervisorFw;
    ImageContext.ImageAddress += ImageContext.SectionAlignment -1 ;
    ImageContext.ImageAddress &= ~((UINTN)ImageContext.SectionAlignment -1);
    Status = PeCoffLoaderLoadImage(&ImageContext);
    ASSERT_EFI_ERROR(Status);
    Status = PeCoffLoaderRelocateImage(&ImageContext);
    ASSERT_EFI_ERROR(Status);
    Status = PeCoffLoaderGetEntryPoint ((VOID *) (UINTN) ImageContext.ImageAddress, (VOID**) HypervisorFwEntryPoint);
    ASSERT_EFI_ERROR(Status);

    BuildModuleHob (
      &gZeroGuid,
      (EFI_PHYSICAL_ADDRESS)(UINTN)BaseHypervisorFw,
      EFI_PAGES_TO_SIZE(Pages),
      (EFI_PHYSICAL_ADDRESS)(UINTN)HypervisorFwEntryPoint
      );

  } else {
    DEBUG ((DEBUG_ERROR, "Unknown FW Image\n"));
    CpuDeadLoop();
  }
}

/**
   This function finds DXE Core in the firmware volume and transfer the control to
   DXE core.

   @return EFI_SUCCESS              DXE core was successfully loaded.
   @return EFI_OUT_OF_RESOURCES     There are not enough resources to load DXE core.

**/
EFI_STATUS
EFIAPI
DxeLoadCore (
  IN  EFI_FIRMWARE_VOLUME_HEADER       *FirmwareVolumePtr
  )
{
  UINTN                      DxeCoreEntryPoint;
  UINTN                      DxeCoreAddress;

  //
  // Create Memory Type Information HOB
  //
  BuildGuidDataHob (
    &gEfiMemoryTypeInformationGuid,
    mDefaultMemoryTypeInformation,
    sizeof(mDefaultMemoryTypeInformation)
    );

  FindAndReportEntryPoints(FirmwareVolumePtr, &DxeCoreEntryPoint, &DxeCoreAddress);

  DEBUG ((DEBUG_INFO | DEBUG_LOAD, "Loading DXE CORE at 0x%11p EntryPoint=0x%11p\n", 
    (VOID *)(UINTN)DxeCoreAddress, FUNCTION_ENTRY_POINT (DxeCoreEntryPoint)));

  //
  // Transfer control to the DXE Core
  // The hand off state is simply a pointer to the HOB list
  //
  HandOffToDxeCore (DxeCoreEntryPoint);
  //
  // If we get here, then the DXE Core returned.  This is an error
  // DxeCore should not return.
  //
  ASSERT (FALSE);
  CpuDeadLoop ();

  return EFI_OUT_OF_RESOURCES;
}


