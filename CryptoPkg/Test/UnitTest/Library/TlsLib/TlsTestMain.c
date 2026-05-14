/** @file
  Host-based entry point for TLS Handshake Unit Test.

  Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TlsTests.h"
#include <Library/PrintLib.h>

#define UNIT_TEST_NAME     "TLS Handshake Unit Test"
#define UNIT_TEST_VERSION  "1.0"

VOID
EFIAPI
ProcessLibraryConstructorList (
  VOID
  );

/**
  Standard POSIX C entry point for host based unit test execution.
**/
int
main (
  int   argc,
  char  *argv[]
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      TlsSuite;
  UINTN                       Index;
  CHAR8                       TestName[128];
  CHAR8                       TestId[128];

  ProcessLibraryConstructorList ();

  DEBUG ((DEBUG_INFO, "%a v%a\n", UNIT_TEST_NAME, UNIT_TEST_VERSION));

  Status = InitUnitTestFramework (
             &Framework,
             UNIT_TEST_NAME,
             gEfiCallerBaseName,
             UNIT_TEST_VERSION
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to init unit test framework: %r\n", Status));
    return Status;
  }

  Status = CreateUnitTestSuite (
             &TlsSuite,
             Framework,
             "TLS handshake tests",
             "CryptoPkg.TlsLib",
             NULL,
             NULL
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to create test suite: %r\n", Status));
    goto Done;
  }

  for (Index = 0; Index < mTlsTestCount; Index++) {
    AsciiSPrint (TestName, sizeof (TestName), "TestTlsHandshake(%a)", mTlsTestParams[Index].Description);
    AsciiSPrint (TestId, sizeof (TestId), "CryptoPkg.TlsLib.Handshake.%d", (int)Index);
    AddTestCase (TlsSuite, TestName, TestId, TestTlsHandshake, NULL, NULL, &mTlsTestParams[Index]);
  }

  Status = RunAllTestSuites (Framework);

Done:
  if (Framework) {
    FreeUnitTestFramework (Framework);
  }

  return Status;
}
