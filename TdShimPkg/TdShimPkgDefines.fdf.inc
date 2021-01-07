## @file
#  FDF include file that defines the main macros and sets the dependent PCDs.
#
#  Copyright (C) 2014, Red Hat, Inc.
#  Copyright (c) 2006 - 2013, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

DEFINE BLOCK_SIZE        = 0x1000

#
# A firmware binary built with FD_SIZE_IN_KB=1024, and a firmware binary built
# with FD_SIZE_IN_KB=2048, use the same variable store layout.
#
# Setting FD_SIZE_IN_KB to 4096 results in a different (much larger) variable
# store structure that is incompatible with both of the above-mentioned
# firmware binaries.
#

DEFINE VARS_OFFSET        =  0x0000

DEFINE VARS_SIZE         = 0x70000
DEFINE VARS_BLOCKS       = 0x70
DEFINE VARS_LIVE_SIZE    = 0x36000
DEFINE VARS_SPARE_SIZE   = 0x37000

DEFINE MAIN_TDMAILBOX_OFFSET            = 0
DEFINE COMBINED_TDMAILBOX_OFFSET        =  $(VARS_SIZE) + $(MAIN_TDMAILBOX_OFFSET)
DEFINE TDMAILBOX_SIZE                   =  0x1000
DEFINE MAIN_TDHOB_OFFSET                =  $(MAIN_TDMAILBOX_OFFSET) + $(TDMAILBOX_SIZE)
DEFINE COMBINED_TDHOB_OFFSET            =  $(COMBINED_TDMAILBOX_OFFSET) + $(TDMAILBOX_SIZE)
DEFINE TDHOB_SIZE                       =  0x1000
DEFINE MAIN_TEMPSTACK_OFFSET            =  $(MAIN_TDHOB_OFFSET) + $(TDHOB_SIZE)
DEFINE COMBINED_TEMPSTACK_OFFSET        =  $(COMBINED_TDHOB_OFFSET) + $(TDHOB_SIZE)
DEFINE TEMPSTACK_SIZE                   =  0x2000
DEFINE MAIN_TEMPHEAP_OFFSET             =  $(MAIN_TEMPSTACK_OFFSET) + $(TEMPSTACK_SIZE)
DEFINE COMBINED_TEMPHEAP_OFFSET         =  $(COMBINED_TEMPSTACK_OFFSET) + $(TEMPSTACK_SIZE)
DEFINE TEMPHEAP_SIZE                    =  0x10000

DEFINE FW_BASE_ADDRESS   = 0xFFC00000
DEFINE FW_SIZE           = 0x00400000
DEFINE FW_BLOCKS         = 0x400

DEFINE COMBINED_PAYLOAD_OFFSET    = 0x084000
DEFINE PAYLOAD_SIZE               = 0x241000
DEFINE COMBINED_MAINFV_OFFSET     = 0x2C5000
DEFINE MAINFV_SIZE                = 0x13B000

SET gUefiTdShimPkgTokenSpaceGuid.PcdFdBaseAddress     = $(FW_BASE_ADDRESS)
SET gUefiTdShimPkgTokenSpaceGuid.PcdFdSize    = $(FW_SIZE)

SET gUefiTdShimPkgTokenSpaceGuid.PcdVarsBase          = $(FW_BASE_ADDRESS) + $(VARS_OFFSET)
SET gUefiTdShimPkgTokenSpaceGuid.PcdVarsSize          = $(VARS_LIVE_SIZE)
SET gUefiTdShimPkgTokenSpaceGuid.PcdVarsRawDataOffset = $(VARS_OFFSET)

SET gUefiTdShimPkgTokenSpaceGuid.PcdBfvBase           = $(FW_BASE_ADDRESS) + $(COMBINED_MAINFV_OFFSET)
SET gUefiTdShimPkgTokenSpaceGuid.PcdBfvSize           = $(MAINFV_SIZE)
SET gUefiTdShimPkgTokenSpaceGuid.PcdBfvRawDataOffset  = $(COMBINED_MAINFV_OFFSET)

SET gUefiTdShimPkgTokenSpaceGuid.PcdPayloadBase           = $(FW_BASE_ADDRESS) + $(COMBINED_PAYLOAD_OFFSET)
SET gUefiTdShimPkgTokenSpaceGuid.PcdPayloadSize           = $(PAYLOAD_SIZE)
SET gUefiTdShimPkgTokenSpaceGuid.PcdPayloadRawDataOffset  = $(COMBINED_PAYLOAD_OFFSET)
