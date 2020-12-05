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

DEFINE FW_BASE_ADDRESS   = 0xFFF00000
DEFINE FW_SIZE           = 0x00100000
DEFINE FW_BLOCKS         = 0x100

DEFINE TDHOB_OFFSET                     =  0
DEFINE TDHOB_SIZE                       =  0x00001000
DEFINE TEMPSTACK_OFFSET                 =  $(TDHOB_OFFSET) + $(TDHOB_SIZE)
DEFINE TEMPSTACK_SIZE                   =  0x00002000
DEFINE TEMPHEAP_OFFSET                  =  $(TEMPSTACK_OFFSET) + $(TEMPSTACK_SIZE)
DEFINE TEMPHEAP_SIZE                    =  0x00010000

DEFINE TDMAILBOX_OFFSET                 =  $(TEMPHEAP_OFFSET) + $(TEMPHEAP_SIZE)
DEFINE TDMAILBOX_SIZE                   =  0x00001000

#DEFINE MAINFV_OFFSET                    =  $(TEMPHEAP_OFFSET) + $(TEMPHEAP_SIZE)
#DEFINE MAINFV_SIZE                      =  0x000ED000
DEFINE MAINFV_OFFSET                    =  0x00080000
DEFINE MAINFV_SIZE                      =  0x00080000

SET gUefiTdShimPkgTokenSpaceGuid.PcdBfvBase     = $(FW_BASE_ADDRESS) + $(MAINFV_OFFSET)
SET gUefiTdShimPkgTokenSpaceGuid.PcdBfvSize     = $(MAINFV_SIZE)
