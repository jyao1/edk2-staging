/** @file
  Processor or Compiler specific defines and types x64 (Intel 64, AMD64).

  Copyright (c) 2006 - 2020, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials                          
  are licensed and made available under the terms and conditions of the BSD License         
  which accompanies this distribution.  The full text of the license may be found at        
  http://opensource.org/licenses/bsd-license.php                                            

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

**/

#ifndef _TDX_H_
#define _TDX_H_

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2

#define EXIT_REASON_PENDING_INTERRUPT   7
#define EXIT_REASON_NMI_WINDOW          8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMOFF               26
#define EXIT_REASON_VMON                27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_STATE       33
#define EXIT_REASON_MSR_LOAD_FAIL       34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_EOI_INDUCED         45
#define EXIT_REASON_GDTR_IDTR           46
#define EXIT_REASON_LDTR_TR             47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_PREEMPTION_TIMER    52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_RDRAND              57
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_VMFUNC              59
#define EXIT_REASON_ENCLS               60
#define EXIT_REASON_RDSEED              61
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64

// TDCALL API Function Completion Status Codes
#define TDX_EXIT_REASON_SUCCESS                     0x0000000000000000
#define TDX_EXIT_REASON_PAGE_ALREADY_ACCEPTED       0x00000B0A00000000
#define TDX_EXIT_REASON_OPERAND_INVALID             0xC000010000000000
#define TDX_EXIT_REASON_OPERAND_BUSY                0x8000020000000000

#define TDCALL_TDVMCALL                 0
#define TDCALL_TDINFO                   1
#define TDCALL_TDEXTENDRTMR             2
#define TDCALL_TDGETVEINFO              3
#define TDCALL_TDREPORT                 4
#define TDCALL_TDSETCPUIDVE             5
#define TDCALL_TDACCEPTPAGE             6

#define TDVMCALL_MAPGPA                 0x10001

#define TDINFO_NUM_VCPUS(X) ((X) & 0xffffffff)
#define TDINFO_MAX_VCPUS(X) (((X) >> 32) & 0xffffffff)
#define TDINFO_VCPUS_INDEX(X) ((X) & 0xffffffff)
#define TDINFO_GPAW(X) ((X) & 0x3f)

#pragma pack(1)
/* data structure used in TDREPORT_STRUCT */
typedef struct{
  UINT8         type;
  UINT8         subtype;
  UINT8         version;
  UINT8         rsvd;
}TD_REPORT_TYPE;

typedef struct{
  TD_REPORT_TYPE   report_type;
  UINT8            rsvd1[12];
  UINT8            cpu_svn[16];
  UINT8            tee_tcb_info_hash[48];
  UINT8            tee_info_hash[48];
  UINT8            report_data[64];
  UINT8            rsvd2[32];
  UINT8            mac[32];
}REPORTMACSTRUCT;

typedef struct{
  UINT8         seam[2];
  UINT8         rsvd[14];
}TEE_TCB_SVN;

typedef struct{
  UINT8         valid[8];
  TEE_TCB_SVN   tee_tcb_svn;
  UINT8         mrseam[48];
  UINT8         mrsignerseam[48];
  UINT8         attributes[8];
  UINT8         rsvd[111];
}TEE_TCB_INFO;

typedef struct{
  UINT8         attributes[8];
  UINT8         xfam[8];
  UINT8         mrtd[48];
  UINT8         mrconfigid[48];
  UINT8         mrowner[48];
  UINT8         mrownerconfig[48];
  UINT8         rtmrs[4][48];
  UINT8         rsvd[112];
}TDINFO;

typedef struct{
  REPORTMACSTRUCT   report_mac_struct;
  TEE_TCB_INFO      tee_tcb_info;
  UINT8             rsvd[17];
  TDINFO            tdinfo;
}TDREPORT_STRUCT;

#pragma pack()

#endif

