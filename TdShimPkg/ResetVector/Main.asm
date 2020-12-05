;------------------------------------------------------------------------------
; @file
; Main routine of the pre-SEC code up through the jump into SEC
;
; Copyright (c) 2008 - 2020, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
;------------------------------------------------------------------------------


;%define INIT_REGISTER_TEST 

BITS    32

;
; Modified:  EBX, ECX, EDX, EBP, EDI, ESP
;
; @param[in,out]  RAX/EAX  0
; @param[in]      RFLAGS   2
; @param[in]      RCX      [31:0] TDINITVP - Untrusted Configuration
;                          [63:32] 0
; @param[in]      RDX      [31:0] VCPUID
;                          [63:32] 0
; @param[in]      RBX      [6:0] CPU supported GPA width
;                          [7:7] 5 level page table support
;                          [63:8] 0
; @param[in]      RSI      [31:0] VCPU_Index
;                          [63:32] 0
; @param[in]      RDI/EDI  0
; @param[in]      RBP/EBP  0
; @param[in/out]  R8       Same as RCX
; @param[out]     R9       [6:0] CPU supported GPA width
;                          [7:7] 5 level page table support
;                          [23:16] VCPUID
;                          [32:24] VCPU_Index
; @param[out]     RBP/EBP  Address of Boot Firmware Volume (BFV)
; @param[out]     DS       Selector allowing flat access to all addresses
; @param[out]     ES       Selector allowing flat access to all addresses
; @param[out]     FS       Selector allowing flat access to all addresses
; @param[out]     GS       Selector allowing flat access to all addresses
; @param[out]     SS       Selector allowing flat access to all addresses
;
; @return         None  This routine jumps to SEC and does not return
;
Main32:
    ; We need to preserve rdx and ebx information
    ; We are ok with rcx getting modified because copy is in r8, but will save in edi for now
    
%ifdef INIT_REGISTER_TEST
    mov         edx, 0x99999999  
    mov         ebx, 0xaaaaaaaa  
    ;mov         ecx, 0x88888888  
    ;mov         ecx, ADDR_OF(KvmTestHob)
%endif

    ; Save ecx in edi
    mov         edi, ecx

%ifdef SEAM_EMULATION
    ; This sets up ebx like seam module would do
    mov        eax, 0x07
    mov        ecx, 0
    cpuid
    and        ecx, 0x10000
    ; mov        ecx, 0x10000 ; use to force 5-level paging support
    shr        ecx, 9
    mov        esp, ecx

    mov        eax, 0x80000008
    cpuid
    mov        ebx, eax
    and        ebx, 0x3f       
    or         ebx, esp
%endif

    ; Save ebx to esp 
    mov         esp, ebx
    
%ifdef SEAM_EMULATION
    ; This sets up edx and ebx with vcpuid and vcpu_index like seam would do
    mov        eax, 0
    cpuid
    cmp        eax, 0bh
    jb         .no_x2_apic             ; CPUID level below CPUID_EXTENDED_TOPOLOGY

    mov        eax, 0bh
    xor        ecx, ecx
    cpuid
    test       ebx, 0ffffh
    jz         .no_x2_apic             ; CPUID.0BH:EBX[15:0] is zero

    ; Hack, vcpu index == to vcpuid
    mov        esi, edx
    ; Processor is x2APIC capable; 32-bit x2APIC ID is already in EDX
    jmp        .end_of_emulation

.no_x2_apic:
    ; Processor is not x2APIC capable, so get 8-bit APIC ID
    mov        eax, 1
    cpuid
    shr        ebx, 24
    mov        edx, ebx
    ; Hack, vcpu index == to vcpuid
    mov        esi, edx
.end_of_emulation:
%endif

    ; We need to store vcpuid/vcpu_index, we will use upper bits of ebx
    shl       esi, 16
    or        esp, esi

    ;
    ; Transition the processor from protected to 32-bit flat mode
    ;
    OneTimeCall ReloadFlat32

    ;
    ; Validate the Boot Firmware Volume (BFV)
    ;
    OneTimeCall Flat32ValidateBfv

    ;
    ; EBP - Start of BFV
    ;

    ;
    ; Search for the SEC entry point
    ;
    OneTimeCall Flat32SearchForSecEntryPoint

    ;
    ; ESI - SEC Core entry point
    ; EBP - Start of BFV
    ;

    ;
    ; Transition the processor from 32-bit flat mode to 64-bit flat mode
    ;
    OneTimeCall Transition32FlatTo64Flat

BITS    64

%ifdef INIT_REGISTER_TEST
    mov r8, rdi
%endif

    mov r9, rsp
    ;
    ; Some values were calculated in 32-bit mode.  Make sure the upper
    ; 32-bits of 64-bit registers are zero for these values.
    ;
    mov     rax, 0x00000000ffffffff
    and     rsi, rax
    and     rbp, rax
    and     rsp, rax

    ;
    ; RSI - SEC Core entry point
    ; RBP - Start of BFV
    ;

    ;
    ; Restore initial EAX value into the RAX register
    ;
    mov     rax, 0

    ;
    ; Jump to the 64-bit SEC entry point
    ;
    jmp     rsi
