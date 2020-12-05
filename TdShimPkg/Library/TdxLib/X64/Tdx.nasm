;------------------------------------------------------------------------------
;*
;*   Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
;*   This program and the accompanying materials
;*   are licensed and made available under the terms and conditions of the BSD License
;*   which accompanies this distribution.  The full text of the license may be found at
;*   http://opensource.org/licenses/bsd-license.php
;*
;*   THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
;*   WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
;*
;*
;------------------------------------------------------------------------------

DEFAULT REL
SECTION .text

%define TDVMCALL_EXPOSE_REGS_MASK       0xffec
%define TDVMCALL                        0x0
%define TDINFO                          0x1
%define TDEXTENDRTMR                    0x2
%define TDGETVEINFO                     0x3
%define TDREPORT                        0x4
%define TDSETCPUIDVE                    0x5
%define TDACCEPTPAGE                    0x6
%define EXIT_REASON_CPUID               0xa

%macro tdcall 0
%if (FixedPcdGet32 (PcdUseTdxEmulation) == 0)
    vmcall
%else
    db 0x66,0x0f,0x01,0xcc
%endif
%endmacro

%macro tdcall_push_regs 0
    push rbp
    mov  rbp, rsp
    push r15
    push r14
    push r13
    push r12
    push rbx
    push rsi
    push rdi
%endmacro

%macro tdcall_pop_regs 0
    pop rdi
    pop rsi
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15
    pop rbp
%endmacro

%define number_of_regs_pushed 8
%define number_of_parameters  4

; Keep these in sync for push_regs/pop_regs, code below uses them to find 5th or greater parameters
%define first_variable_on_stack_offset  (number_of_regs_pushed * 8) + (number_of_parameters * 8) + 8
%define second_variable_on_stack_offset (first_variable_on_stack_offset) + 8

%macro tdcall_regs_preamble 2
    mov rax, %1

    mov ecx, %2

    ; R10 = 0 (standard TDVMCALL)

    xor r10d, r10d

    ; Zero out unused (for standard TDVMCALL) registers to avoid leaking
    ; secrets to the VMM.
    
    xor ebx, ebx
    xor esi, esi
    xor edi, edi

    xor edx, edx
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
%endmacro

%macro tdcall_regs_postamble 0
    xor ebx, ebx
    xor esi, esi
    xor edi, edi

    xor ecx, ecx
    xor edx, edx
    xor r8d,  r8d
    xor r9d,  r9d
    xor r10d, r10d
    xor r11d, r11d
%endmacro

global ASM_PFX(TdVmCall_inb)
global ASM_PFX(TdVmCall_inw)
global ASM_PFX(TdVmCall_inl)

ASM_PFX(TdVmCall_inb):
        or ecx, 0x10000
        jmp tdvmcall_in
ASM_PFX(TdVmCall_inw):
        or ecx, 0x20000
        jmp tdvmcall_in
ASM_PFX(TdVmCall_inl):
        or ecx, 0x40000
tdvmcall_in:
        tdcall_push_regs

        push rsi
        push rdi
        push rdx
        push rcx

        ; R11 = EXIT_REASON_IO_INSTRUCTION
        mov r11d, 30

        ; size
        mov r12d, ecx
        shr r12d, 16 

        ; in 
        xor r13d, r13d

        ; port
        xor r14d, r14d
        mov r14w, cx

        ; unused
        xor r15d, r15d

        tdcall_regs_preamble TDVMCALL, TDVMCALL_EXPOSE_REGS_MASK

        tdcall

        ; Panic if TDCALL reports failure.
        test rax, rax
        jnz .panic

        ; Panic if TDVMCALL reports failure.
        test r10, r10
        jnz .panic

        mov eax, r11d
        tdcall_regs_postamble

        pop rcx
        pop rdx
        pop rdi
        pop rsi

        tdcall_pop_regs
        ret
.panic:
        ud2

global ASM_PFX(TdVmCall_outb)
global ASM_PFX(TdVmCall_outw)
global ASM_PFX(TdVmCall_outl)

ASM_PFX(TdVmCall_outb):
        or ecx, 0x10000
        jmp tdvmcall_out
ASM_PFX(TdVmCall_outw):
        or ecx, 0x20000
        jmp tdvmcall_out
ASM_PFX(TdVmCall_outl):
        or ecx, 0x40000
tdvmcall_out:
        tdcall_push_regs

        push rsi
        push rdi
        push rdx
        push rcx

        ; R11 = EXIT_REASON_IO_INSTRUCTION
        mov r11d, 30

        ; size
        mov r12d, ecx
        shr r12d, 16

        ; out
        mov r13d, 1

        ; port
        xor r14d, r14d
        mov r14w, cx

        ; value
        mov r15d, edx

        tdcall_regs_preamble TDVMCALL, TDVMCALL_EXPOSE_REGS_MASK
        tdcall

        ; Panic if TDCALL reports failure.
        test rax, rax
        jnz .panic

        ; Panic if TDVMCALL reports failure.
        test r10, r10
        jnz .panic

        tdcall_regs_postamble

        pop rcx
        pop rdx
        pop rdi
        pop rsi

        tdcall_pop_regs
        ret

.panic:
        ud2

;------------------------------------------------------------------------------
; 0   => RAX = TDCALL leaf
; M   => RCX = TDVMCALL register behavior
; 1   => R10 = standard vs. vendor
; RDI => R11 = TDVMCALL function / nr
; RSI =  R12 = p1
; RDX => R13 = p2
; RCX => R14 = p3
; R8  => R15 = p4

;  UINT64
;  EFIAPI
;  TdVmCall (
;    UINT64  Nr,  // Rcx
;    UINT64  P1,  // Rdx
;    UINT64  P2,  // R8
;    UINT64  P3,  // R9
;    UINT64  P4,  // rsp + 0x28 
;    UINT64  *Val // rsp + 0x30
;    )
global ASM_PFX(TdVmCall)
ASM_PFX(TdVmCall):
       tdcall_push_regs

       mov r11, rcx
       mov r12, rdx
       mov r13, r8
       mov r14, r9
       mov r15, [rsp + first_variable_on_stack_offset ]

       tdcall_regs_preamble TDVMCALL, TDVMCALL_EXPOSE_REGS_MASK

       tdcall

       ; Panic if TDCALL reports failure.
       test rax, rax
       jnz .no_return_data

       ; Propagate TDVMCALL success/failure to return value.
       mov rax, r10

       ; Retrieve the Val pointer.
       mov r9, [rsp + second_variable_on_stack_offset ]
       test r9, r9
       jz .no_return_data

       ; On success, propagate TDVMCALL output value to output param
       test rax, rax
       jnz .no_return_data
       mov [r9], r11
.no_return_data:
       tdcall_regs_postamble

       tdcall_pop_regs

       ret

global ASM_PFX(TdVmPanic)
ASM_PFX(TdVmPanic):
      ud2
      ret

;------------------------------------------------------------------------------
; 0   => RAX = TDCALL leaf
; M   => RCX = TDVMCALL register behavior
; 1   => R10 = standard vs. vendor
; RDI => R11 = TDVMCALL function / nr
; RSI =  R12 = p1
; RDX => R13 = p2
; RCX => R14 = p3
; R8  => R15 = p4

;  UINT64
;  EFIAPI
;  TdVmCall_cpuid (
;    UINT64  EaxIn,  // Rcx
;    UINT64  EcxIn,  // Rdx
;    UINT64  *Eax,  // R8
;    UINT64  *Ebx,  // R9
;    UINT64  *Ecx,  // rsp + 0x28 
;    UINT64  *Edx // rsp + 0x30
;    )
global ASM_PFX(TdVmCall_cpuid)
ASM_PFX(TdVmCall_cpuid):
       tdcall_push_regs

       mov r11, EXIT_REASON_CPUID
       mov r12, rcx
       mov r13, rdx

       tdcall_regs_preamble TDVMCALL, TDVMCALL_EXPOSE_REGS_MASK

       ; Save *eax and *ebx pointers
       push r9
       push r8

       tdcall

       ; Panic if TDCALL reports failure.
       test rax, rax
       jnz .panic

       ; Propagate TDVMCALL success/failure to return value.
       mov rax, r10

       ; Retrieve *eax
       pop r8
       test r8, r8
       jz .get_ebx_value
       mov [r8], r12

.get_ebx_value
       ; Retrieve *ebx
       pop r9
       test r9, r9
       jz .get_ecx_value
       mov [r9], r13

.get_ecx_value
       ; Retrieve *ecx
       mov r9, [rsp + first_variable_on_stack_offset ]
       test r9, r9
       jz .get_edx_value
       mov [r9], r14

.get_edx_value
       ; Retrieve *edx
       mov r9, [rsp + second_variable_on_stack_offset ]
       test r9, r9
       jz .no_return_data
       mov [r9], r15

.no_return_data:
       tdcall_regs_postamble

       tdcall_pop_regs

       ret

.panic:
       ud2


;------------------------------------------------------------------------------
; 1   => RAX = TDINFO leaf
; On success,
; RCX holds gpaw
; RDX hold tdinit attributes
; R8 holds vcpus info
; R9 holds current vcpu index
; R10 not used yet
; R11 not used yet

;  UINT64
;  EFIAPI
;  TdInfo (
;    UINT64  *Gpaw,  // Rcx
;    UINT64  *TdAttributes,  // Rdx
;    UINT64  *Vcpus,  // R8
;    UINT64  *VcpuIndex,  // R9
;    UINT64  *Dummy1,  // rsp + 0x28 
;    UINT64  *Dummy2 // rsp + 0x30
;    )
global ASM_PFX(TdInfo)
ASM_PFX(TdInfo):
       tdcall_push_regs

       mov rax, TDINFO

       ; save first 4 pointers to registers that aren't used by call
       mov r12, rcx
       mov r13, rdx
       mov r14, r8
       mov r15, r9

       tdcall

       ; Panic if TDCALL reports failure.
       test rax, rax
       jnz .panic

       ; Save rcx (gpaw) if caller passed pointer
       test r12, r12
       jz .get_tdattributes
       mov [r12], rcx
.get_tdattributes:

       ; Save rdx (tdattributes) if caller passed pointer
       test r13, r13
       jz .get_vcpus
       mov [r13], rdx
.get_vcpus:

       ; Save r8 (vcpus) if caller passed pointer
       test r14, r14
       jz .get_vcpus_index
       mov [r14], r8
.get_vcpus_index:

       ; Save r9 (vcpu index) if caller passed pointer
       test r15, r15
       jz .get_dummy1
       mov [r15], r9
.get_dummy1:

       mov r15, [rsp + first_variable_on_stack_offset ]
       ; Save r10 (dummy1) if caller passed pointer
       test r15, r15
       jz .get_dummy2
       mov [r15], r10
.get_dummy2:

       mov r15, [rsp +  second_variable_on_stack_offset]
       ; Save r11 (dummy2) if caller passed pointer
       test r15, r15
       jz .no_dummy2
       mov [r15], r11
.no_dummy2:

       tdcall_pop_regs
       ret
.panic:
       ud2

;  UINT64
;  EFIAPI
;  TdExtendRtmr (
;    UINT64  *Address,  // Rcx
;    UINT64  RegisterIndex  // Rdx
;    )
global ASM_PFX(TdExtendRtmr)
ASM_PFX(TdExtendRtmr):
       tdcall_push_regs

       mov rax, TDEXTENDRTMR

       tdcall

       tdcall_pop_regs
       ret

;  UINT64
;  EFIAPI
;  TdGetVeInfo (
;    UINT64  *ExitReason,  // Rcx
;    UINT64  *ExitQualification,  // Rdx
;    UINT64  *Gla  // R8
;    UINT64  *Gpa  // R9
;    UINT64  *InstructionInfo,  // rsp + 0x28 
;    )
global ASM_PFX(TdGetVeInfo)
ASM_PFX(TdGetVeInfo):
       tdcall_push_regs

       mov rax, TDGETVEINFO

       ; save first 4 pointers to registers that aren't used by call
       mov r12, rcx
       mov r13, rdx
       mov r14, r8
       mov r15, r9

       tdcall

       ; Panic if TDCALL reports failure.
       test rax, rax
       jnz .exit

       ; Save rcx (exitreason) if caller passed pointer
       test r12, r12
       jz .get_exit_qualification
       mov [r12], rcx
.get_exit_qualification:

       ; Save rdx (exit_qualification) if caller passed pointer
       test r13, r13
       jz .get_guest_linear_address
       mov [r13], rdx
.get_guest_linear_address:

       ; Save r8 (guest_linear_address) if caller passed pointer
       test r14, r14
       jz .get_guest_physical_address
       mov [r14], r8
.get_guest_physical_address:

       ; Save r9 (guest_physical_address) if caller passed pointer
       test r15, r15
       jz .get_instruction_info
       mov [r15], r9
.get_instruction_info:

       mov r15, [rsp + first_variable_on_stack_offset]
       ; Save r10 (instruction_info) if caller passed pointer
       test r15, r15
       jz .exit
       mov [r15], r10
.exit:
       tdcall_pop_regs
       ret

;  UINT64
;  EFIAPI
;  TdReport (
;    UINT64  Report,  // Rcx
;    UINT64  AdditionalData  // Rdx
;    )
global ASM_PFX(TdReport)
ASM_PFX(TdReport):
       tdcall_push_regs

       mov rax, TDREPORT

       mov r8, 0 ; report sub-type, must be 0

       tdcall

       tdcall_pop_regs
       ret

;  UINT64
;  EFIAPI
;  TdSetCpuidVe (
;    UINT64  Flags  // Rcx
;    )
global ASM_PFX(TdSetCpuidVe)
ASM_PFX(TdSetCpuidVe):
       tdcall_push_regs

       mov rax, TDSETCPUIDVE

       tdcall

       tdcall_pop_regs
       ret

;  UINT64
;  EFIAPI
;  TdAcceptPage (
;    UINT64  StartAddress  // Rcx
;    )
global ASM_PFX(TdAcceptPage)
ASM_PFX(TdAcceptPage):
       tdcall_push_regs

       mov rax, TDACCEPTPAGE
       tdcall

       tdcall_pop_regs
       ret
