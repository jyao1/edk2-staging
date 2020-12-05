#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/TdxLib.h>
#include <Library/BaseMemoryLib.h>
#include <IndustryStandard/Tdx.h>


/**
  #VE handler for cpuid
  @param  SystemContext     
**/
STATIC
UINT64
EFIAPI
TdxCpuIdHandler(
  IN EFI_SYSTEM_CONTEXT   SystemContext
  )
{
	UINT64 A, B, C, D;
  UINT64 Ret;

	Ret = TdVmCall_cpuid(SystemContext.SystemContextX64->Rax, 
    SystemContext.SystemContextX64->Rcx, 
    &A, &B, &C, &D);

	SystemContext.SystemContextX64->Rax = A;
	SystemContext.SystemContextX64->Rbx = B;
	SystemContext.SystemContextX64->Rcx = C;
	SystemContext.SystemContextX64->Rdx = D;
  
  return Ret;
}

#define REG_MASK(size) ((1ULL << ((size) * 8)) - 1)

/**
  #VE handler for i/o
  @param  SystemContext     
  @param  ExitQualification     
**/
STATIC
UINT64
EFIAPI
TdxIoHandler(
  IN EFI_SYSTEM_CONTEXT   SystemContext,
  IN UINT64               ExitQualification
  )
{
	BOOLEAN Write = (ExitQualification & 8) ? FALSE : TRUE;
	UINTN Size = (ExitQualification & 7) + 1;
	UINTN Port = (ExitQualification >> 16) & 0xffff;
	UINT64 Val = 0;

	/* I/O strings ops are unrolled at build time. */
	//ASSERT(ExitQualification & 0x10);

	if (Write) {
		Val = SystemContext.SystemContextX64->Rax & REG_MASK(Size);
    switch (Size) {
    case 1:
      TdVmCall_outb(Port, Val);
      break;
    case 2:
      TdVmCall_outw(Port, Val);
      break;
    case 4:
      TdVmCall_outl(Port, Val);
      break;
    }
	} else {
    switch (Size) {
    case 1:
      Val = TdVmCall_inb(Port);
      break;
    case 2:
      Val = TdVmCall_inw(Port);
      break;
    case 4:
      Val = TdVmCall_inl(Port);
      break;
    }
		/* The upper bits of *AX are preserved for 2 and 1 byte I/O. */
		if (Size < 4) {
			Val |= (SystemContext.SystemContextX64->Rax & ~REG_MASK(Size));
    }
		SystemContext.SystemContextX64->Rax = Val;
  }

  return 0;
}

/**
  #VE handler for rdmsr
  @param  SystemContext     
**/
STATIC
UINT64
EFIAPI
TdxReadMsrHandler(
  IN EFI_SYSTEM_CONTEXT   SystemContext
  )
{
	UINT64 Val;
	UINT64 Ret;

	Ret = TdVmCall(EXIT_REASON_MSR_READ, SystemContext.SystemContextX64->Rcx, 0, 0, 0, &Val);

	if (!Ret) {
		SystemContext.SystemContextX64->Rax = Val & 0xffffffff;
		SystemContext.SystemContextX64->Rdx = Val >> 32;
	}

  return Ret;
}

/**
  #VE handler for wrmsr
  @param  SystemContext     
**/
STATIC
UINT64
EFIAPI
TdxWriteMsrHandler(
  IN EFI_SYSTEM_CONTEXT   SystemContext
  )
{
	UINT64 Ret;
	UINT64 Val = (SystemContext.SystemContextX64->Rax & 0xffffffff) | 
    ((SystemContext.SystemContextX64->Rdx & 0xffffffff) << 32);

	Ret =  TdVmCall(EXIT_REASON_MSR_WRITE, SystemContext.SystemContextX64->Rcx, Val, 0, 0, NULL);

  return Ret;
}

STATIC
VOID
EFIAPI
TdxDecodeInstruction(
  IN UINT8 *Rip
)
{
	UINTN i;

	DEBUG ((EFI_D_INFO,"TDX: #TD[EPT] instruction (%p):", Rip));
	for (i = 0; i < 15; i++)
    DEBUG ((EFI_D_INFO, "%02x:", Rip[i]));
  DEBUG ((EFI_D_INFO, "\n"));
}

#define TDX_DECODER_BUG_ON(x) 				\
	if (x) {				\
		TdxDecodeInstruction(Rip);			\
    TdVmPanic(); \
	}

STATIC
UINT64 *
EFIAPI
GetRegFromContext(
  IN EFI_SYSTEM_CONTEXT   SystemContext,
  IN UINTN RegIndex
)
{
  switch(RegIndex) {
  case 0: return &SystemContext.SystemContextX64->Rax; break;
  case 1: return &SystemContext.SystemContextX64->Rcx; break;
  case 2: return &SystemContext.SystemContextX64->Rdx; break;
  case 3: return &SystemContext.SystemContextX64->Rbx; break;
  case 4: return &SystemContext.SystemContextX64->Rsp; break;
  case 5: return &SystemContext.SystemContextX64->Rbp; break;
  case 6: return &SystemContext.SystemContextX64->Rsi; break;
  case 7: return &SystemContext.SystemContextX64->Rdi; break;
  case 8: return &SystemContext.SystemContextX64->R8; break;
  case 9: return &SystemContext.SystemContextX64->R9; break;
  case 10: return &SystemContext.SystemContextX64->R10; break;
  case 11: return &SystemContext.SystemContextX64->R11; break;
  case 12: return &SystemContext.SystemContextX64->R12; break;
  case 13: return &SystemContext.SystemContextX64->R13; break;
  case 14: return &SystemContext.SystemContextX64->R14; break;
  case 15: return &SystemContext.SystemContextX64->R15; break;
  }
  return NULL;
}

/**
  #VE handler for mmio
  @param  SystemContext     
  @param  ExitQualification     
**/
STATIC
INTN
EFIAPI
TdxMmioHandler(
  IN EFI_SYSTEM_CONTEXT   SystemContext,
  IN UINT64               ExitQualification,
  IN UINT64               Gpa
  )
{
  UINT64 Status;
	INT32 i, op, mem_size, reg_size, modrm, mod, rm;
	BOOLEAN op_size, rex, rexw, rexr, rexx, rexb;
	UINT64 *reg;
	UINT8 *Rip = (UINT8 *)SystemContext.SystemContextX64->Rip;
	UINT64 val = 0;

	op_size = FALSE;
	rex = rexw = rexr = rexx = rexb = FALSE;
	for (i = 0; i < 15; i++) {
		if (Rip[i] == 0x66) {
			TDX_DECODER_BUG_ON(rex);
			op_size = TRUE;
		} else if (Rip[i] == 0x64 || Rip[i] == 0x65 || Rip[i] == 0x67) {
			TDX_DECODER_BUG_ON(rex);
		} else if (Rip[i] >= 0x40 && Rip[i] <= 0x4f) {
			TDX_DECODER_BUG_ON(rex);
			rex = TRUE;
			rexw = (Rip[i] & 0x8 ? 1 : 0);
			rexr = (Rip[i] & 0x4 ? 1 : 0);
			rexx = (Rip[i] & 0x2 ? 1 : 0);
			rexb = (Rip[i] & 0x1 ? 1 : 0);
		} else {
			break;
		}
	}

	/*
	 * We should have at least two more bytes, one for the opcode and one
	 * for the ModR/M byte.
	 */
	TDX_DECODER_BUG_ON(i > 13);

	op = Rip[i++];
	TDX_DECODER_BUG_ON(op != 0x88 && op != 0x89 && op != 0x8A && op != 0x8B && op != 0x0F && op != 0xC7);
	if (op == 0x0F) {
		/*
		 * Intentionally overwrite op, the allowed values won't conflict
		 * with the one byte opcodes.
		 */
		op = Rip[i++];
		TDX_DECODER_BUG_ON(op != 0xB6 && op != 0xB7);
	}

	if (op == 0x88 || op == 0x8A || op == 0xB6)
		mem_size = 1;
	else if (op == 0xB7)
		mem_size = 2;
	else
		mem_size = rexw ? 8 : op_size ? 2 : 4;

	/* Punt on AH/BH/CH/DH unless it shows up. */
	modrm = Rip[i++];
	TDX_DECODER_BUG_ON(mem_size == 1 && ((modrm >> 3) & 0x7) > 4 && !rex && op != 0xB6);
	reg = GetRegFromContext(SystemContext, ((modrm >> 3) & 0x7) | ((int)rexr << 3));
	TDX_DECODER_BUG_ON(!reg);

	mod = (modrm >> 6) & 0x3;
	rm = (modrm & 0x7);

	/* mod=3 means "MOV reg, reg", which should be impossible. */
	TDX_DECODER_BUG_ON(mod > 2);
	if (rm == 4)
		i++;	/* SIB byte */

	if (mod == 2 || (mod == 0 && rm == 5))
		i += 4;	/* DISP32 */
	else if (mod == 1)
		i++;	/* DISP8 */

	if (op == 0x88 || op == 0x89) {
		CopyMem((void *)&val, reg, mem_size);
	  Status = TdVmCall(EXIT_REASON_EPT_VIOLATION, mem_size, 1, Gpa, val, 0);
	} else if (op == 0xC7) {
		CopyMem((void *)&val, Rip + i, op_size ? 2 : 4);
	  Status = TdVmCall(EXIT_REASON_EPT_VIOLATION, mem_size, 1, Gpa, val, 0);
		i += op_size ? 2 : 4;
	} else {
		/*
		 * In 64-bit mode, 32-bit writes registers are zero extended to
		 * the full 64-bit register.  Hence 'MOVZX r[32/64], r/m16' is
		 * hardcoded to reg size 8, and the straight MOV case has a reg
		 * size of 8 in the 32-bit read case.
		 */
		if (op == 0xB6)
			reg_size = rexw ? 8 : op_size ? 2 : 4;
		else if (op == 0xB7)
			reg_size =  8;
		else
			reg_size = mem_size == 4 ? 8 : mem_size;

	  Status = TdVmCall(EXIT_REASON_EPT_VIOLATION, mem_size, 0, Gpa, 0, &val);

		ZeroMem(reg, reg_size);
		CopyMem(reg, (void *)&val, mem_size);
	}

	TDX_DECODER_BUG_ON(i > 15);
	SystemContext.SystemContextX64->Rip += i;

	return Status;
}

/**
  #VE handler
  @param  InterruptType     
  @param  SystemContext     
**/
VOID
EFIAPI
TdxVirtualizationExceptionHandler (
  IN EFI_EXCEPTION_TYPE   InterruptType,
  IN EFI_SYSTEM_CONTEXT   SystemContext
  )
{
    UINT64  ExitReason;
    UINT64  ExitQualification;
    UINT64  Gla;
    UINT64  Gpa;
    UINT64  InstructionInfo;
    UINT64  Status;
    BOOLEAN AdjustRip = TRUE;

    Status = TdGetVeInfo(&ExitReason,&ExitQualification, &Gla, &Gpa, &InstructionInfo);
    ASSERT(Status == 0);
    DEBUG((DEBUG_VERBOSE, "%a:%d: 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n", __func__, __LINE__, 
      ExitReason,ExitQualification, 
      Gla, Gpa, InstructionInfo));

    DEBUG((DEBUG_VERBOSE, "%a:%d:  rax 0x%llx rbx 0x%llx ecx 0x%llx rdx 0x%llx 0x%llx\n", __func__, __LINE__, 
      SystemContext.SystemContextX64->Rax,
      SystemContext.SystemContextX64->Rbx,
      SystemContext.SystemContextX64->Rcx,
      SystemContext.SystemContextX64->Rdx,
      0));
      
	  switch (ExitReason) {
	  case EXIT_REASON_CPUID:
		  Status = TdxCpuIdHandler(SystemContext);
		  break;
	  case EXIT_REASON_HLT:
      if (FixedPcdGetBool(PcdIgnoreVeHalt) == FALSE) {
		    Status = TdVmCall(EXIT_REASON_HLT, 0, 0, 0, 0, 0);
      }
		  break;
	  case EXIT_REASON_IO_INSTRUCTION:
		  Status = TdxIoHandler(SystemContext, ExitQualification);
		  break;
	  case EXIT_REASON_MSR_READ:
		  Status = TdxReadMsrHandler(SystemContext);
		  break;
	  case EXIT_REASON_MSR_WRITE:
		  Status = TdxWriteMsrHandler(SystemContext);
		  break;
	  case EXIT_REASON_EPT_VIOLATION:
      AdjustRip = FALSE;
		  Status = TdxMmioHandler(SystemContext, ExitQualification, Gpa);
		  break;
	  case EXIT_REASON_VMCALL:
	  case EXIT_REASON_MWAIT_INSTRUCTION:
	  case EXIT_REASON_MONITOR_INSTRUCTION:
	  case EXIT_REASON_WBINVD:
		  /* Handle as nops. */
		  break;
	  case EXIT_REASON_RDPMC:
	  default:
      DEBUG ((DEBUG_ERROR,
        "Unsupported #VE happened, ExitReasion is %d, ExitQualification = 0x%x.\n",
        ExitReason, ExitQualification));
      ASSERT(FALSE);
      CpuDeadLoop();
    }
	  if (Status) {
      DEBUG ((DEBUG_ERROR,
        "#VE Error (0x%x) returned from host, ExitReasion is %d, ExitQualification = 0x%x.\n",
        Status, ExitReason, ExitQualification));
      TdVmPanic();
    } else if (AdjustRip == TRUE) {
		  SystemContext.SystemContextX64->Rip += InstructionInfo & 0xffffffff;
    }
}
