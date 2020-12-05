/** @file
  Linux Boot Parameter

  https://www.kernel.org/doc/Documentation/x86/boot.txt
  https://www.kernel.org/doc/Documentation/x86/zero-page.txt

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _LINUX_BOOT_PARAMETER_H_
#define _LINUX_BOOT_PARAMETER_H_

/*

Offset	Proto	Name		Meaning
/Size

000/040	ALL	screen_info	Text mode or frame buffer information
				(struct screen_info)
040/014	ALL	apm_bios_info	APM BIOS information (struct apm_bios_info)
058/008	ALL	tboot_addr      Physical address of tboot shared page
060/010	ALL	ist_info	Intel SpeedStep (IST) BIOS support information
				(struct ist_info)
080/010	ALL	hd0_info	hd0 disk parameter, OBSOLETE!!
090/010	ALL	hd1_info	hd1 disk parameter, OBSOLETE!!
0A0/010	ALL	sys_desc_table	System description table (struct sys_desc_table),
				OBSOLETE!!
0B0/010	ALL	olpc_ofw_header	OLPC's OpenFirmware CIF and friends
0C0/004	ALL	ext_ramdisk_image ramdisk_image high 32bits
0C4/004	ALL	ext_ramdisk_size  ramdisk_size high 32bits
0C8/004	ALL	ext_cmd_line_ptr  cmd_line_ptr high 32bits
140/080	ALL	edid_info	Video mode setup (struct edid_info)
1C0/020	ALL	efi_info	EFI 32 information (struct efi_info)
1E0/004	ALL	alt_mem_k	Alternative mem check, in KB
1E4/004	ALL	scratch		Scratch field for the kernel setup code
1E8/001	ALL	e820_entries	Number of entries in e820_table (below)
1E9/001	ALL	eddbuf_entries	Number of entries in eddbuf (below)
1EA/001	ALL	edd_mbr_sig_buf_entries	Number of entries in edd_mbr_sig_buffer
				(below)
1EB/001	ALL     kbd_status      Numlock is enabled
1EC/001	ALL     secure_boot	Secure boot is enabled in the firmware
1EF/001	ALL	sentinel	Used to detect broken bootloaders
290/040	ALL	edd_mbr_sig_buffer EDD MBR signatures
2D0/A00	ALL	e820_table	E820 memory map table
				(array of struct e820_entry)
D00/1EC	ALL	eddbuf		EDD data (array of struct edd_info)

*/
typedef struct {
  UINT8  Buffer[0x1000];
} LINUX_BOOT_PARAMETER;

#define LINUX_BOOT_PARAMETER_E820_ENTRY_NUM_OFFSET  0x1E8
#define LINUX_BOOT_PARAMETER_E820_ENTRY_OFFSET      0x2D0
#define LINUX_BOOT_PARAMETER_E820_ENTRY_MAX_SIZE    0xA00

/*

Offset	Proto	Name		Meaning
/Size

01F1/1	ALL(1	setup_sects	The size of the setup in sectors
01F2/2	ALL	root_flags	If set, the root is mounted readonly
01F4/4	2.04+(2	syssize		The size of the 32-bit code in 16-byte paras
01F8/2	ALL	ram_size	DO NOT USE - for bootsect.S use only
01FA/2	ALL	vid_mode	Video mode control
01FC/2	ALL	root_dev	Default root device number
01FE/2	ALL	boot_flag	0xAA55 magic number
0200/2	2.00+	jump		Jump instruction
0202/4	2.00+	header		Magic signature "HdrS"
0206/2	2.00+	version		Boot protocol version supported
0208/4	2.00+	realmode_swtch	Boot loader hook (see below)
020C/2	2.00+	start_sys_seg	The load-low segment (0x1000) (obsolete)
020E/2	2.00+	kernel_version	Pointer to kernel version string
0210/1	2.00+	type_of_loader	Boot loader identifier
0211/1	2.00+	loadflags	Boot protocol option flags
0212/2	2.00+	setup_move_size	Move to high memory size (used with hooks)
0214/4	2.00+	code32_start	Boot loader hook (see below)
0218/4	2.00+	ramdisk_image	initrd load address (set by boot loader)
021C/4	2.00+	ramdisk_size	initrd size (set by boot loader)
0220/4	2.00+	bootsect_kludge	DO NOT USE - for bootsect.S use only
0224/2	2.01+	heap_end_ptr	Free memory after setup end
0226/1	2.02+(3 ext_loader_ver	Extended boot loader version
0227/1	2.02+(3	ext_loader_type	Extended boot loader ID
0228/4	2.02+	cmd_line_ptr	32-bit pointer to the kernel command line
022C/4	2.03+	initrd_addr_max	Highest legal initrd address
0230/4	2.05+	kernel_alignment Physical addr alignment required for kernel
0234/1	2.05+	relocatable_kernel Whether kernel is relocatable or not
0235/1	2.10+	min_alignment	Minimum alignment, as a power of two
0236/2	2.12+	xloadflags	Boot protocol option flags
0238/4	2.06+	cmdline_size	Maximum size of the kernel command line
023C/4	2.07+	hardware_subarch Hardware subarchitecture
0240/8	2.07+	hardware_subarch_data Subarchitecture-specific data
0248/4	2.08+	payload_offset	Offset of kernel payload
024C/4	2.08+	payload_length	Length of kernel payload
0250/8	2.09+	setup_data	64-bit physical pointer to linked list
				of struct setup_data
0258/8	2.10+	pref_address	Preferred loading address
0260/4	2.10+	init_size	Linear memory required during initialization
0264/4	2.11+	handover_offset	Offset of handover entry point

*/

#define LINUX_BOOT_PARAMETER_SETUP_HEADER_MAGIC_OFFSET         0x202
#define LINUX_BOOT_PARAMETER_SETUP_HEADER_MAGIC                0x53726448

#define LINUX_BOOT_PARAMETER_SETUP_HEADER_VERSION_OFFSET       0x206

//
// the setup header at offset 0x01f1 of kernel image on should be
// loaded into struct boot_params and examined.
//
#define LINUX_BOOT_PARAMETER_SETUP_HEADER_OFFSET         0x1F1

//
// The end of setup header can be calculated as follows:
//	0x0202 + byte value at offset 0x0201
//
#define LINUX_BOOT_PARAMETER_SETUP_HEADER_SIZE_OFFSET    0x201

//
// The boot loader *must* fill out the following fields in bp,
//    o hdr.code32_start
//    o hdr.cmd_line_ptr
//    o hdr.ramdisk_image (if applicable)
//    o hdr.ramdisk_size  (if applicable)
//
#define LINUX_BOOT_PARAMETER_SETUP_HEADER_CODE32_START_OFFSET    0x214
#define LINUX_BOOT_PARAMETER_SETUP_HEADER_CMD_LINE_PTR_OFFSET    0x228
#define LINUX_BOOT_PARAMETER_SETUP_HEADER_RAMDISK_IMAGE_OFFSET   0x218
#define LINUX_BOOT_PARAMETER_SETUP_HEADER_RAMDISK_SIZE_OFFSET    0x21C

/*
  Bit 0 (read):	XLF_KERNEL_64
	- If 1, this kernel has the legacy 64-bit entry point at 0x200.

  Bit 1 (read): XLF_CAN_BE_LOADED_ABOVE_4G
        - If 1, kernel/boot_params/cmdline/ramdisk can be above 4G.

  Bit 2 (read):	XLF_EFI_HANDOVER_32
	- If 1, the kernel supports the 32-bit EFI handoff entry point
          given at handover_offset.

  Bit 3 (read): XLF_EFI_HANDOVER_64
	- If 1, the kernel supports the 64-bit EFI handoff entry point
          given at handover_offset + 0x200.

  Bit 4 (read): XLF_EFI_KEXEC
	- If 1, the kernel supports kexec EFI boot with EFI runtime support.
*/
#define LINUX_BOOT_PARAMETER_SETUP_HEADER_XLOAD_FLAGS_OFFSET     0x236
#define LINUX_BOOT_PARAMETER_SETUP_HEADER_HANDOVER_OFFSET        0x264

//
// efi_main(void *handle, efi_system_table_t *table, struct boot_params *bp)
//
typedef
VOID
(EFIAPI *EFI_HANDOVER) (
  IN EFI_HANDLE            Handle,
  IN EFI_SYSTEM_TABLE      *SystemTable,
  IN LINUX_BOOT_PARAMETER  *BootParameter
  );

#endif
