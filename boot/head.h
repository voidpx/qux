#ifndef HEAD_H
#define HEAD_H

#include "../include/kmap.h"

#define PG_2M (1<<21)
#define PTE_N 512ULL
#define PG_4K (1<<12)
#define PG_4K_MASK ~(PG_4K - 1)

#define EI_NIDENT	16

typedef unsigned long long int u64;
typedef unsigned long long	Elf64_Addr;
typedef unsigned short	Elf64_Half;
typedef short	Elf64_SHalf;
typedef unsigned long long	Elf64_Off;
typedef int	Elf64_Sword;
typedef unsigned	Elf64_Word;
typedef unsigned long long	Elf64_Xword;
typedef long long	Elf64_Sxword;

typedef struct elf64_hdr {
  unsigned char	e_ident[EI_NIDENT];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;	
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct elf64_phdr {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;
  Elf64_Addr p_vaddr;
  Elf64_Addr p_paddr;
  Elf64_Xword p_filesz;
  Elf64_Xword p_memsz;
  Elf64_Xword p_align;
} Elf64_Phdr;

typedef struct elf64_shdr {
  Elf64_Word sh_name;		
  Elf64_Word sh_type;		
  Elf64_Xword sh_flags;		
  Elf64_Addr sh_addr;		
  Elf64_Off sh_offset;		
  Elf64_Xword sh_size;		
  Elf64_Word sh_link;		
  Elf64_Word sh_info;		
  Elf64_Xword sh_addralign;	
  Elf64_Xword sh_entsize;	
} Elf64_Shdr;

#define SHT_NULL	0
#define SHT_PROGBITS	1
#define SHT_SYMTAB	2
#define SHT_STRTAB	3
#define SHT_RELA	4
#define SHT_HASH	5
#define SHT_DYNAMIC	6
#define SHT_NOTE	7
#define SHT_NOBITS	8
#define SHT_REL		9
#define SHT_SHLIB	10
#define SHT_DYNSYM	11
#define SHT_NUM		12
#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7fffffff
#define SHT_LOUSER	0x80000000
#define SHT_HIUSER	0xffffffff
#define PT_NULL    0
#define PT_LOAD    1

typedef struct boot_info {
    u64 mb2;
    u64 boot_pgd;
    u64 boot_pgd_size;
    u64 gdtr;
    u64 gdt;
} boot_info;

#endif

