/*
 * setup for long mode, load 64bit kernel and jump to it.
 *
 */
#include "head.h"
struct gdtr {
  unsigned short size;
  unsigned int ptr;
} __attribute__((packed)) gdtr __attribute__((__aligned__(16)));

static struct gdt {
  u64 null;
  u64 cs;
  u64 ds;
  struct ts {
              u64 ts1;
              u64 ts2;
  } ts;
} gdt __attribute__((__aligned__(16)));

extern char boot_pgd;

static void memset(char *dst, int v, unsigned int size) {
  char c = (char)v;
  int iv = c<<24 | c<<16 | c << 8 | c;
  unsigned int is = size/4;
  unsigned int r = size%4;
  int *p = (int *)dst;
  int *e = p+is;
  while (p < e) *p++ = iv;
  char *bp = (char *)e;
  while (r--) {
    *bp++ = c; 
  }
}

static void memcpy(char *dst, char *src, unsigned int size) {
  unsigned int is = size/4;
  unsigned int r = size%4;
  int *p = (int *)dst;
  int *e = p+is;
  int *s = (int *)src;
  while (p < e) *p++ = *s++;
  char *bp = (char *)e;
  char *bs = (char *)s;
  while (r--) {
    *bp++ = *bs++; 
  }
}

static void setup_boot_pgt() {
  memset(&boot_pgd, 0x0, 6*PG_4K);
  u64 *pgd = (u64 *)&boot_pgd;
  u64 *pud = (u64 *)(&boot_pgd + PG_4K);
  pgd[0] = (u64)pud + 0x7; // identity map
  pgd[KERNEL_PGD_IDX] = pgd[0];  // kernel map
  for (int i=0; i<4; i++) {
    u64 a = (u64)pud & PG_4K_MASK;
    pud[i] = a + (i+1) * PG_4K + 0x7;
    u64 *pte = (u64 *)(pud[i] & PG_4K_MASK);
    for (int j=0; j<PTE_N; j++) {
      pte[j] = (i * PTE_N * PG_2M) + j * PG_2M + 0x183;
    }
  }
}

void goto_long_mode(Elf64_Addr, unsigned long);
extern char _kernel_start, _kernel_end;

static Elf64_Addr load_kernel() {
  Elf64_Ehdr *eh = (Elf64_Ehdr *)&_kernel_start;
  Elf64_Phdr *ph = (Elf64_Phdr *)(&_kernel_start + eh->e_phoff);
  for (int i = 0; i < eh->e_phnum; i++, ph++) {
    if (ph->p_type == PT_LOAD) {
      unsigned dst = ph->p_paddr;
      memcpy((char *)dst, &_kernel_start + ph->p_offset, ph->p_filesz);
    }
  }
  u64 entry = eh->e_entry;
  return entry;
}

static void setup_gdt() {
  gdtr.size = sizeof(gdt) - 1;
  gdtr.ptr = (unsigned long long int)&gdt;
  gdt.null = 0x0;
  gdt.cs = 0x00af9a000000ffff;
  gdt.ds = 0x00cf92000000ffff;
  gdt.ts.ts1 = 0x0080890000000000;
  gdt.ts.ts2 = 0x0000000000000000;
}

void setup(unsigned long magic, unsigned long addr)
{
  Elf64_Addr entry = load_kernel();
  setup_boot_pgt();
  setup_gdt();
  static boot_info info;
  info = (boot_info) {
    .boot_pgd = (u64)&boot_pgd,
    .boot_pgd_size = 6 * PG_4K,
    .mb2 = addr,
    .gdt = (u64)&gdt,
    .gdtr = (u64)&gdtr
  };
  goto_long_mode(entry, (unsigned long)&info);
}

