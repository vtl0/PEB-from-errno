#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winternl.h>

#define PREFIX_REX 0b01000000
#define PREFIX_B_BIT 0b0001
#define PREFIX_X_BIT 0b0010
#define PREFIX_R_BIT 0b0100
#define PREFIX_W_BIT 0b1000
#define PREFIX_IS_REX(x) (PREFIX_REX == (x & 0b11110000))
#define ADD_EAX_INSN 0x05

// NOTICE: get_teb and get_peb functions are only for confirmation
static inline TEB *get_teb(void) {
#if defined(_WIN64)
  return __readgsqword(&((NT_TIB *)0)->Self);
#else
  return __readfsdword(&((NT_TIB *)0)->Self);
#endif  // defined(_WIN64)
}

static inline PEB *get_peb(void) {
  return get_teb()->ProcessEnvironmentBlock;
}

int main(void) {
  typedef int *(*_errno_fn)(void);
  HMODULE ntdll;
  _errno_fn ntdll_errno;  
  TEB *current_teb;
  uint32_t *offset;
  char *insn;

  ntdll = LoadLibraryA("ntdll.dll");
  if (ntdll == NULL) {
    fprintf(stderr, "LoadLibrary(\"ntdll.dll\") returned NULL (%d)\n", GetLastError());
    return EXIT_FAILURE;
  }

  ntdll_errno = (_errno_fn)GetProcAddress(ntdll, "_errno");
  if (ntdll_errno == NULL) {
    fprintf(stderr, "Could not find _errno export from ntdll (%d)\n", GetLastError());
    return EXIT_FAILURE;
  }

  offset = NULL;
#if defined(_WIN64)
  insn = (char *)ntdll_errno + 0x09;  
#else
  insn = (char *)ntdll_errno + 0x06;
#endif  // defined(_WIN64)
  if (PREFIX_IS_REX(insn[0]) && insn[1] == ADD_EAX_INSN) {
    offset = &insn[2];
  }
  else if (insn[0] == ADD_EAX_INSN) {
    offset = &insn[1];
  }
  if (offset == NULL) {
    fprintf(stderr, "_errno function signature mismatch\n");
    return EXIT_FAILURE;
  }

  current_teb = (char *)ntdll_errno() - *offset;
  printf("_errno() - 0x%lx -> %p\nPEB -> %p\n", (unsigned long)*offset,
         (PEB *)current_teb->ProcessEnvironmentBlock, get_peb());
  
  return EXIT_SUCCESS;
}
