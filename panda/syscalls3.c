#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <qemu-plugin.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Simple syscalls hooking??
// TODO: validate call triggers at the right time 
// TODO: hook returns
// TODO: get away from strcmps?

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef bool (*is_syscall_t)(unsigned char* buf, size_t buf_len);

is_syscall_t is_syscall_fn = NULL;

bool is_syscall_i386(unsigned char* buf, size_t buf_len);
bool is_syscall_x86_64(unsigned char* buf, size_t buf_len);
bool is_syscall_arm(unsigned char* buf, size_t buf_len);
bool is_syscall_aarch64(unsigned char* buf, size_t buf_len);
bool is_syscall_mips(unsigned char* buf, size_t buf_len);
bool is_syscall_other(unsigned char* buf, size_t buf_len);

bool is_syscall_i386(unsigned char* buf, size_t buf_len) {
  assert(buf_len >= 2);
  // Check if the instruction is syscall (0F 05)
  if (buf[0]== 0x0F && buf[1] == 0x05) {
    return true;
  }

  // Check if the instruction is int 0x80 (CD 80)
  if (buf[0]== 0xCD && buf[1] == 0x80) {
    return true;
  }

  // Check if the instruction is sysenter (0F 34)
  if (buf[0]== 0x0F && buf[1] == 0x34) {
    // If 64-bit, we want to warn and ignore this, maybe warn
    return true;
  }
  return false;
}


bool is_syscall_x86_64(unsigned char* buf, size_t buf_len) {
  assert(buf_len >= 2);
  // Check if the instruction is syscall (0F 05)
  if (buf[0]== 0x0F && buf[1] == 0x05) {
    return true;
  }

  return false;
}



bool is_syscall_arm(unsigned char* buf, size_t buf_len) {
  assert(buf_len >=4);
  // TODO THUMB MODE

  // EABI - Thumb=0
  if (((buf[3] & 0x0F) ==  0x0F)  && (buf[2] == 0) && (buf[1] == 0) && (buf[0] == 0)) {
    return true;
  }
  // OABI - Thumb=0
  if (((buf[3] & 0x0F) == 0x0F)  && (buf[2] == 0x90)) {
      //*static_callno = (buf[1]<<8) + (buf[0]);
      return true;
  }

#if 0 // IF THUMB
    if (buf[1] == 0xDF && buf[0] == 0) {
      return true;
    }
#endif
  return false;
}

bool is_syscall_aarch64(unsigned char* buf, size_t buf_len) {
  assert(buf_len >=4);
  if ((buf[0] == 0x01)  && (buf[1] == 0) && (buf[2] == 0) && (buf[3] == 0xd4)) {
    return true;
  }
  return false;
}

bool is_syscall_mips(unsigned char* buf, size_t buf_len) {
  assert(buf_len >= 4);
  #if defined(TARGET_WORDS_BIGENDIAN)
      // 32-bit MIPS "syscall" instruction - big endian
      if ((buf[0] == 0x00) && (buf[1] == 0x00) && (buf[2] == 0x00) && (buf[3] == 0x0c)) {
          return true;
      }
  #else
      // 32-bit MIPS "syscall" instruction - little endian
      if ((buf[3] == 0x00) && (buf[2] == 0x00) && (buf[1] == 0x00) && (buf[0] == 0x0c)) {
          return true;
      }
  #endif
  return false;
}

bool is_syscall_other(unsigned char* buf, size_t buf_len) {
  // If we could get a handle to the insn object we could do the following:
#if 0
  char *insn_disas = qemu_plugin_insn_disas(insn);
  return (strcmp(insn_disas, "syscall ") == 0);
#endif
  return false;
}

typedef struct {
    const char *qemu_target;
    is_syscall_t is_syscall_fn;
} SyscallDetectorSelector;

// aarch64, sparc, sparc64, i386, x86_64
static SyscallDetectorSelector syscall_selectors[] = {
    { "i386",    is_syscall_i386},
    { "x86_64",  is_syscall_x86_64},
    { "arm",     is_syscall_arm},
    { "aarch64", is_syscall_aarch64},
    { "mips",    is_syscall_mips},
    { NULL,      is_syscall_other},
};

void my_func(void);

unsigned long ctr = 0;
void my_func(void) {
  ctr++;
  //if (ctr % 0x1000000 == 0)
    printf("Func called 0x%lx times\n", ctr);
}

static void my_exec(unsigned int cpu_index, void *udata) {
    printf("Syscall runs\n");
}

int first = 0;
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  // Handle to first insns
  size_t n = qemu_plugin_tb_n_insns(tb);
  struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, n-1);
  uint32_t insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));

  if (is_syscall_fn((unsigned char*)&insn_opcode, sizeof(uint32_t))) {
    // register my_exec to run before(?) the last instruction in this block
    qemu_plugin_register_vcpu_insn_exec_cb(insn, my_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);
  }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    for (int i = 0; i < ARRAY_SIZE(syscall_selectors); i++) {
        SyscallDetectorSelector *entry = &syscall_selectors[i];
        if (!entry->qemu_target ||
            strcmp(entry->qemu_target, info->target_name) == 0) {
            is_syscall_fn = entry->is_syscall_fn;
            break;
        }
    }

    return 0;
}
