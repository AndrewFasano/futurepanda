#include <glib.h>
#include <plugin-qpp.h>

extern "C" {
#include <qemu-plugin.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
QEMU_PLUGIN_EXPORT const char *qemu_plugin_name = "hw_proc_id";
#include "hw_proc_id.h"
}

#define unlikely(expr) __builtin_expect(!!(expr), 0)
#define likely(expr) __builtin_expect(!!(expr), 1)

bool initialized = false;

// We'll only use these for mips which we only support with 32 bits
uint32_t last_r28 = 0;
int WORD_SIZE = 32;

uint64_t _get_asid(void) {
  return qemu_plugin_get_asid();
}

/**
 * @brief Returns true if all prerequisite values to determine hwid cached.
 * TODO: export?
 */
bool id_is_initialized(void){
  return initialized;
}

typedef uint64_t (*_do_get_id_t)(void);

_do_get_id_t _do_get_id;

/**
 * @brief Returns a hardware-based process ID for the current process.
 * 
 * This is a wrapper around ASID that takes into the oddity that is MIPS.
 * 
 */
QEMU_PLUGIN_EXPORT uint64_t hw_proc_id_get(void) {
  // Exported function to either return ASID or cached R28 on mips
  return (*_do_get_id)();
}

static inline bool address_in_kernel_code_linux(uint64_t addr){
    // https://www.kernel.org/doc/html/latest/vm/highmem.html
    // https://github.com/torvalds/linux/blob/master/Documentation/x86/x86_64/mm.rst
    // If addr MSB set -> kernelspace!

    uint64_t msb_mask = ((uint64_t)1 << ((WORD_SIZE * 8) - 1));
    if (msb_mask & addr) {
        return true;
    } else {
        return false;
    }
}


/**
 * @brief Cache the last R28 observed while in kernel for MIPS
 * 
 * On MIPS in kernel mode r28 a pointer to the location of the current
 * task_struct. We need to cache this value for use in usermode. 
 */
void check_cache_r28(){
  if (qemu_plugin_in_privileged_mode()) {
		bool error = false;
    uint32_t potential = qemu_plugin_get_reg32(28, &error);
		if (error) return;

    if (unlikely(potential != last_r28)) {
      if (likely(address_in_kernel_code_linux(potential))) {
        last_r28 = potential;
        initialized = true;
      }
    }
  }
}

uint64_t _get_mips_r28(void) {
  if (!id_is_initialized()) {
    // try to initialize before returning
    check_cache_r28();
  }
  return (uint64_t)last_r28;
}


static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
  // TODO: should we do this per cpu?
  check_cache_r28();
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         NULL);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{

		_do_get_id = _get_asid;

    if (strcmp(info->target_name, "mipsel") == 0 ||
        strcmp(info->target_name, "mips") == 0) {
      qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
			_do_get_id = _get_mips_r28;
		}
	return 0;
}
