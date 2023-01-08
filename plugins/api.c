/*
 * QEMU Plugin API
 *
 * This provides the API that is available to the plugins to interact
 * with QEMU. We have to be careful not to expose internal details of
 * how QEMU works so we abstract out things like translation and
 * instructions to anonymous data types:
 *
 *  qemu_plugin_tb
 *  qemu_plugin_insn
 *
 * Which can then be passed back into the API to do additional things.
 * As such all the public functions in here are exported in
 * qemu-plugin.h.
 *
 * The general life-cycle of a plugin is:
 *
 *  - plugin is loaded, public qemu_plugin_install called
 *    - the install func registers callbacks for events
 *    - usually an atexit_cb is registered to dump info at the end
 *  - when a registered event occurs the plugin is called
 *     - some events pass additional info
 *     - during translation the plugin can decide to instrument any
 *       instruction
 *  - when QEMU exits all the registered atexit callbacks are called
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "qemu/osdep.h"
#include "qemu/plugin.h"
#include "qemu/log.h"
#include "tcg/tcg.h"
#include "exec/exec-all.h"
#include "exec/ram_addr.h"
#include "exec/address-spaces.h"
#include "disas/disas.h"
#include "plugin.h"
#ifndef CONFIG_USER_ONLY
#include "qemu/plugin-memory.h"
#include "hw/boards.h"
#else
#include "qemu.h"
#ifdef CONFIG_LINUX
#include "loader.h"
#endif
#endif


/* Uninstall and Reset handlers */

void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, false);
}

void qemu_plugin_reset(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, true);
}

/*
 * Plugin Register Functions
 *
 * This allows the plugin to register callbacks for various events
 * during the translation.
 */

void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_INIT, cb);
}

void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_EXIT, cb);
}

void qemu_plugin_register_vcpu_tb_exec_cb(struct qemu_plugin_tb *tb,
                                          qemu_plugin_vcpu_udata_cb_t cb,
                                          enum qemu_plugin_cb_flags flags,
                                          void *udata)
{
    if (!tb->mem_only) {
        plugin_register_dyn_cb__udata(&tb->cbs[PLUGIN_CB_REGULAR],
                                      cb, flags, udata);
    }
}

void qemu_plugin_register_vcpu_tb_exec_inline(struct qemu_plugin_tb *tb,
                                              enum qemu_plugin_op op,
                                              void *ptr, uint64_t imm)
{
    if (!tb->mem_only) {
        plugin_register_inline_op(&tb->cbs[PLUGIN_CB_INLINE], 0, op, ptr, imm);
    }
}

void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
                                            qemu_plugin_vcpu_udata_cb_t cb,
                                            enum qemu_plugin_cb_flags flags,
                                            void *udata)
{
    if (!insn->mem_only) {
        plugin_register_dyn_cb__udata(&insn->cbs[PLUGIN_CB_INSN][PLUGIN_CB_REGULAR],
                                      cb, flags, udata);
    }
}

void qemu_plugin_register_vcpu_insn_exec_inline(struct qemu_plugin_insn *insn,
                                                enum qemu_plugin_op op,
                                                void *ptr, uint64_t imm)
{
    if (!insn->mem_only) {
        plugin_register_inline_op(&insn->cbs[PLUGIN_CB_INSN][PLUGIN_CB_INLINE],
                                  0, op, ptr, imm);
    }
}


/*
 * We always plant memory instrumentation because they don't finalise until
 * after the operation has complete.
 */
void qemu_plugin_register_vcpu_mem_cb(struct qemu_plugin_insn *insn,
                                      qemu_plugin_vcpu_mem_cb_t cb,
                                      enum qemu_plugin_cb_flags flags,
                                      enum qemu_plugin_mem_rw rw,
                                      void *udata)
{
    plugin_register_vcpu_mem_cb(&insn->cbs[PLUGIN_CB_MEM][PLUGIN_CB_REGULAR],
                                    cb, flags, rw, udata);
}

void qemu_plugin_register_vcpu_mem_inline(struct qemu_plugin_insn *insn,
                                          enum qemu_plugin_mem_rw rw,
                                          enum qemu_plugin_op op, void *ptr,
                                          uint64_t imm)
{
    plugin_register_inline_op(&insn->cbs[PLUGIN_CB_MEM][PLUGIN_CB_INLINE],
                              rw, op, ptr, imm);
}

void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_tb_trans_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_TB_TRANS, cb);
}

void qemu_plugin_register_vcpu_syscall_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_syscall_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL, cb);
}

void
qemu_plugin_register_vcpu_syscall_ret_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_syscall_ret_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL_RET, cb);
}

/*
 * Plugin Queries
 *
 * These are queries that the plugin can make to gauge information
 * from our opaque data types. We do not want to leak internal details
 * here just information useful to the plugin.
 */

/*
 * Translation block information:
 *
 * A plugin can query the virtual address of the start of the block
 * and the number of instructions in it. It can also get access to
 * each translated instruction.
 */

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb)
{
    return tb->n;
}

uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb)
{
    return tb->vaddr;
}

struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx)
{
    struct qemu_plugin_insn *insn;
    if (unlikely(idx >= tb->n)) {
        return NULL;
    }
    insn = g_ptr_array_index(tb->insns, idx);
    insn->mem_only = tb->mem_only;
    return insn;
}

/*
 * Register information
 *
 * These queries allow the plugin to retrieve information about each
 * the current state of registers in the CPU
 */

uint64_t qemu_plugin_get_pc(void) {
    CPUState *cpu = current_cpu;
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    target_ulong pc, cs_base;
    uint32_t flags;
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    return (uint64_t)pc;
}

int32_t qemu_plugin_get_reg32(unsigned int reg_idx, bool* error) {
    // Should we directly use gdbsub.c's gdb_read_register?
    CPUState *cpu = current_cpu;
    CPUClass *cc = CPU_GET_CLASS(cpu);
    GByteArray* result = g_byte_array_sized_new(4);

    int32_t rv = 0;
    int bytes_read = cc->gdb_read_register(cpu, result, reg_idx);
    *error = (bytes_read == 0);
    if (*error) {
      return 0;
    }
    memcpy(&rv, result->data, sizeof(rv));

    g_byte_array_free(result, true);
    return rv;
}

int64_t qemu_plugin_get_reg64(unsigned int reg_idx, bool* error) {
    // Should we directly use gdbsub.c's gdb_read_register?
    CPUState *cpu = current_cpu;
    CPUClass *cc = CPU_GET_CLASS(cpu);
    GByteArray* result = g_byte_array_sized_new(8);

    int64_t rv = 0;
    int bytes_read = cc->gdb_read_register(cpu, result, reg_idx);
    *error = (bytes_read == 0);
    if (*error) {
      return 0;
    }

    memcpy(&rv, result->data, sizeof(rv));
    g_byte_array_free(result, true);
    return rv;
}

inline uint64_t qemu_plugin_virt_to_phys(uint64_t addr) {
#ifdef CONFIG_SOFTMMU
    CPUState *cpu = current_cpu;
    target_ulong page;
    hwaddr phys_addr;
    page = addr & TARGET_PAGE_MASK;
    phys_addr = cpu_get_phys_page_debug(cpu, page);
    if (phys_addr == -1) {
        // no physical page mapped
        return -1;
    }
    phys_addr += (addr & ~TARGET_PAGE_MASK);
    return phys_addr;
#else
    return -1;
#endif
}

int qemu_plugin_read_guest_virt_mem(uint64_t gva, void* buf, size_t length) {
#ifdef CONFIG_SOFTMMU
    return cpu_memory_rw_debug(current_cpu, gva, buf, length, 0);
#else
    return -1;
#endif
}


void *qemu_plugin_virt_to_host(uint64_t addr, int len)
{
#ifdef CONFIG_SOFTMMU
    uint64_t phys = qemu_plugin_virt_to_phys(addr);
    hwaddr addr1;
    hwaddr l = (hwaddr)len;
    MemoryRegion *mr =
        address_space_translate(&address_space_memory, phys, &addr1, &l, true, MEMTXATTRS_UNSPECIFIED);

    if (!memory_access_is_direct(mr, true)) {
        return NULL;
    }

    return qemu_map_ram_ptr(mr->ram_block, addr1);
#else
    return NULL;
#endif
}

/*
 * Instruction information
 *
 * These queries allow the plugin to retrieve information about each
 * instruction being translated.
 */

const void *qemu_plugin_insn_data(const struct qemu_plugin_insn *insn)
{
    return insn->data->data;
}

size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn)
{
    return insn->data->len;
}

uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn)
{
    return insn->vaddr;
}

void *qemu_plugin_insn_haddr(const struct qemu_plugin_insn *insn)
{
    return insn->haddr;
}

char *qemu_plugin_insn_disas(const struct qemu_plugin_insn *insn)
{
    CPUState *cpu = current_cpu;
    return plugin_disas(cpu, insn->vaddr, insn->data->len);
}

const char *qemu_plugin_insn_symbol(const struct qemu_plugin_insn *insn)
{
    const char *sym = lookup_symbol(insn->vaddr);
    return sym[0] != 0 ? sym : NULL;
}

/*
 * The memory queries allow the plugin to query information about a
 * memory access.
 */

unsigned qemu_plugin_mem_size_shift(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return op & MO_SIZE;
}

bool qemu_plugin_mem_is_sign_extended(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return op & MO_SIGN;
}

bool qemu_plugin_mem_is_big_endian(qemu_plugin_meminfo_t info)
{
    MemOp op = get_memop(info);
    return (op & MO_BSWAP) == MO_BE;
}

bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t info)
{
    return get_plugin_meminfo_rw(info) & QEMU_PLUGIN_MEM_W;
}

/*
 * Virtual Memory queries
 */

#ifdef CONFIG_SOFTMMU
static __thread struct qemu_plugin_hwaddr hwaddr_info;
#endif

struct qemu_plugin_hwaddr *qemu_plugin_get_hwaddr(qemu_plugin_meminfo_t info,
                                                  uint64_t vaddr)
{
#ifdef CONFIG_SOFTMMU
    CPUState *cpu = current_cpu;
    unsigned int mmu_idx = get_mmuidx(info);
    enum qemu_plugin_mem_rw rw = get_plugin_meminfo_rw(info);
    hwaddr_info.is_store = (rw & QEMU_PLUGIN_MEM_W) != 0;

    assert(mmu_idx < NB_MMU_MODES);

    if (!tlb_plugin_lookup(cpu, vaddr, mmu_idx,
                           hwaddr_info.is_store, &hwaddr_info)) {
        error_report("invalid use of qemu_plugin_get_hwaddr");
        return NULL;
    }

    return &hwaddr_info;
#else
    return NULL;
#endif
}

bool qemu_plugin_hwaddr_is_io(const struct qemu_plugin_hwaddr *haddr)
{
#ifdef CONFIG_SOFTMMU
    return haddr->is_io;
#else
    return false;
#endif
}

uint64_t qemu_plugin_hwaddr_phys_addr(const struct qemu_plugin_hwaddr *haddr)
{
#ifdef CONFIG_SOFTMMU
    if (haddr) {
        if (!haddr->is_io) {
            RAMBlock *block;
            ram_addr_t offset;
            void *hostaddr = haddr->v.ram.hostaddr;

            block = qemu_ram_block_from_host(hostaddr, false, &offset);
            if (!block) {
                error_report("Bad host ram pointer %p", haddr->v.ram.hostaddr);
                abort();
            }

            return block->offset + offset + block->mr->addr;
        } else {
            MemoryRegionSection *mrs = haddr->v.io.section;
            return mrs->offset_within_address_space + haddr->v.io.offset;
        }
    }
#endif
    return 0;
}

const char *qemu_plugin_hwaddr_device_name(const struct qemu_plugin_hwaddr *h)
{
#ifdef CONFIG_SOFTMMU
    if (h && h->is_io) {
        MemoryRegionSection *mrs = h->v.io.section;
        if (!mrs->mr->name) {
            unsigned long maddr = 0xffffffff & (uintptr_t) mrs->mr;
            g_autofree char *temp = g_strdup_printf("anon%08lx", maddr);
            return g_intern_string(temp);
        } else {
            return g_intern_string(mrs->mr->name);
        }
    } else {
        return g_intern_static_string("RAM");
    }
#else
    return g_intern_static_string("Invalid");
#endif
}

/*
 * Queries to the number and potential maximum number of vCPUs there
 * will be. This helps the plugin dimension per-vcpu arrays.
 */

#ifndef CONFIG_USER_ONLY
static MachineState * get_ms(void)
{
    return MACHINE(qdev_get_machine());
}
#endif

int qemu_plugin_n_vcpus(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return get_ms()->smp.cpus;
#endif
}

int qemu_plugin_n_max_vcpus(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return get_ms()->smp.max_cpus;
#endif
}

/*
 * Plugin output
 */
void qemu_plugin_outs(const char *string)
{
    qemu_log_mask(CPU_LOG_PLUGIN, "%s", string);
}

bool qemu_plugin_bool_parse(const char *name, const char *value, bool *ret)
{
    return name && value && qapi_bool_parse(name, value, ret, NULL);
}


/**
 * Externally accessible plugin load function
 */

int qemu_plugin_load_plugin(char *path, int argc, char **argv) {
    g_autofree qemu_info_t *info = g_new0(qemu_info_t, 1);

    info->target_name = TARGET_NAME;
    info->version.min = QEMU_PLUGIN_MIN_VERSION;
    info->version.cur = QEMU_PLUGIN_VERSION;
#ifndef CONFIG_USER_ONLY
    MachineState *ms = MACHINE(qdev_get_machine());
    info->system_emulation = true;
    info->system.smp_vcpus = ms->smp.cpus;
    info->system.max_vcpus = ms->smp.max_cpus;
#else
    info->system_emulation = false;
#endif

    return on_demand_load(path, argc, argv, info);
}

/*
 * QPP: inter-plugin function resolution and callbacks
 */

gpointer qemu_plugin_import_function(const char *target_plugin,
                                     const char *function) {
    gpointer function_pointer = NULL;
    struct qemu_plugin_ctx *ctx = plugin_name_to_ctx_locked(target_plugin);
    if (ctx == NULL) {
        error_report("Unable to load plugin %s by name", target_plugin);
    } else if (g_module_symbol(ctx->handle, function,
               (gpointer *)&function_pointer)) {
        return function_pointer;
    } else {
      error_report("function: %s not found in plugin: %s", function,
                   target_plugin);
    }
    abort();
    return NULL;
}

bool qemu_plugin_create_callback(qemu_plugin_id_t id, const char *cb_name)
{
    struct qemu_plugin_ctx *ctx = plugin_id_to_ctx_locked(id);
    if (ctx == NULL) {
        error_report("Cannot create callback with invalid plugin ID");
        return false;
    }

    if (ctx->version < QPP_MINIMUM_VERSION) {
        error_report("Plugin %s cannot create callbacks as its PLUGIN_VERSION"
                     " %d is below QPP_MINIMUM_VERSION (%d).",
                     ctx->name, ctx->version, QPP_MINIMUM_VERSION);
        return false;
    }

    if (plugin_find_qpp_cb(ctx, cb_name)) {
        error_report("Plugin %s already created callback %s", ctx->name,
                     cb_name);
        return false;
    }

    plugin_add_qpp_cb(ctx, cb_name);
    return true;
}

bool qemu_plugin_run_callback(qemu_plugin_id_t id, const char *cb_name,
                              gpointer evdata, gpointer udata) {
    struct qemu_plugin_ctx *ctx = plugin_id_to_ctx_locked(id);
    if (ctx == NULL) {
        error_report("Cannot run callback with invalid plugin ID");
        return false;
    }

    struct qemu_plugin_qpp_cb *cb = plugin_find_qpp_cb(ctx, cb_name);
    if (!cb) {
        error_report("Can not run previously-unregistered callback %s in "
                     "plugin %s", cb_name, ctx->name);
        return false;
    }

    // Run all functions in list with args evdata and udata
    for (int i = 0; i < cb->counter; i++) {
        cb_func_t qpp_cb_func = cb->registered_cb_funcs[i];
        qpp_cb_func(evdata, udata);
    }

    return (cb->registered_cb_funcs[0] != NULL);
}

bool qemu_plugin_reg_callback(const char *target_plugin, const char *cb_name,
                              cb_func_t function_pointer) {
    struct qemu_plugin_ctx *ctx = plugin_name_to_ctx_locked(target_plugin);
    if (ctx == NULL) {
        error_report("Cannot register callback with unknown plugin %s",
                     target_plugin);
      return false;
    }

    struct qemu_plugin_qpp_cb *cb = plugin_find_qpp_cb(ctx, cb_name);
    if (!cb) {
        error_report("Cannot register a function to run on callback %s in "
                     "plugin %s as that callback does not exist",
                     cb_name, target_plugin);
        return false;
    }
    if (cb->counter == QEMU_PLUGIN_EV_MAX) {
        error_report("The maximum number of allowed callbacks are already "
                     "registered for callback %s in plugin %s\n",
                     cb_name, target_plugin);
        return false;
    }
    // append function pointer to list of functions
    cb->registered_cb_funcs[cb->counter] = function_pointer;
    cb->counter++;
    return true;
}

bool qemu_plugin_unreg_callback(const char *target_plugin, const char *cb_name,
                              cb_func_t function_pointer) {
    struct qemu_plugin_ctx *ctx = plugin_name_to_ctx_locked(target_plugin);
    if (ctx == NULL) {
        error_report("Cannot remove callback function from unknown plugin %s",
                     target_plugin);
        return false;
    }

    struct qemu_plugin_qpp_cb *cb = plugin_find_qpp_cb(ctx, cb_name);
    if (!cb) {
        error_report("Cannot remove a function to run on callback %s in "
                     "plugin %s as that callback does not exist",
                     cb_name, target_plugin);
        return false;
    }

    // remove function pointer from list of functions and shift all others accordingly
    for (int i = 0; i < cb->counter; i++) {
        if (cb->registered_cb_funcs[i] == function_pointer) {
            for (int j = i + 1; j < cb->counter; j++) {
                cb->registered_cb_funcs[i] = cb->registered_cb_funcs[j];
                i++;
            }
            cb->registered_cb_funcs[i] = NULL;
            cb->counter--;
            return true;
        }
    }
    error_report("Function to remove not found in registered functions "
                 "for callback %s in plugin %s",
                 cb_name, target_plugin);
    return false;
}

/*
 * Binary path, start and end locations
 */
const char *qemu_plugin_path_to_binary(void)
{
    char *path = NULL;
#ifdef CONFIG_USER_ONLY
    TaskState *ts = (TaskState *) current_cpu->opaque;
    path = g_strdup(ts->bprm->filename);
#endif
    return path;
}

uint64_t qemu_plugin_start_code(void)
{
    uint64_t start = 0;
#ifdef CONFIG_USER_ONLY
    TaskState *ts = (TaskState *) current_cpu->opaque;
    start = ts->info->start_code;
#endif
    return start;
}

uint64_t qemu_plugin_end_code(void)
{
    uint64_t end = 0;
#ifdef CONFIG_USER_ONLY
    TaskState *ts = (TaskState *) current_cpu->opaque;
    end = ts->info->end_code;
#endif
    return end;
}

uint64_t qemu_plugin_entry_code(void)
{
    uint64_t entry = 0;
#ifdef CONFIG_USER_ONLY
    TaskState *ts = (TaskState *) current_cpu->opaque;
    entry = ts->info->entry;
#endif
    return entry;
}
