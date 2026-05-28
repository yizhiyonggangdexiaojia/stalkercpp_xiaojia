var stalker_module
var trace_config_func
!function () {
    const code = `
#include <gum/gumstalker.h>
#include <glib.h>
#include <stdio.h>
#include <capstone.h>

#define MAX_LINE_LEN 2048
#define MAX_TRACE_REGS 16
#define MAX_TRACE_MEMS 4

#define TRACE_CALL_NONE 0
#define TRACE_CALL_FUNC 1
#define TRACE_CALL_JNI 2
#define TRACE_CALL_SYSCALL 3

#define TRACE_BRANCH_NONE 0
#define TRACE_BRANCH_IMM 1
#define TRACE_BRANCH_REG 2
#define TRACE_BRANCH_SVC 3

struct stalker_info {
    guint64 start;
    guint64 end;
    char *module_name;
    arm64_reg pending_writes[MAX_TRACE_REGS];
    gsize pending_num_write;
    gboolean pending_line;
    gboolean pending_call;
    int pending_call_kind;
    char *pending_call_name;
    char *pending_call_info;
    guint64 pending_call_address;
    guint64 pending_syscall_nr;
    guint64 pending_args[8];
} typedef stalker_info;

extern stalker_info *init_info;

extern FILE *fopen(char *filename, char *mode);
extern int fclose(FILE* fp);
extern size_t fwrite(const void* __buf, size_t __size, size_t __count, FILE* __fp);
extern int snprintf(char *str, size_t size, const char *format, ...);

extern void *send(char *info);
extern char *resolve_func_name(gpointer address);
extern char *resolve_jni_name(gpointer address);
extern char *resolve_syscall_name(gpointer number);
extern char *format_call_before(int kind, char *name,
                                gpointer x0, gpointer x1, gpointer x2, gpointer x3,
                                gpointer x4, gpointer x5, gpointer x6, gpointer x7,
                                gpointer syscall_nr);
extern char *format_call_info(int kind, char *name,
                              gpointer x0, gpointer x1, gpointer x2, gpointer x3,
                              gpointer x4, gpointer x5, gpointer x6, gpointer x7,
                              gpointer ret, gpointer syscall_nr);

size_t my_strlen(const char *str) {
    size_t length = 0;
    // 遍历字符串，直到遇到终止符 '\\0'
    while (str[length] != '\\0') {
        length++;
    }
    return length;
}

gboolean my_contains(const char *haystack, const char *needle) {
    if (haystack == NULL || needle == NULL || needle[0] == '\\0') return FALSE;
    for (size_t i = 0; haystack[i] != '\\0'; ++i) {
        size_t j = 0;
        while (needle[j] != '\\0' && haystack[i + j] == needle[j]) {
            ++j;
        }
        if (needle[j] == '\\0') return TRUE;
    }
    return FALSE;
}

gboolean my_streq(const char *left, const char *right) {
    if (left == NULL || right == NULL) return FALSE;
    size_t i = 0;
    while (left[i] != '\\0' && right[i] != '\\0') {
        if (left[i] != right[i]) return FALSE;
        ++i;
    }
    return left[i] == '\\0' && right[i] == '\\0';
}

gboolean trace_is_cas_mnemonic(const char *mnemonic) {
    return mnemonic != NULL && mnemonic[0] == 'c' && mnemonic[1] == 'a' && mnemonic[2] == 's';
}

gboolean trace_is_ret_mnemonic(const char *mnemonic) {
    return my_streq(mnemonic, "ret") || my_streq(mnemonic, "retaa") || my_streq(mnemonic, "retab");
}

gboolean trace_is_pac_link_branch(const char *mnemonic) {
    return my_streq(mnemonic, "blraa") || my_streq(mnemonic, "blrab") ||
           my_streq(mnemonic, "blraaz") || my_streq(mnemonic, "blrabz");
}

gboolean trace_is_pac_branch(const char *mnemonic) {
    return my_streq(mnemonic, "braa") || my_streq(mnemonic, "brab") ||
           my_streq(mnemonic, "braaz") || my_streq(mnemonic, "brabz");
}

void transformer_callback_base(GumStalkerIterator *iterator,
                               GumStalkerOutput *output, gpointer user_data) {
    send("transformer");
    while (true) {
        const cs_insn *insn = NULL;
        if (!gum_stalker_iterator_next(iterator, &insn)) {
            break;
        };
        gchar *line = g_strdup_printf("\\t0x%llx %s %s", insn->address, insn->mnemonic,
                                      insn->op_str);
        send(line);
        gum_stalker_iterator_keep(iterator);
    }
    send("");
}

static char default_module_name[] = "trace";

const gchar *trace_x_names[] = {
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28"
};
const gchar *trace_w_names[] = {
        "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
        "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
        "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
        "w24", "w25", "w26", "w27", "w28", "w29", "w30"
};
const gchar *trace_d_names[] = {
        "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
        "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
        "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
        "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31"
};
const gchar *trace_q_names[] = {
        "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
        "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15",
        "q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
        "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31"
};
const gchar *trace_v_names[] = {
        "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
        "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
        "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
        "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
};
const gchar *trace_s_names[] = {
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
        "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
        "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31"
};
const gchar *trace_h_names[] = {
        "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7",
        "h8", "h9", "h10", "h11", "h12", "h13", "h14", "h15",
        "h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23",
        "h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31"
};
const gchar *trace_b_names[] = {
        "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
        "b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
        "b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
        "b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31"
};

FILE *init_func_with_module(guint64 start, guint64 end, char *filename, char *module_name) {
    if (init_info != NULL) {
        if (init_info->pending_call_info != NULL) {
            g_free(init_info->pending_call_info);
            init_info->pending_call_info = NULL;
        }
        if (init_info->module_name != NULL && init_info->module_name != default_module_name) {
            g_free(init_info->module_name);
            init_info->module_name = NULL;
        }
        g_free(init_info);
    }
    init_info = (stalker_info *) g_malloc0(sizeof(stalker_info));
//    写上你的要trace的地址范围
    init_info->start = start;
    init_info->end = end;
    init_info->module_name = module_name ? g_strdup(module_name) : default_module_name;
    init_info->pending_line = FALSE;
    init_info->pending_num_write = 0;
//    清空这个文件 
    stdout = fopen(filename, "w");
    if (stdout) fclose(stdout);
    stdout = fopen(filename, "a+");
    return stdout;
}

FILE *init_func(guint64 start, guint64 end, char *filename) {
    return init_func_with_module(start, end, filename, default_module_name);
}

void end_func(){
    if (stdout) {
        if (init_info != NULL && init_info->pending_line) {
            fwrite("\\n", 1, 1, stdout);
            init_info->pending_line = FALSE;
            init_info->pending_num_write = 0;
        }
        if (init_info != NULL) {
            init_info->pending_call = FALSE;
            init_info->pending_call_kind = TRACE_CALL_NONE;
            init_info->pending_call_name = NULL;
            if (init_info->pending_call_info != NULL) {
                g_free(init_info->pending_call_info);
                init_info->pending_call_info = NULL;
            }
            if (init_info->module_name != NULL && init_info->module_name != default_module_name) {
                g_free(init_info->module_name);
            }
            init_info->module_name = default_module_name;
        }
        fclose(stdout);
    }
}

typedef struct {
    guint64 pc;
    guint64 sp;
    guint64 nzcv;

    guint64 x[29];
    guint64 fp;
    guint64 lr;

    GumArm64VectorReg v[32];
} GumArm64CpuContext;

typedef struct {
    arm64_reg base;
    arm64_reg index;
    gint64 disp;
    arm64_shifter shift_type;
    unsigned int shift_value;
    arm64_extender ext;
    gboolean is_write;
} MemContext;

/* 指令上下文在 transform 阶段解析一次，在 callout 阶段只做取值和格式化。 */
typedef struct {
    guint64 address;
    int branch_kind;
    guint64 branch_imm;
    arm64_reg branch_reg;
    arm64_reg regs_write[MAX_TRACE_REGS];
    arm64_reg regs_read[MAX_TRACE_REGS];
    MemContext mems[MAX_TRACE_MEMS];
    gsize num_read;
    gsize num_write;
    gsize num_mem;
    char mnemonic[32];
    char instruction[128];
} InsnContext;

const gchar *trace_reg_name(arm64_reg reg) {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        return trace_x_names[reg - ARM64_REG_X0];
    }
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
        return trace_w_names[reg - ARM64_REG_W0];
    }
    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        return trace_d_names[reg - ARM64_REG_D0];
    }
    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        return trace_q_names[reg - ARM64_REG_Q0];
    }
    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        return trace_v_names[reg - ARM64_REG_V0];
    }
    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        return trace_s_names[reg - ARM64_REG_S0];
    }
    if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        return trace_h_names[reg - ARM64_REG_H0];
    }
    if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        return trace_b_names[reg - ARM64_REG_B0];
    }
    switch (reg) {
        case ARM64_REG_FP:
            return "fp";
        case ARM64_REG_LR:
            return "lr";
        case ARM64_REG_SP:
            return "sp";
        case ARM64_REG_WSP:
            return "wsp";
        case ARM64_REG_XZR:
            return "xzr";
        case ARM64_REG_WZR:
            return "wzr";
        case ARM64_REG_NZCV:
            return "nzcv";
        default:
            return NULL;
    }
}

gboolean trace_get_reg_value(arm64_reg reg, GumArm64CpuContext *cpu_context, guint64 *value) {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        *value = cpu_context->x[reg - ARM64_REG_X0];
        return TRUE;
    }
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W28) {
        *value = cpu_context->x[reg - ARM64_REG_W0] & 0xffffffffULL;
        return TRUE;
    }
    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        guint64 raw = 0;
        guint8 *bytes = cpu_context->v[reg - ARM64_REG_D0].q;
        for (int i = 7; i >= 0; --i) {
            raw = (raw << 8) | bytes[i];
        }
        *value = raw;
        return TRUE;
    }
    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        guint32 raw = 0;
        guint8 *bytes = cpu_context->v[reg - ARM64_REG_S0].q;
        for (int i = 3; i >= 0; --i) {
            raw = (raw << 8) | bytes[i];
        }
        *value = raw;
        return TRUE;
    }
    if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        guint8 *bytes = cpu_context->v[reg - ARM64_REG_H0].q;
        *value = ((guint64) bytes[1] << 8) | bytes[0];
        return TRUE;
    }
    if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        guint8 *bytes = cpu_context->v[reg - ARM64_REG_B0].q;
        *value = bytes[0];
        return TRUE;
    }
    switch (reg) {
        case ARM64_REG_W29:
            *value = cpu_context->fp & 0xffffffffULL;
            return TRUE;
        case ARM64_REG_W30:
            *value = cpu_context->lr & 0xffffffffULL;
            return TRUE;
        case ARM64_REG_FP:
            *value = cpu_context->fp;
            return TRUE;
        case ARM64_REG_LR:
            *value = cpu_context->lr;
            return TRUE;
        case ARM64_REG_SP:
            *value = cpu_context->sp;
            return TRUE;
        case ARM64_REG_WSP:
            *value = cpu_context->sp & 0xffffffffULL;
            return TRUE;
        case ARM64_REG_XZR:
        case ARM64_REG_WZR:
            *value = 0;
            return TRUE;
        case ARM64_REG_NZCV:
            *value = cpu_context->nzcv;
            return TRUE;
        default:
            return FALSE;
    }
}

int trace_append_hex_byte(char *log_line, int offset, guint8 value) {
    static const char hex[] = "0123456789abcdef";
    if (offset + 2 >= MAX_LINE_LEN) return offset;
    log_line[offset++] = hex[(value >> 4) & 0xf];
    log_line[offset++] = hex[value & 0xf];
    return offset;
}

int trace_advance_offset(int offset, int written) {
    if (written < 0) return offset;
    if (offset >= MAX_LINE_LEN - 1) return MAX_LINE_LEN - 1;
    if (written >= MAX_LINE_LEN - offset) return MAX_LINE_LEN - 1;
    return offset + written;
}

int trace_append_vector128_value(char *log_line, int offset, arm64_reg reg, GumArm64CpuContext *cpu_context) {
    const gchar *name = trace_reg_name(reg);
    guint8 *bytes = NULL;
    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        bytes = cpu_context->v[reg - ARM64_REG_Q0].q;
    } else if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        bytes = cpu_context->v[reg - ARM64_REG_V0].q;
    } else {
        return offset;
    }
    offset = trace_advance_offset(offset, snprintf(log_line + offset, MAX_LINE_LEN - offset, "%s=0x", name));
    for (int i = 15; i >= 0; --i) {
        offset = trace_append_hex_byte(log_line, offset, bytes[i]);
    }
    if (offset + 1 < MAX_LINE_LEN) {
        log_line[offset++] = ' ';
        log_line[offset] = '\\0';
    }
    return offset;
}

gboolean trace_reg_in_list(arm64_reg *regs, gsize count, arm64_reg reg) {
    for (gsize i = 0; i < count; ++i) {
        if (regs[i] == reg) return TRUE;
    }
    return FALSE;
}

void trace_add_reg(arm64_reg *regs, gsize *count, arm64_reg reg) {
    if (reg == ARM64_REG_INVALID || trace_reg_name(reg) == NULL) return;
    if (trace_reg_in_list(regs, *count, reg)) return;
    if (*count < MAX_TRACE_REGS) {
        regs[*count] = reg;
        (*count)++;
    }
}

int trace_append_reg_value(char *log_line, int offset, arm64_reg reg, GumArm64CpuContext *cpu_context) {
    const gchar *name = trace_reg_name(reg);
    guint64 value = 0;
    if ((reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) || (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31)) {
        return trace_append_vector128_value(log_line, offset, reg, cpu_context);
    }
    if (name == NULL || !trace_get_reg_value(reg, cpu_context, &value)) return offset;
    return trace_advance_offset(offset, snprintf(log_line + offset, MAX_LINE_LEN - offset, "%s=0x%llx ", name, value));
}

int trace_append_pre_regs(InsnContext *ctx, GumArm64CpuContext *cpu_context, char *log_line, int offset) {
    for (gsize i = 0; i < ctx->num_read; ++i) {
        offset = trace_append_reg_value(log_line, offset, ctx->regs_read[i], cpu_context);
    }
    for (gsize i = 0; i < ctx->num_write; ++i) {
        if (!trace_reg_in_list(ctx->regs_read, ctx->num_read, ctx->regs_write[i])) {
            offset = trace_append_reg_value(log_line, offset, ctx->regs_write[i], cpu_context);
        }
    }
    return offset;
}

guint64 trace_apply_extend(guint64 value, arm64_extender ext) {
    switch (ext) {
        case ARM64_EXT_UXTB:
            return value & 0xffULL;
        case ARM64_EXT_UXTH:
            return value & 0xffffULL;
        case ARM64_EXT_UXTW:
            return value & 0xffffffffULL;
        case ARM64_EXT_SXTB:
            return (guint64) (gint64) (gint8) value;
        case ARM64_EXT_SXTH:
            return (guint64) (gint64) (gint16) value;
        case ARM64_EXT_SXTW:
            return (guint64) (gint64) (gint32) value;
        default:
            return value;
    }
}

guint64 trace_apply_shift(guint64 value, arm64_shifter type, unsigned int amount) {
    if (amount == 0) return value;
    switch (type) {
        case ARM64_SFT_LSL:
            return value << amount;
        case ARM64_SFT_LSR:
            return value >> amount;
        case ARM64_SFT_ASR:
            return (guint64) ((gint64) value >> amount);
        case ARM64_SFT_ROR:
            return (value >> amount) | (value << (64 - amount));
        case ARM64_SFT_MSL:
            return (value << amount) | ((1ULL << amount) - 1);
        default:
            return value;
    }
}

gboolean trace_calc_mem_addr(MemContext *mem, GumArm64CpuContext *cpu_context, guint64 *addr) {
    guint64 base = 0;
    guint64 index = 0;
    if (mem->base != ARM64_REG_INVALID && !trace_get_reg_value(mem->base, cpu_context, &base)) {
        return FALSE;
    }
    if (mem->index != ARM64_REG_INVALID) {
        if (!trace_get_reg_value(mem->index, cpu_context, &index)) return FALSE;
        index = trace_apply_extend(index, mem->ext);
        index = trace_apply_shift(index, mem->shift_type, mem->shift_value);
    }
    *addr = base + index + mem->disp;
    return TRUE;
}

int trace_append_mem_ops(InsnContext *ctx, GumArm64CpuContext *cpu_context, char *log_line, int offset) {
    for (gsize i = 0; i < ctx->num_mem; ++i) {
        guint64 addr = 0;
        if (!trace_calc_mem_addr(&ctx->mems[i], cpu_context, &addr)) continue;
        offset = trace_advance_offset(offset, snprintf(
                log_line + offset, MAX_LINE_LEN - offset,
                "mem_%c=0x%llx ",
                ctx->mems[i].is_write ? 'w' : 'r',
                addr
        ));
    }
    return offset;
}

int trace_append_syscall_name(InsnContext *ctx, GumArm64CpuContext *cpu_context, char *log_line, int offset) {
    if (ctx->branch_kind != TRACE_BRANCH_SVC) return offset;
    char *name = resolve_syscall_name((gpointer) cpu_context->x[8]);
    if (name == NULL || name[0] == '\\0') return offset;
    return trace_advance_offset(offset, snprintf(log_line + offset, MAX_LINE_LEN - offset, "syscall=%s ", name));
}

void trace_finalize_pending(GumArm64CpuContext *cpu_context) {
    if (init_info == NULL || !init_info->pending_line || stdout == NULL) return;

    char log_line[MAX_LINE_LEN];
    int offset = 0;
    if (init_info->pending_num_write > 0) {
        offset = trace_advance_offset(offset, snprintf(log_line + offset, MAX_LINE_LEN - offset, " -> "));
        for (gsize i = 0; i < init_info->pending_num_write; ++i) {
            offset = trace_append_reg_value(log_line, offset, init_info->pending_writes[i], cpu_context);
        }
    }
    fwrite(log_line, my_strlen(log_line), 1, stdout);
    fwrite("\\n", 1, 1, stdout);
    init_info->pending_line = FALSE;
    init_info->pending_num_write = 0;
}

void trace_emit_pending_call(GumArm64CpuContext *cpu_context) {
    if (init_info == NULL || !init_info->pending_call || stdout == NULL) return;

    if (init_info->pending_call_kind != TRACE_CALL_JNI && init_info->pending_call_info != NULL) {
        fwrite(init_info->pending_call_info, my_strlen(init_info->pending_call_info), 1, stdout);
        char ret_line[64];
        int n = snprintf(ret_line, sizeof(ret_line), "ret: 0x%llx\\n", cpu_context->x[0]);
        fwrite(ret_line, n, 1, stdout);
    } else {
        char *info = format_call_info(
                init_info->pending_call_kind,
                init_info->pending_call_name,
                (gpointer) init_info->pending_args[0],
                (gpointer) init_info->pending_args[1],
                (gpointer) init_info->pending_args[2],
                (gpointer) init_info->pending_args[3],
                (gpointer) init_info->pending_args[4],
                (gpointer) init_info->pending_args[5],
                (gpointer) init_info->pending_args[6],
                (gpointer) init_info->pending_args[7],
                (gpointer) cpu_context->x[0],
                (gpointer) init_info->pending_syscall_nr
        );
        if (info != NULL && info[0] != '\\0') {
            fwrite(info, my_strlen(info), 1, stdout);
        }
    }
    init_info->pending_call = FALSE;
    init_info->pending_call_kind = TRACE_CALL_NONE;
    init_info->pending_call_name = NULL;
    if (init_info->pending_call_info != NULL) {
        g_free(init_info->pending_call_info);
        init_info->pending_call_info = NULL;
    }
    init_info->pending_call_address = 0;
    init_info->pending_syscall_nr = 0;
}

gboolean trace_get_branch_target(InsnContext *ctx, GumArm64CpuContext *cpu_context, guint64 *target) {
    if (ctx->branch_kind == TRACE_BRANCH_IMM) {
        *target = ctx->branch_imm;
        return TRUE;
    }
    if (ctx->branch_kind == TRACE_BRANCH_REG) {
        return trace_get_reg_value(ctx->branch_reg, cpu_context, target);
    }
    return FALSE;
}

void trace_save_pending_call(InsnContext *ctx, GumArm64CpuContext *cpu_context) {
    if (init_info == NULL) return;

    char *name = NULL;
    int kind = TRACE_CALL_NONE;
    guint64 address = 0;
    guint64 syscall_nr = 0;

    if (ctx->branch_kind == TRACE_BRANCH_SVC) {
        syscall_nr = cpu_context->x[8];
        name = resolve_syscall_name((gpointer) syscall_nr);
        if (name != NULL && name[0] != 0) {
            kind = TRACE_CALL_SYSCALL;
        }
    } else if (trace_get_branch_target(ctx, cpu_context, &address) && address != 0) {
        if (address >= init_info->start && address < init_info->end) return;
        name = resolve_jni_name((gpointer) address);
        if (name != NULL && name[0] != '\\0') {
            kind = TRACE_CALL_JNI;
        } else {
            name = resolve_func_name((gpointer) address);
            if (name != NULL && name[0] != '\\0') {
                kind = TRACE_CALL_FUNC;
            }
        }
    }

    if (kind == TRACE_CALL_NONE || name == NULL || name[0] == '\\0') return;

    init_info->pending_call = TRUE;
    init_info->pending_call_kind = kind;
    init_info->pending_call_name = name;
    init_info->pending_call_address = address;
    init_info->pending_syscall_nr = syscall_nr;
    for (int i = 0; i < 8; ++i) {
        init_info->pending_args[i] = cpu_context->x[i];
    }
    if (kind != TRACE_CALL_JNI) {
        char *before = format_call_before(
                kind,
                name,
                (gpointer) init_info->pending_args[0],
                (gpointer) init_info->pending_args[1],
                (gpointer) init_info->pending_args[2],
                (gpointer) init_info->pending_args[3],
                (gpointer) init_info->pending_args[4],
                (gpointer) init_info->pending_args[5],
                (gpointer) init_info->pending_args[6],
                (gpointer) init_info->pending_args[7],
                (gpointer) syscall_nr
        );
        if (before != NULL && before[0] != '\\0') {
            init_info->pending_call_info = g_strdup(before);
        }
    }
}

void stalker_callout(GumArm64CpuContext *cpu_context, gpointer user_data) {
    InsnContext *ctx = (InsnContext *) user_data;
    char log_line[MAX_LINE_LEN];
    int offset = 0;

    if (init_info == NULL || stdout == NULL) {
        return;
    }

    trace_finalize_pending(cpu_context);
    trace_emit_pending_call(cpu_context);

    offset = trace_advance_offset(offset, snprintf(
            log_line + offset, MAX_LINE_LEN - offset,
            "[%s] 0x%llx!0x%llx %s; ",
            init_info->module_name ? init_info->module_name : default_module_name,
            ctx->address,
            ctx->address - init_info->start,
            ctx->instruction
    ));
    offset = trace_append_pre_regs(ctx, cpu_context, log_line, offset);
    offset = trace_append_mem_ops(ctx, cpu_context, log_line, offset);
    offset = trace_append_syscall_name(ctx, cpu_context, log_line, offset);

    fwrite(log_line, my_strlen(log_line), 1, stdout);
    if (ctx->num_write > 0) {
        init_info->pending_num_write = ctx->num_write;
        for (gsize i = 0; i < ctx->num_write; ++i) {
            init_info->pending_writes[i] = ctx->regs_write[i];
        }
        init_info->pending_line = TRUE;
    } else {
        fwrite("\\n", 1, 1, stdout);
    }

    trace_save_pending_call(ctx, cpu_context);
}

void transformer_callback_trace(GumStalkerIterator *iterator,
                                GumStalkerOutput *output, gpointer user_data) {
    if (init_info == NULL) return;
    while (true) {
        const cs_insn *insn;

        if (!gum_stalker_iterator_next(iterator, &insn)) {
            break;
        }

        if (gum_stalker_iterator_get_memory_access(iterator) == GUM_MEMORY_ACCESS_EXCLUSIVE) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        if (trace_is_cas_mnemonic(insn->mnemonic)) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }
        
        /* 地址过滤 */
        if (insn->address < init_info->start || insn->address >= init_info->end) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        /* 解析指令操作数 */
        InsnContext *ctx = g_malloc0(sizeof(InsnContext));
        ctx->address = insn->address;
        ctx->branch_kind = TRACE_BRANCH_NONE;
        ctx->branch_reg = ARM64_REG_INVALID;
        snprintf(ctx->mnemonic, sizeof(ctx->mnemonic), "%s", insn->mnemonic);
        if (insn->op_str[0]) {
            snprintf(ctx->instruction, sizeof(ctx->instruction), "%s %s", insn->mnemonic, insn->op_str);
        } else {
            snprintf(ctx->instruction, sizeof(ctx->instruction), "%s", insn->mnemonic);
        }
        gboolean writeback = (my_contains(insn->op_str, "]!") || my_contains(insn->op_str, "],"));
        cs_arm64_op *ops = insn->detail->arm64.operands;
        for (int i = 0; i < insn->detail->arm64.op_count; ++i) {
            switch (ops[i].type) {
                case ARM64_OP_REG:
                    if (insn->detail->arm64.operands[i].access & CS_AC_READ) {
                        trace_add_reg(ctx->regs_read, &ctx->num_read, ops[i].reg);
                    }
                    if (insn->detail->arm64.operands[i].access & CS_AC_WRITE) {
                        trace_add_reg(ctx->regs_write, &ctx->num_write, ops[i].reg);
                    }
                    break;
                case ARM64_OP_MEM:
                    trace_add_reg(ctx->regs_read, &ctx->num_read, ops[i].mem.base);
                    trace_add_reg(ctx->regs_read, &ctx->num_read, ops[i].mem.index);
                    if (writeback) {
                        trace_add_reg(ctx->regs_write, &ctx->num_write, ops[i].mem.base);
                    }
                    if (ctx->num_mem < MAX_TRACE_MEMS) {
                        MemContext *mem = &ctx->mems[ctx->num_mem++];
                        mem->base = ops[i].mem.base;
                        mem->index = ops[i].mem.index;
                        mem->disp = ops[i].mem.disp;
                        mem->shift_type = ops[i].shift.type;
                        mem->shift_value = ops[i].shift.value;
                        mem->ext = ops[i].ext;
                        if (insn->mnemonic[0] == 's' || insn->mnemonic[0] == 'S') {
                            mem->is_write = TRUE;
                        } else if (insn->mnemonic[0] == 'l' || insn->mnemonic[0] == 'L') {
                            mem->is_write = FALSE;
                        } else {
                            mem->is_write = (ops[i].access & CS_AC_WRITE) ? TRUE : FALSE;
                        }
                    }
                    break;
                default:
                    break;
            }
        }

        if (trace_is_ret_mnemonic(insn->mnemonic)) {
            trace_add_reg(ctx->regs_read, &ctx->num_read, ARM64_REG_X0);
        }

        if (my_streq(insn->mnemonic, "svc")) {
            trace_add_reg(ctx->regs_read, &ctx->num_read, ARM64_REG_X8);
            trace_add_reg(ctx->regs_read, &ctx->num_read, ARM64_REG_X0);
            trace_add_reg(ctx->regs_read, &ctx->num_read, ARM64_REG_X1);
            trace_add_reg(ctx->regs_read, &ctx->num_read, ARM64_REG_X2);
            trace_add_reg(ctx->regs_read, &ctx->num_read, ARM64_REG_X3);
            trace_add_reg(ctx->regs_read, &ctx->num_read, ARM64_REG_X4);
            trace_add_reg(ctx->regs_read, &ctx->num_read, ARM64_REG_X5);
            trace_add_reg(ctx->regs_write, &ctx->num_write, ARM64_REG_X0);
            ctx->branch_kind = TRACE_BRANCH_SVC;
        } else if (my_streq(insn->mnemonic, "bl") ||
                   my_streq(insn->mnemonic, "b") ||
                   trace_is_pac_link_branch(insn->mnemonic)) {
            if (insn->detail->arm64.op_count > 0) {
                if (ops[0].type == ARM64_OP_IMM) {
                    ctx->branch_kind = TRACE_BRANCH_IMM;
                    ctx->branch_imm = ops[0].imm;
                } else if (ops[0].type == ARM64_OP_REG) {
                    ctx->branch_kind = TRACE_BRANCH_REG;
                    ctx->branch_reg = ops[0].reg;
                }
            }
        } else if (my_streq(insn->mnemonic, "blr") ||
                   my_streq(insn->mnemonic, "br") ||
                   trace_is_pac_branch(insn->mnemonic)) {
            if (insn->detail->arm64.op_count > 0 && ops[0].type == ARM64_OP_REG) {
                ctx->branch_kind = TRACE_BRANCH_REG;
                ctx->branch_reg = ops[0].reg;
            }
        }

        gum_stalker_iterator_put_callout(iterator,
                                         (GumStalkerCallout) stalker_callout,
                                         ctx,
                                         (GDestroyNotify) g_free);
        gum_stalker_iterator_keep(iterator);
    }
}
`

    const NULL = ptr(0);
    const annotationScratch = Memory.alloc(256 * 1024);
    const symbolCStringCache = new Map();
    const funcNameByAddress = new Map();
    const jniNameByAddress = new Map();
    const symbolModulesPrepared = new Set();
    const jniClassesByHandle = new Map();
    const jniMethodsByHandle = new Map();
    const jniMethodClassesByHandle = new Map();
    const cStringPins = [];
    var resolverPrepared = false;

    const syscallNames = {
        0: 'io_setup', 1: 'io_destroy', 2: 'io_submit', 3: 'io_cancel', 4: 'io_getevents',
        5: 'setxattr', 6: 'lsetxattr', 7: 'fsetxattr', 8: 'getxattr', 9: 'lgetxattr',
        10: 'fgetxattr', 11: 'listxattr', 12: 'llistxattr', 13: 'flistxattr', 14: 'removexattr',
        15: 'lremovexattr', 16: 'fremovexattr', 17: 'getcwd', 18: 'lookup_dcookie', 19: 'eventfd2',
        20: 'epoll_create1', 21: 'epoll_ctl', 22: 'epoll_pwait', 23: 'dup', 24: 'dup3',
        25: 'fcntl', 26: 'inotify_init1', 27: 'inotify_add_watch', 28: 'inotify_rm_watch',
        29: 'ioctl', 30: 'ioprio_set', 31: 'ioprio_get', 32: 'flock', 33: 'mknodat',
        34: 'mkdirat', 35: 'unlinkat', 36: 'symlinkat', 37: 'linkat', 38: 'renameat',
        39: 'umount2', 40: 'mount', 41: 'pivot_root', 42: 'nfsservctl', 43: 'statfs',
        44: 'fstatfs', 45: 'truncate', 46: 'ftruncate', 47: 'fallocate', 48: 'faccessat',
        49: 'chdir', 50: 'fchdir', 51: 'chroot', 52: 'fchmod', 53: 'fchmodat',
        54: 'fchownat', 55: 'fchown', 56: 'openat', 57: 'close', 58: 'vhangup',
        59: 'pipe2', 60: 'quotactl', 61: 'getdents64', 62: 'lseek', 63: 'read',
        64: 'write', 65: 'readv', 66: 'writev', 67: 'pread64', 68: 'pwrite64',
        69: 'preadv', 70: 'pwritev', 71: 'sendfile', 72: 'pselect6', 73: 'ppoll',
        74: 'signalfd4', 75: 'vmsplice', 76: 'splice', 77: 'tee', 78: 'readlinkat',
        79: 'fstatat', 80: 'fstat', 81: 'sync', 82: 'fsync', 83: 'fdatasync',
        84: 'sync_file_range', 85: 'timerfd_create', 86: 'timerfd_settime', 87: 'timerfd_gettime',
        88: 'utimensat', 89: 'acct', 90: 'capget', 91: 'capset', 92: 'personality',
        93: 'exit', 94: 'exit_group', 95: 'waitid', 96: 'set_tid_address', 97: 'unshare',
        98: 'futex', 99: 'set_robust_list', 100: 'get_robust_list', 101: 'nanosleep',
        102: 'getitimer', 103: 'setitimer', 104: 'kexec_load', 105: 'init_module', 106: 'delete_module',
        107: 'timer_create', 108: 'timer_gettime', 109: 'timer_getoverrun', 110: 'timer_settime',
        111: 'timer_delete', 112: 'clock_settime', 113: 'clock_gettime', 114: 'clock_getres',
        115: 'clock_nanosleep', 116: 'syslog', 117: 'ptrace', 118: 'sched_setparam',
        119: 'sched_setscheduler', 120: 'sched_getscheduler', 121: 'sched_getparam',
        122: 'sched_setaffinity', 123: 'sched_getaffinity', 124: 'sched_yield',
        125: 'sched_get_priority_max', 126: 'sched_get_priority_min', 127: 'sched_rr_get_interval',
        128: 'restart_syscall', 129: 'kill', 130: 'tkill', 131: 'tgkill', 132: 'sigaltstack',
        133: 'rt_sigsuspend', 134: 'rt_sigaction', 135: 'rt_sigprocmask', 136: 'rt_sigpending',
        137: 'rt_sigtimedwait', 138: 'rt_sigqueueinfo', 139: 'rt_sigreturn', 140: 'setpriority',
        141: 'getpriority', 142: 'reboot', 143: 'setregid', 144: 'setgid', 145: 'setreuid',
        146: 'setuid', 147: 'setresuid', 148: 'getresuid', 149: 'setresgid', 150: 'getresgid',
        151: 'setfsuid', 152: 'setfsgid', 153: 'times', 154: 'setpgid', 155: 'getpgid',
        156: 'getsid', 157: 'setsid', 158: 'getgroups', 159: 'setgroups', 160: 'uname',
        161: 'sethostname', 162: 'setdomainname', 163: 'getrlimit', 164: 'setrlimit',
        165: 'getrusage', 166: 'umask', 167: 'prctl', 168: 'getcpu', 169: 'gettimeofday',
        170: 'settimeofday', 171: 'adjtimex', 172: 'getpid', 173: 'getppid', 174: 'getuid',
        175: 'geteuid', 176: 'getgid', 177: 'getegid', 178: 'gettid', 179: 'sysinfo',
        180: 'mq_open', 181: 'mq_unlink', 182: 'mq_timedsend', 183: 'mq_timedreceive',
        184: 'mq_notify', 185: 'mq_getsetattr', 186: 'msgget', 187: 'msgctl', 188: 'msgrcv',
        189: 'msgsnd', 190: 'semget', 191: 'semctl', 192: 'semtimedop', 193: 'semop',
        194: 'shmget', 195: 'shmctl', 196: 'shmat', 197: 'shmdt', 198: 'socket',
        199: 'socketpair', 200: 'bind', 201: 'listen', 202: 'accept', 203: 'connect',
        204: 'getsockname', 205: 'getpeername', 206: 'sendto', 207: 'recvfrom',
        208: 'setsockopt', 209: 'getsockopt', 210: 'shutdown', 211: 'sendmsg', 212: 'recvmsg',
        213: 'readahead', 214: 'brk', 215: 'munmap', 216: 'mremap', 217: 'add_key',
        218: 'request_key', 219: 'keyctl', 220: 'clone', 221: 'execve', 222: 'mmap',
        223: 'fadvise64', 224: 'swapon', 225: 'swapoff', 226: 'mprotect', 227: 'msync',
        228: 'mlock', 229: 'munlock', 230: 'mlockall', 231: 'munlockall', 232: 'mincore',
        233: 'madvise', 234: 'remap_file_pages', 235: 'mbind', 236: 'get_mempolicy',
        237: 'set_mempolicy', 238: 'migrate_pages', 239: 'move_pages', 240: 'rt_tgsigqueueinfo',
        241: 'perf_event_open', 242: 'accept4', 243: 'recvmmsg', 244: 'arch_specific_syscall',
        260: 'wait4', 261: 'prlimit64', 262: 'fanotify_init', 263: 'fanotify_mark',
        264: 'name_to_handle_at', 265: 'open_by_handle_at', 266: 'clock_adjtime',
        267: 'syncfs', 268: 'setns', 269: 'sendmmsg', 270: 'process_vm_readv',
        271: 'process_vm_writev', 272: 'kcmp', 273: 'finit_module', 274: 'sched_setattr',
        275: 'sched_getattr', 276: 'renameat2', 277: 'seccomp', 278: 'getrandom',
        279: 'memfd_create', 280: 'bpf', 281: 'execveat', 282: 'userfaultfd',
        283: 'membarrier', 284: 'mlock2', 285: 'copy_file_range', 286: 'preadv2',
        287: 'pwritev2', 288: 'pkey_mprotect', 289: 'pkey_alloc', 290: 'pkey_free',
        291: 'statx'
    };

    const jniFunctionNames = [
        'reserved0', 'reserved1', 'reserved2', 'reserved3', 'GetVersion', 'DefineClass', 'FindClass',
        'FromReflectedMethod', 'FromReflectedField', 'ToReflectedMethod', 'GetSuperclass', 'IsAssignableFrom',
        'ToReflectedField', 'Throw', 'ThrowNew', 'ExceptionOccurred', 'ExceptionDescribe', 'ExceptionClear',
        'FatalError', 'PushLocalFrame', 'PopLocalFrame', 'NewGlobalRef', 'DeleteGlobalRef', 'DeleteLocalRef',
        'IsSameObject', 'NewLocalRef', 'EnsureLocalCapacity', 'AllocObject', 'NewObject', 'NewObjectV', 'NewObjectA',
        'GetObjectClass', 'IsInstanceOf', 'GetMethodID', 'CallObjectMethod', 'CallObjectMethodV', 'CallObjectMethodA',
        'CallBooleanMethod', 'CallBooleanMethodV', 'CallBooleanMethodA', 'CallByteMethod', 'CallByteMethodV', 'CallByteMethodA',
        'CallCharMethod', 'CallCharMethodV', 'CallCharMethodA', 'CallShortMethod', 'CallShortMethodV', 'CallShortMethodA',
        'CallIntMethod', 'CallIntMethodV', 'CallIntMethodA', 'CallLongMethod', 'CallLongMethodV', 'CallLongMethodA',
        'CallFloatMethod', 'CallFloatMethodV', 'CallFloatMethodA', 'CallDoubleMethod', 'CallDoubleMethodV', 'CallDoubleMethodA',
        'CallVoidMethod', 'CallVoidMethodV', 'CallVoidMethodA', 'CallNonvirtualObjectMethod', 'CallNonvirtualObjectMethodV',
        'CallNonvirtualObjectMethodA', 'CallNonvirtualBooleanMethod', 'CallNonvirtualBooleanMethodV', 'CallNonvirtualBooleanMethodA',
        'CallNonvirtualByteMethod', 'CallNonvirtualByteMethodV', 'CallNonvirtualByteMethodA', 'CallNonvirtualCharMethod',
        'CallNonvirtualCharMethodV', 'CallNonvirtualCharMethodA', 'CallNonvirtualShortMethod', 'CallNonvirtualShortMethodV',
        'CallNonvirtualShortMethodA', 'CallNonvirtualIntMethod', 'CallNonvirtualIntMethodV', 'CallNonvirtualIntMethodA',
        'CallNonvirtualLongMethod', 'CallNonvirtualLongMethodV', 'CallNonvirtualLongMethodA', 'CallNonvirtualFloatMethod',
        'CallNonvirtualFloatMethodV', 'CallNonvirtualFloatMethodA', 'CallNonvirtualDoubleMethod', 'CallNonvirtualDoubleMethodV',
        'CallNonvirtualDoubleMethodA', 'CallNonvirtualVoidMethod', 'CallNonvirtualVoidMethodV', 'CallNonvirtualVoidMethodA',
        'GetFieldID', 'GetObjectField', 'GetBooleanField', 'GetByteField', 'GetCharField', 'GetShortField', 'GetIntField',
        'GetLongField', 'GetFloatField', 'GetDoubleField', 'SetObjectField', 'SetBooleanField', 'SetByteField', 'SetCharField',
        'SetShortField', 'SetIntField', 'SetLongField', 'SetFloatField', 'SetDoubleField', 'GetStaticMethodID', 'CallStaticObjectMethod',
        'CallStaticObjectMethodV', 'CallStaticObjectMethodA', 'CallStaticBooleanMethod', 'CallStaticBooleanMethodV',
        'CallStaticBooleanMethodA', 'CallStaticByteMethod', 'CallStaticByteMethodV', 'CallStaticByteMethodA', 'CallStaticCharMethod',
        'CallStaticCharMethodV', 'CallStaticCharMethodA', 'CallStaticShortMethod', 'CallStaticShortMethodV', 'CallStaticShortMethodA',
        'CallStaticIntMethod', 'CallStaticIntMethodV', 'CallStaticIntMethodA', 'CallStaticLongMethod', 'CallStaticLongMethodV',
        'CallStaticLongMethodA', 'CallStaticFloatMethod', 'CallStaticFloatMethodV', 'CallStaticFloatMethodA', 'CallStaticDoubleMethod',
        'CallStaticDoubleMethodV', 'CallStaticDoubleMethodA', 'CallStaticVoidMethod', 'CallStaticVoidMethodV', 'CallStaticVoidMethodA',
        'GetStaticFieldID', 'GetStaticObjectField', 'GetStaticBooleanField', 'GetStaticByteField', 'GetStaticCharField', 'GetStaticShortField',
        'GetStaticIntField', 'GetStaticLongField', 'GetStaticFloatField', 'GetStaticDoubleField', 'SetStaticObjectField', 'SetStaticBooleanField',
        'SetStaticByteField', 'SetStaticCharField', 'SetStaticShortField', 'SetStaticIntField', 'SetStaticLongField', 'SetStaticFloatField',
        'SetStaticDoubleField', 'NewString', 'GetStringLength', 'GetStringChars', 'ReleaseStringChars', 'NewStringUTF', 'GetStringUTFLength',
        'GetStringUTFChars', 'ReleaseStringUTFChars', 'GetArrayLength', 'NewObjectArray', 'GetObjectArrayElement', 'SetObjectArrayElement',
        'NewBooleanArray', 'NewByteArray', 'NewCharArray', 'NewShortArray', 'NewIntArray', 'NewLongArray', 'NewFloatArray', 'NewDoubleArray',
        'GetBooleanArrayElements', 'GetByteArrayElements', 'GetCharArrayElements', 'GetShortArrayElements', 'GetIntArrayElements', 'GetLongArrayElements',
        'GetFloatArrayElements', 'GetDoubleArrayElements', 'ReleaseBooleanArrayElements', 'ReleaseByteArrayElements', 'ReleaseCharArrayElements',
        'ReleaseShortArrayElements', 'ReleaseIntArrayElements', 'ReleaseLongArrayElements', 'ReleaseFloatArrayElements', 'ReleaseDoubleArrayElements',
        'GetBooleanArrayRegion', 'GetByteArrayRegion', 'GetCharArrayRegion', 'GetShortArrayRegion', 'GetIntArrayRegion', 'GetLongArrayRegion',
        'GetFloatArrayRegion', 'GetDoubleArrayRegion', 'SetBooleanArrayRegion', 'SetByteArrayRegion', 'SetCharArrayRegion',
        'SetShortArrayRegion', 'SetIntArrayRegion', 'SetLongArrayRegion', 'SetFloatArrayRegion', 'SetDoubleArrayRegion',
        'RegisterNatives', 'UnregisterNatives', 'MonitorEnter', 'MonitorExit', 'GetJavaVM', 'GetStringRegion',
        'GetStringUTFRegion', 'GetPrimitiveArrayCritical', 'ReleasePrimitiveArrayCritical', 'GetStringCritical', 'ReleaseStringCritical',
        'NewWeakGlobalRef', 'DeleteWeakGlobalRef', 'ExceptionCheck', 'NewDirectByteBuffer', 'GetDirectBufferAddress',
        'GetDirectBufferCapacity', 'GetObjectRefType'
    ];

    const callJniMethods = new Set([
        'CallStaticObjectMethod', 'CallStaticObjectMethodV', 'CallStaticObjectMethodA',
        'CallStaticBooleanMethod', 'CallStaticBooleanMethodV', 'CallStaticBooleanMethodA',
        'CallStaticByteMethod', 'CallStaticByteMethodV', 'CallStaticByteMethodA',
        'CallStaticCharMethod', 'CallStaticCharMethodV', 'CallStaticCharMethodA',
        'CallStaticShortMethod', 'CallStaticShortMethodV', 'CallStaticShortMethodA',
        'CallStaticIntMethod', 'CallStaticIntMethodV', 'CallStaticIntMethodA',
        'CallStaticLongMethod', 'CallStaticLongMethodV', 'CallStaticLongMethodA',
        'CallStaticFloatMethod', 'CallStaticFloatMethodV', 'CallStaticFloatMethodA',
        'CallStaticDoubleMethod', 'CallStaticDoubleMethodV', 'CallStaticDoubleMethodA',
        'CallStaticVoidMethod', 'CallStaticVoidMethodV', 'CallStaticVoidMethodA',
        'CallObjectMethod', 'CallObjectMethodV', 'CallObjectMethodA',
        'CallBooleanMethod', 'CallBooleanMethodV', 'CallBooleanMethodA',
        'CallByteMethod', 'CallByteMethodV', 'CallByteMethodA',
        'CallCharMethod', 'CallCharMethodV', 'CallCharMethodA',
        'CallShortMethod', 'CallShortMethodV', 'CallShortMethodA',
        'CallIntMethod', 'CallIntMethodV', 'CallIntMethodA',
        'CallLongMethod', 'CallLongMethodV', 'CallLongMethodA',
        'CallFloatMethod', 'CallFloatMethodV', 'CallFloatMethodA',
        'CallDoubleMethod', 'CallDoubleMethodV', 'CallDoubleMethodA',
        'CallVoidMethod', 'CallVoidMethodV', 'CallVoidMethodA',
        'CallNonvirtualObjectMethod', 'CallNonvirtualObjectMethodV', 'CallNonvirtualObjectMethodA',
        'CallNonvirtualBooleanMethod', 'CallNonvirtualBooleanMethodV', 'CallNonvirtualBooleanMethodA',
        'CallNonvirtualByteMethod', 'CallNonvirtualByteMethodV', 'CallNonvirtualByteMethodA',
        'CallNonvirtualCharMethod', 'CallNonvirtualCharMethodV', 'CallNonvirtualCharMethodA',
        'CallNonvirtualShortMethod', 'CallNonvirtualShortMethodV', 'CallNonvirtualShortMethodA',
        'CallNonvirtualIntMethod', 'CallNonvirtualIntMethodV', 'CallNonvirtualIntMethodA',
        'CallNonvirtualLongMethod', 'CallNonvirtualLongMethodV', 'CallNonvirtualLongMethodA',
        'CallNonvirtualFloatMethod', 'CallNonvirtualFloatMethodV', 'CallNonvirtualFloatMethodA',
        'CallNonvirtualDoubleMethod', 'CallNonvirtualDoubleMethodV', 'CallNonvirtualDoubleMethodA',
        'CallNonvirtualVoidMethod', 'CallNonvirtualVoidMethodV', 'CallNonvirtualVoidMethodA'
    ]);

    const FUNC_CONFIGS = {
        strstr: { p: 2, s: [0, 1] }, strlen: { p: 1, s: [0] }, __strlen_chk: { p: 1, s: [0] }, __strlen_aarch64: { p: 1, s: [0] },
        strcmp: { p: 2, s: [0, 1] }, strncmp: { p: 2, s: [0, 1] }, __strncmp_aarch64: { p: 2, s: [0, 1] },
        strcpy: { p: 2, s: [0, 1] }, __strcpy_chk: { p: 2, s: [0, 1] }, strncpy: { p: 2, s: [0, 1] }, __strncpy_chk: { p: 2, s: [0, 1] },
        strcat: { p: 2, s: [0, 1] }, __strcat_chk: { p: 2, s: [0, 1] }, strncat: { p: 2, s: [0, 1] }, __strncat_chk: { p: 2, s: [0, 1] },
        strdup: { p: 1, s: [0] }, __strdup_chk: { p: 1, s: [0] }, strndup: { p: 1, s: [0] }, __strndup_chk: { p: 1, s: [0] },
        strchr: { p: 1, s: [0] }, strrchr: { p: 1, s: [0] }, strspn: { p: 1, s: [0] }, strcspn: { p: 1, s: [0] },
        strcasestr: { p: 1, s: [0] }, strlcpy: { p: 3, s: [0, 1] }, __strlcpy_chk: { p: 3, s: [0, 1] },
        strlcat: { p: 3, s: [0, 1] }, __strlcat_chk: { p: 3, s: [0, 1] },
        memcpy: { p: 3, h: [[1, 2]] }, __memcpy_chk: { p: 3, h: [[1, 2]] }, __memcpy_aarch64_simd: { p: 3, h: [[1, 2]] },
        memmove: { p: 3, h: [[1, 2]] }, __memmove_chk: { p: 3, h: [[1, 2]] }, memset: { p: 3 }, __memset_chk: { p: 3 }, __memset_aarch64: { p: 3 },
        memmem: { p: 4, h: [[0, 1], [2, 3]] }, memcmp: { p: 3, h: [[0, 2], [1, 2]] }, __memcmp_aarch64: { p: 3, h: [[0, 2], [1, 2]] },
        memchr: { p: 3, s: [0] }, __memchr_aarch64: { p: 3, s: [0] },
        fopen: { p: 2, s: [0, 1] }, fopen64: { p: 2, s: [0, 1] }, open: { p: 2, s: [0] }, openat: { p: 4, s: [1] },
        read: { p: 3, h: [[1, 2]] }, pread64: { p: 3, h: [[1, 2]] }, write: { p: 3, h: [[1, 2]] }, pwrite64: { p: 3, h: [[1, 2]] },
        readlink: { p: 3, s: [0, 1] }, readlinkat: { p: 4, s: [1, 2] }, stat: { p: 2, s: [0] }, access: { p: 2, s: [0] },
        mknodat: { p: 4, s: [1] }, mkdirat: { p: 3, s: [1] }, fstatat: { p: 4, s: [1] }, newfstatat: { p: 4, s: [1] },
        opendir: { p: 1, s: [0] }, popen: { p: 2, s: [0, 1] }, close: { p: 1 }, fstat: { p: 2 }, pclose: { p: 1 },
        sprintf: { p: 2, s: [0, 1] }, __sprintf_chk: { p: 2, s: [0, 1] }, snprintf: { p: 3, s: [0] }, __snprintf_chk: { p: 3, s: [0] },
        vsprintf: { p: 2, s: [0] }, __vsprintf_chk: { p: 2, s: [0] }, vsnprintf: { p: 3, s: [0] }, __vsnprintf_chk: { p: 3, s: [0] },
        fgets: { p: 3, s: [0] }, __fgets_chk: { p: 3, s: [0] }, sscanf: { p: 2, s: [0, 1] },
        calloc: { p: 2 }, malloc: { p: 1 }, realloc: { p: 2, h: [[0, 32]] }, free: { p: 1, h: [[0, 32]] }, aligned_alloc: { p: 2 },
        mmap: { p: 6 }, mmap64: { p: 6 }, mprotect: { p: 3 }, dlopen: { p: 2, s: [0] }, dlsym: { p: 2, s: [1] }, dlclose: { p: 1 },
        sysconf: { p: 1 }, __system_property_get: { p: 2, s: [0, 1] }, gettimeofday: { p: 2, h: [[0, 32]] },
        srand48: { p: 1 }, arc4random_buf: { p: 2, h: [[0, 1]] }, syscall: { p: 1 }
    };

    const JNI_CONFIGS = {
        FindClass: { p: 2, s: [1] }, GetMethodID: { p: 4, s: [2, 3] }, GetStaticMethodID: { p: 4, s: [2, 3] },
        DefineClass: { p: 5, s: [1], h: [[3, 4]] },
        NewStringUTF: { p: 2, s: [1] }, ReleaseStringUTFChars: { p: 3, s: [2] },
        GetStringRegion: { p: 5 }, GetStringUTFRegion: { p: 5, h: [[4, 3]] },
        GetByteArrayRegion: { p: 5, h: [[4, 3]] }, SetByteArrayRegion: { p: 5, h: [[4, 3]] },
        NewString: { p: 2 }, GetStringLength: { p: 2 }, GetStringUTFLength: { p: 2 },
        GetStringChars: { p: 3 }, GetStringUTFChars: { p: 3, retStringAsArg: 1 }, GetArrayLength: { p: 2 },
        GetByteArrayElements: { p: 3, retH: 32 }, RegisterNatives: { p: 4, natives: true }
    };

    function ptrKey(p) { return ptr(p).toString(); }
    function ptrToNum(p) {
        const s = ptr(p).toString();
        return parseInt(s.indexOf('0x') === 0 ? s.slice(2) : s, 16);
    }
    function isLikelyUserPointer(p) {
        const text = ptr(p).toString();
        if (text.indexOf('0xffff') === 0) return false;
        const value = ptrToNum(p);
        return value >= 0x100000000;
    }
    function hexPtr(p) { return ptr(p).toString(); }
    function readCStringArg(p, maxLen) {
        if (typeof p === 'string') return p;
        try {
            return ptr(p).readUtf8String(maxLen || 4096) || '';
        } catch (_) {
            try { return ptr(p).readCString(maxLen || 4096) || ''; } catch (_) {}
        }
        return '';
    }
    function pinUtf8CString(value, maxLen) {
        const s = (typeof value === 'string') ? value : readCStringArg(value, maxLen || 4096);
        const p = Memory.allocUtf8String(s || '');
        cStringPins.push(p);
        return p;
    }
    function cacheCString(s) {
        if (!s) return NULL;
        let p = symbolCStringCache.get(s);
        if (!p) {
            p = Memory.allocUtf8String(s);
            symbolCStringCache.set(s, p);
        }
        return p;
    }
    function scratchCString(s) {
        if (s.length > 250000) s = s.slice(0, 250000) + '\n';
        annotationScratch.writeUtf8String(s);
        return annotationScratch;
    }
    function sanitizeSymbolName(name) {
        if (!name) return null;
        const at = name.indexOf('@');
        if (at > 0) name = name.slice(0, at);
        return name;
    }
    function addSymbol(address, name) {
        if (!address || ptr(address).isNull() || !name) return;
        name = sanitizeSymbolName(name);
        if (!name || name.indexOf(' ') !== -1) return;
        const key = ptrKey(address);
        if (!funcNameByAddress.has(key)) funcNameByAddress.set(key, name);
    }
    function enumerateExportsCompat(m) {
        try {
            if (m.enumerateExports) return m.enumerateExports();
        } catch (_) {}
        try {
            if (Module.enumerateExportsSync) return Module.enumerateExportsSync(m.name);
        } catch (_) {}
        try {
            if (Module.enumerateExports) return Module.enumerateExports(m.name);
        } catch (_) {}
        return [];
    }
    function enumerateSymbolsCompat(m) {
        try {
            if (m.enumerateSymbols) return m.enumerateSymbols();
        } catch (_) {}
        try {
            if (Module.enumerateSymbolsSync) return Module.enumerateSymbolsSync(m.name);
        } catch (_) {}
        try {
            if (Module.enumerateSymbols) return Module.enumerateSymbols(m.name);
        } catch (_) {}
        return [];
    }
    function shouldEnumerateSymbols(m, targetModuleName) {
        if (targetModuleName && m.name === targetModuleName) return true;
        if (m.name === 'libc.so' || m.name === 'libart.so' || m.name === 'libdl.so' ||
            m.name === 'libm.so' || m.name.indexOf('libc++') !== -1 ||
            m.name.indexOf('libmetasec') !== -1 || m.name.indexOf('libsscronet') !== -1) {
            return true;
        }
        const path = m.path || '';
        return path.length > 0 &&
            path.indexOf('/system/') !== 0 &&
            path.indexOf('/system_ext/') !== 0 &&
            path.indexOf('/apex/') !== 0 &&
            path.indexOf('/vendor/') !== 0 &&
            path.indexOf('.odex') === -1 &&
            path.indexOf('memfd') === -1 &&
            m.name.indexOf('.so') !== -1;
    }
    function prepareTraceResolvers(targetModuleName) {
        const modules = Process.enumerateModules();
        if (!resolverPrepared) {
            resolverPrepared = true;
            modules.forEach(function (m) {
                enumerateExportsCompat(m).forEach(function (e) {
                    if (!e.type || e.type === 'function') addSymbol(e.address, e.name);
                });
            });
        }
        modules.forEach(function (m) {
            if (!symbolModulesPrepared.has(m.name) && shouldEnumerateSymbols(m, targetModuleName)) {
                symbolModulesPrepared.add(m.name);
                enumerateSymbolsCompat(m).forEach(function (s) {
                    if (!s.type || s.type === 'function') addSymbol(s.address, s.name);
                });
            }
        });
        buildJniMap();
    }
    function buildJniMap() {
        if (typeof Java === 'undefined' || !Java.available || jniNameByAddress.size !== 0) return;
        try {
            let env = null;
            try { env = Java.vm.tryGetEnv(); } catch (_) {}
            if ((!env || !env.handle) && Java.vm.getEnv) {
                try { env = Java.vm.getEnv(); } catch (_) {}
            }
            if ((!env || !env.handle) && Java.performNow) {
                Java.performNow(function () {
                    try { env = Java.vm.getEnv(); } catch (_) {}
                });
            }
            if (!env || !env.handle) return;
            const table = env.handle.readPointer();
            for (let i = 0; i < jniFunctionNames.length; i++) {
                const name = jniFunctionNames[i];
                if (!name || name.indexOf('reserved') === 0) continue;
                const addr = table.add(i * Process.pointerSize).readPointer();
                if (!addr.isNull()) jniNameByAddress.set(addr.toString(), name);
            }
        } catch (_) {}
    }
    function resolveFuncName(address) {
        if (!resolverPrepared) prepareTraceResolvers();
        const p = ptr(address);
        let name = funcNameByAddress.get(p.toString());
        if (!name) {
            try {
                const ds = DebugSymbol.fromAddress(p);
                if (ds && ds.name && ds.address && ptr(ds.address).equals(p)) {
                    name = sanitizeSymbolName(ds.name);
                }
            } catch (_) {}
        }
        return cacheCString(name);
    }
    function resolveJniName(address) {
        buildJniMap();
        return cacheCString(jniNameByAddress.get(ptr(address).toString()));
    }
    function resolveSyscallName(number) {
        const nr = ptrToNum(number);
        return cacheCString(syscallNames[nr] || ('syscall_' + nr));
    }
    function safeCString(p, maxLen) {
        p = ptr(p);
        if (p.isNull() || !isLikelyUserPointer(p)) return '';
        return readCStringArg(p, maxLen || 1024);
    }
    function hexdumpText(address, length) {
        const p = ptr(address);
        let n = Number(ptrToNum(length));
        if (n === 32 || n <= 0) n = 0x100;
        if (n > 0x1000) n = 0x1000;
        if (p.isNull() || !isLikelyUserPointer(p)) {
            return '\nhexdump at address ' + p + ' with length 0x' + n.toString(16) + ':\n';
        }
        let bytes;
        try {
            bytes = new Uint8Array(p.readByteArray(n));
        } catch (_) {
            return '\nhexdump at address ' + p + ' with length 0x' + n.toString(16) + ':\n';
        }
        let out = '\nhexdump at address ' + p + ' with length 0x' + n.toString(16) + ':\n';
        for (let off = 0; off < bytes.length; off += 16) {
            const chunk = bytes.slice(off, off + 16);
            const hex = Array.prototype.map.call(chunk, b => ('0' + b.toString(16)).slice(-2)).join(' ');
            const ascii = Array.prototype.map.call(chunk, b => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.').join('');
            out += p.add(off).toString().replace(/^0x/, '') + ': ' + hex.padEnd(47, ' ') + ' |' + ascii.padEnd(16, ' ') + '|';
            if (off + 16 < bytes.length) out += '\n';
        }
        return out;
    }
    function formatParams(args, count) {
        const items = [];
        for (let i = 0; i < count; i++) items.push(hexPtr(args[i]));
        return '(' + items.join(', ') + ')';
    }
    function formatCallWithoutRet(prefix, name, args, config) {
        config = config || { p: 0 };
        let out = prefix + name + formatParams(args, config.p || 0);
        (config.s || []).forEach(function (idx) {
            const s = safeCString(args[idx], 1024);
            if (s.length) out += '\nargs' + idx + ': ' + s;
        });
        (config.h || []).forEach(function (pair) {
            out += hexdumpText(args[pair[0]], pair[1] === 32 ? ptr(32) : args[pair[1]]);
        });
        return out;
    }
    function formatWithConfig(prefix, name, args, ret, config) {
        config = config || { p: 0 };
        let out = formatCallWithoutRet(prefix, name, args, config);
        out += '\nret: ' + hexPtr(ret) + '\n';
        return out;
    }
    function appendRegisterNatives(out, args) {
        const methods = ptr(args[2]);
        const count = Math.min(Number(ptrToNum(args[3])) || 0, 64);
        if (methods.isNull() || !isLikelyUserPointer(methods) || count <= 0) return out;
        const stride = Process.pointerSize * 3;
        for (let i = 0; i < count; i++) {
            try {
                const item = methods.add(i * stride);
                const namePtr = item.readPointer();
                const sigPtr = item.add(Process.pointerSize).readPointer();
                const fnPtr = item.add(Process.pointerSize * 2).readPointer();
                const nativeName = safeCString(namePtr, 256);
                const nativeSig = safeCString(sigPtr, 256);
                if (nativeName.length) {
                    out += '\nargs2: ' + nativeName + (nativeSig.length ? ' ' + nativeSig : '') + ' ' + fnPtr;
                    addSymbol(fnPtr, nativeName);
                }
            } catch (_) {
                break;
            }
        }
        return out;
    }
    function formatJniCallInfo(name, args, ret) {
        const config = JNI_CONFIGS[name] || { p: 0 };
        let out = formatCallWithoutRet('call jni func: ', name, args, config);

        if (config.retStringAsArg !== undefined) {
            const s = safeCString(ret, 4096);
            if (s.length) out += '\nargs' + config.retStringAsArg + ': ' + s;
        }
        if (config.retH) {
            out += hexdumpText(ret, ptr(config.retH));
        }
        if (config.natives) {
            out = appendRegisterNatives(out, args);
        }

        const retPtr = ptr(ret);
        if ((name === 'FindClass' || name === 'DefineClass') && !retPtr.isNull()) {
            const className = safeCString(args[1], 1024);
            if (className.length) jniClassesByHandle.set(ptrKey(retPtr), className);
        } else if ((name === 'GetMethodID' || name === 'GetStaticMethodID') && !retPtr.isNull()) {
            const methodName = safeCString(args[2], 1024);
            const methodSig = safeCString(args[3], 1024);
            const className = jniClassesByHandle.get(ptrKey(args[1]));
            if (methodName.length) {
                const fullMethod = methodName + (methodSig.length ? methodSig : '');
                jniMethodsByHandle.set(ptrKey(retPtr), fullMethod);
                if (className) jniMethodClassesByHandle.set(ptrKey(retPtr), className);
            }
            if (className) out += '\nargsjclass: ' + className;
        }

        if (callJniMethods.has(name)) {
            const methodKey = ptrKey(args[2]);
            const methodName = jniMethodsByHandle.get(methodKey);
            const className = jniMethodClassesByHandle.get(methodKey) || jniClassesByHandle.get(ptrKey(args[1]));
            if (methodName) out += '\nargsjmethod: ' + methodName;
            if (className) out += '\nargsjclass: ' + className;
        }

        out += '\nret: ' + hexPtr(ret) + '\n';
        return out;
    }
    function formatCallBefore(kind, namePtr, x0, x1, x2, x3, x4, x5, x6, x7, syscallNr) {
        let name = '';
        try { name = ptr(namePtr).readCString() || ''; } catch (_) {}
        const args = [x0, x1, x2, x3, x4, x5, x6, x7].map(ptr);
        let out = '';
        if (kind === 3) {
            out = formatCallWithoutRet('call func: ', name, args, FUNC_CONFIGS[name] || { p: Math.min(6, args.length) });
        } else if (kind !== 2) {
            if (name === 'syscall') {
                const syscallName = syscallNames[ptrToNum(args[0])] || ('syscall_' + ptrToNum(args[0]));
                out = formatCallWithoutRet('call func: ', syscallName, args.slice(1), FUNC_CONFIGS[syscallName] || { p: 6 });
            } else {
                out = formatCallWithoutRet('call func: ', name, args, FUNC_CONFIGS[name]);
            }
        }
        if (out.length) out += '\n';
        return scratchCString(out);
    }
    function formatCallInfo(kind, namePtr, x0, x1, x2, x3, x4, x5, x6, x7, ret, syscallNr) {
        let name = '';
        try { name = ptr(namePtr).readCString() || ''; } catch (_) {}
        const args = [x0, x1, x2, x3, x4, x5, x6, x7].map(ptr);
        let out;
        if (kind === 3) {
            out = formatWithConfig('call func: ', name, args, ret, FUNC_CONFIGS[name] || { p: Math.min(6, args.length) });
        } else if (kind === 2) {
            out = formatJniCallInfo(name, args, ret);
        } else {
            if (name === 'syscall') {
                const syscallName = syscallNames[ptrToNum(args[0])] || ('syscall_' + ptrToNum(args[0]));
                out = formatWithConfig('call func: ', syscallName, args.slice(1), ret, FUNC_CONFIGS[syscallName] || { p: 6 });
            } else {
                out = formatWithConfig('call func: ', name, args, ret, FUNC_CONFIGS[name]);
            }
        }
        return scratchCString(out);
    }

    const data = Memory.alloc(Process.pointerSize * 2);
    data.writePointer(ptr(0));
    cStringPins.push(data);

    stalker_module = new CModule(code, {
        init_info: data,
        inst_dict: data.add(Process.pointerSize),
        fopen: Module.findExportByName("libc.so", "fopen"),
        fclose: Module.findExportByName("libc.so", "fclose"),
        fwrite: Module.findExportByName("libc.so", "fwrite"),
        snprintf: Module.findExportByName("libc.so", "snprintf"),
        resolve_func_name: new NativeCallback((address) => {
            return resolveFuncName(address);
        }, "pointer", ["pointer"]),
        resolve_jni_name: new NativeCallback((address) => {
            return resolveJniName(address);
        }, "pointer", ["pointer"]),
        resolve_syscall_name: new NativeCallback((number) => {
            return resolveSyscallName(number);
        }, "pointer", ["pointer"]),
        format_call_before: new NativeCallback((
            kind, name, x0, x1, x2, x3, x4, x5, x6, x7, syscallNr
        ) => {
            return formatCallBefore(kind, name, x0, x1, x2, x3, x4, x5, x6, x7, syscallNr);
        }, "pointer", [
            "int", "pointer",
            "pointer", "pointer", "pointer", "pointer",
            "pointer", "pointer", "pointer", "pointer",
            "pointer"
        ]),
        format_call_info: new NativeCallback((
            kind, name, x0, x1, x2, x3, x4, x5, x6, x7, ret, syscallNr
        ) => {
            return formatCallInfo(kind, name, x0, x1, x2, x3, x4, x5, x6, x7, ret, syscallNr);
        }, "pointer", [
            "int", "pointer",
            "pointer", "pointer", "pointer", "pointer",
            "pointer", "pointer", "pointer", "pointer",
            "pointer", "pointer"
        ]),
        send: new NativeCallback((arg0) => {
            console.log(arg0.readUtf8String())
        }, "void", ["pointer"])
    });

    const nativeInitFunc = new NativeFunction(stalker_module.init_func, "pointer", ["pointer", "pointer", "pointer"]);
    const nativeInitFuncWithModule = new NativeFunction(stalker_module.init_func_with_module, "pointer", ["pointer", "pointer", "pointer", "pointer"]);
    const nativeEndFunc = new NativeFunction(stalker_module.end_func, "void", []);

    trace_config_func = {
        prepare_resolvers: prepareTraceResolvers,
        init_func: function (start, end, filename) {
            prepareTraceResolvers();
            return nativeInitFunc(start, end, pinUtf8CString(filename, 4096));
        },
        init_func_with_module: function (start, end, filename, moduleName) {
            const moduleNameString = readCStringArg(moduleName, 256);
            prepareTraceResolvers(moduleNameString);
            return nativeInitFuncWithModule(
                start,
                end,
                pinUtf8CString(filename, 4096),
                pinUtf8CString(moduleNameString, 256)
            );
        },
        end_func: nativeEndFunc
    }
}()


rpc.exports = {
    stalker_module: stalker_module,
    trace_config_func: trace_config_func
}
// 使用示例
// Process.enumerateModules().forEach(_module => {
//     if (_module.name !== so_name) {
//         Stalker.exclude({
//             base: _module.base,
//             size: _module.size
//         })
//     }
// })
// Interceptor.attach(module.base.add(0x8B04C), {
//     onEnter: function () {
//         console.log("[0x8B04C] start")
//         var curTid = Process.getCurrentThreadId();
//         var filename = "/data/data/" + get_self_process_name() + "/files/trace.txt"
//         console.log("[trace] filename", filename)
//         // init函数返回函数指针
//         var file = trace_config_func.init_func_with_module(
//             module.base,
//             module.base.add(module.size),
//             Memory.allocUtf8String(filename),
//             Memory.allocUtf8String(module.name))
//
//         // 初始化相关参数
//         console.log("[trace] file", file, filename, this.context.lr)
//
//         // 开始stalker
//         Stalker.follow(curTid, {
//             // 直接创建block块，什么都不做
//             transform: stalker_module.transformer_callback_trace
//         })
//     },
//     onLeave: function () {
//         Stalker.unfollow();
//         Stalker.garbageCollect();
//         trace_config_func.end_func();
//         console.log("[0x8B04C] end")
//     }
// })

// 如果奔溃了，添加
// if (insn->id == ARM64_INS_LDAXR || insn->id == ARM64_INS_STLXR ||
//     insn->id == ARM64_INS_LDAXRB || insn->id == ARM64_INS_STLXRB ||
//     insn->id == ARM64_INS_LDAXRH || insn->id == ARM64_INS_STLXRH) {
//   gum_stalker_iterator_keep(iterator);
//   continue;
// }
// 如果还是崩溃了，直接用最暴力的方式
//     if (insn->id == ARM64_INS_STP || insn->id == ARM64_INS_STXP || insn->id == ARM64_INS_STNP || insn->id == ARM64_INS_STLXP || insn->id == ARM64_INS_LDP || insn->id == ARM64_INS_LDXP || insn->id == ARM64_INS_LDNP || insn->id == ARM64_INS_CAS || insn->id == ARM64_INS_CASP || insn->id == ARM64_INS_LDADD || insn->id == ARM64_INS_LDARB || insn->id == ARM64_INS_LDARH || insn->id == ARM64_INS_LDAR || insn->id == ARM64_INS_LDAXP || insn->id == ARM64_INS_LDAXR || insn->id == ARM64_INS_LDAXRB || insn->id == ARM64_INS_LDAXRH || insn->id == ARM64_INS_LDCLR || insn->id == ARM64_INS_LDEOR || insn->id == ARM64_INS_LDSET || insn->id == ARM64_INS_LDSMAX || insn->id == ARM64_INS_LDSMIN || insn->id == ARM64_INS_LDUMAX || insn->id == ARM64_INS_LDUMIN || insn->id == ARM64_INS_SWP) {
//         gum_stalker_iterator_keep(iterator);
//         continue;
//     }
