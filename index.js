const code = `
#include <gum/gumstalker.h>
#include <glib.h>
#include <stdio.h>
#include <capstone.h>

#define MAX_LINE_LEN 1024

struct stalker_info {
    guint64 start;
    guint64 end;
    guint64 register_list[32];
    gboolean init;
} typedef stalker_info;

extern stalker_info *init_info;

extern FILE *fopen(char *filename, char *mode);
extern int fclose(FILE* fp);
extern size_t fwrite(const void* __buf, size_t __size, size_t __count, FILE* __fp);
extern int snprintf(char *str, size_t size, const char *format, ...);

extern void *send(char *info);

size_t my_strlen(const char *str) {
    size_t length = 0;
    // 遍历字符串，直到遇到终止符 '\\0'
    while (str[length] != '\\0') {
        length++;
    }
    return length;
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

FILE *init_func(guint64 start, guint64 end, char *filename) {
    if (init_info != NULL) {
        g_free(init_info);
    }
    init_info = (stalker_info *) g_malloc(sizeof(stalker_info));
//    写上你的要trace的地址范围
    init_info->start = start;
    init_info->end = end;
//    需要监控的寄存器内容
    init_info->init = FALSE;
//    清空这个文件 
    stdout = fopen(filename, "w");
    fclose(stdout);
    stdout = fopen(filename, "a+");
    return stdout;
}

void end_func(){
    char* end_line = "end \\n";
    fwrite(end_line, my_strlen(end_line), 1, stdout);
    fclose(stdout);
}

const gchar *register_names[] = {
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "x29", "lr", "sp"
};
const gchar *register32_names[] = {
        "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
        "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
        "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
        "w24", "w25", "w26", "w27", "w28", "w29", "w30"
};

typedef struct {
    guint64 pc;
    guint64 sp;
    guint64 nzcv;

    guint64 x[29];
    guint64 fp;
    guint64 lr;

    GumArm64VectorReg v[32];
} GumArm64CpuContext;

/* 新增结构体用于传递指令上下文信息 */
typedef struct {
    arm64_reg regs_write[8];        // 固定数组，避免额外 malloc
    arm64_reg regs_read[8];         // 固定数组，避免额外 malloc
    gsize num_read;                 // 读取寄存器数量
    gsize num_write;                // 写入寄存器数量
    char instruction[128];          // 固定数组，避免额外 malloc
} InsnContext;

int trace_write_read_reg(InsnContext *ctx, GumArm64CpuContext* cpu_context, char* log_line, int offset){
    for (gsize i = 0; i < ctx->num_read; ++i) {
        arm64_reg reg = ctx->regs_read[i];
        switch (reg) {
            case ARM64_REG_X0 ... ARM64_REG_X28:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[reg - ARM64_REG_X0],
                        cpu_context->x[reg - ARM64_REG_X0]
                );
                break;
            case ARM64_REG_W0 ... ARM64_REG_W30:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register32_names[reg - ARM64_REG_W0],
                        cpu_context->x[reg - ARM64_REG_W0]
                );
                break;
            case ARM64_REG_FP:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[29],
                        cpu_context->fp
                );
                break;
            case ARM64_REG_LR:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[30],
                        cpu_context->lr
                );
                break;
            case ARM64_REG_SP:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[31],
                        cpu_context->sp
                );
                break;
            default:
                break;
        }
    }
    return offset;
}

int trace_write_write_reg(InsnContext *ctx, GumArm64CpuContext* cpu_context, char* log_line, int offset){
    offset += snprintf(log_line + offset, MAX_LINE_LEN - offset, "--- ");
    for (gsize i = 0; i < ctx->num_write; ++i) {
        arm64_reg reg = ctx->regs_write[i];
        switch (reg) {
            case ARM64_REG_X0 ... ARM64_REG_X28:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[reg - ARM64_REG_X0],
                        init_info->register_list[reg - ARM64_REG_X0]
                );
                break;
            case ARM64_REG_W0 ... ARM64_REG_W30:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register32_names[reg - ARM64_REG_W0],
                        init_info->register_list[reg - ARM64_REG_W0]
                );
                break;
            case ARM64_REG_FP:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[29],
                        init_info->register_list[29]
                );
                break;
            case ARM64_REG_LR:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[30],
                        init_info->register_list[30]
                );
                break;
            case ARM64_REG_SP:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[31],
                        init_info->register_list[31]
                );
            default:
                break;
        }
    }
    offset += snprintf(log_line + offset, MAX_LINE_LEN - offset, "=> ");
    for (gsize i = 0; i < ctx->num_write; ++i) {
        arm64_reg reg = ctx->regs_write[i];
        switch (reg) {
            case ARM64_REG_X0 ... ARM64_REG_X28:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[reg - ARM64_REG_X0],
                        cpu_context->x[reg - ARM64_REG_X0]
                );
                break;
            case ARM64_REG_W0 ... ARM64_REG_W30:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register32_names[reg - ARM64_REG_W0],
                        cpu_context->x[reg - ARM64_REG_W0]
                );
                break;
            case ARM64_REG_FP:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[29],
                        cpu_context->fp
                );
                break;
            case ARM64_REG_LR:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[30],
                        cpu_context->lr
                );
                break;
            case ARM64_REG_SP:
                offset += snprintf(
                        log_line + offset, MAX_LINE_LEN - offset,
                        "%s=0x%llx ",
                        register_names[31],
                        cpu_context->sp
                );
                break;
            default:
                break;
        }
    }
    return offset;
}


void stalker_callout(GumArm64CpuContext *cpu_context, gpointer user_data) {
    InsnContext *ctx = (InsnContext *) user_data;
    char log_line[MAX_LINE_LEN];  // 栈上分配，避免 malloc
    int offset = 0;

    /* 添加PC记录 */
    offset += snprintf(log_line + offset, MAX_LINE_LEN - offset, 
                      "0x%llx: \\"%s\\" ", cpu_context->pc, ctx->instruction);

    // 初始化 register_list
    if (!init_info->init) {
        for (int i = 0; i < 29; ++i) {
            init_info->register_list[i] = cpu_context->x[i];
        }
        init_info->register_list[29] = cpu_context->fp;
        init_info->register_list[30] = cpu_context->lr;
        init_info->register_list[31] = cpu_context->sp;
        init_info->init = TRUE;
        return;
    }
    
    if (ctx->num_read) {
        offset = trace_write_read_reg(ctx, cpu_context, log_line, offset);     
    }
    if (ctx->num_write) {
        offset = trace_write_write_reg(ctx, cpu_context, log_line, offset);
    }
    
    for (int i = 0; i < 29; ++i) {
        init_info->register_list[i] = cpu_context->x[i];
    }
    init_info->register_list[29] = cpu_context->fp;
    init_info->register_list[30] = cpu_context->lr;
    init_info->register_list[31] = cpu_context->sp;
    
    /* 输出日志 */
    if (stdout) {
        fwrite(log_line, my_strlen(log_line), 1, stdout);
        fwrite("\\n", 1, 1, stdout);  // 输出换行符
    }
}

void transformer_callback_trace(GumStalkerIterator *iterator,
                                GumStalkerOutput *output, gpointer user_data) {
    if (init_info == NULL) return;
    while (true) {
        const cs_insn *insn;

        if (!gum_stalker_iterator_next(iterator, &insn)) {
            break;
        }

        if (insn->id == ARM64_INS_CAS   ||
            insn->id == ARM64_INS_CASA  ||
            insn->id == ARM64_INS_CASL  ||
            insn->id == ARM64_INS_CASAL ||
            insn->id == ARM64_INS_CASP  ||
            insn->id == ARM64_INS_CASPA ||
            insn->id == ARM64_INS_CASPL ||
            insn->id == ARM64_INS_CASPAL) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }
        
        /* 地址过滤 */
        if (insn->address < init_info->start || insn->address > init_info->end) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        /* 解析指令操作数 */
        InsnContext *ctx = g_malloc(sizeof(InsnContext));  // 只需一次 malloc
        ctx->num_read = 0;
        ctx->num_write = 0;
        // 使用 snprintf 直接写入固定数组，避免 g_strdup_printf 的 malloc
        snprintf(ctx->instruction, sizeof(ctx->instruction), "%s %s", insn->mnemonic, insn->op_str);
        cs_arm64_op *ops = insn->detail->arm64.operands;
        for (int i = 0; i < insn->detail->arm64.op_count; ++i) {
            switch (ops[i].type) {
                case ARM64_OP_REG:
                    if (insn->detail->arm64.operands[i].access & CS_AC_READ) {
                        ctx->regs_read[ctx->num_read++] = ops[i].reg;
                    }
                    if (insn->detail->arm64.operands[i].access & CS_AC_WRITE) {
                        ctx->regs_write[ctx->num_write++] = ops[i].reg;
                    }
                    break;
                case ARM64_OP_MEM:
                    ctx->regs_read[ctx->num_read++] = insn->detail->arm64.operands[i].mem.base;
                    if (insn->detail->arm64.operands[i].mem.index) {
                        ctx->regs_read[ctx->num_read++] = insn->detail->arm64.operands[i].mem.index;
                    }
                    break;
                default:
                    break;
            }
        }

        if (insn->id == ARM64_INS_BL ||
            insn->id == ARM64_INS_BLR ||
            insn->id == ARM64_INS_BLRAA ||
            insn->id == ARM64_INS_BLRAB
            ) {
            // 处理可能使用 LR 的指令，但是没法看到lr，因为bl会修改但是如果bl执行了你就走不到我们的跳转了
            gum_stalker_iterator_put_callout(iterator,
                                 (GumStalkerCallout) stalker_callout,
                                 ctx,
                                 (GDestroyNotify) g_free);
            gum_stalker_iterator_keep(iterator);
        } else if (insn->id == ARM64_INS_RET) {
            ctx->regs_read[ctx->num_read++] = ARM64_REG_X0;
            gum_stalker_iterator_put_callout(iterator,
                                             (GumStalkerCallout) stalker_callout,
                                             ctx,
                                             (GDestroyNotify) g_free);
            gum_stalker_iterator_keep(iterator);
        } else if (insn->id == ARM64_INS_BR ||
                   insn->id == ARM64_INS_BRAA ||
                   insn->id == ARM64_INS_BRAB ||
                   insn->id == ARM64_INS_CBNZ ||
                   insn->id == ARM64_INS_CBZ ||
                   insn->id == ARM64_INS_TBNZ ||
                   insn->id == ARM64_INS_TBZ ||
                   insn->id == ARM64_INS_ERET ||
                   insn->id == ARM64_INS_B) {
            // 处理不修改 LR 的指令
            gum_stalker_iterator_put_callout(iterator,
                                             (GumStalkerCallout) stalker_callout,
                                             ctx,
                                             (GDestroyNotify) g_free);
            gum_stalker_iterator_keep(iterator);
        } else {
            gum_stalker_iterator_keep(iterator);
            /* 插入回调 */
            gum_stalker_iterator_put_callout(iterator,
                                             (GumStalkerCallout) stalker_callout,
                                             ctx,
                                             (GDestroyNotify) g_free);
        }
    }
}
`

const pointerSize = Process.pointerSize;
const data = Memory.alloc(pointerSize * 2)

const stalker_module = new CModule(code, {
    init_info: data,
    inst_dict: data.add(pointerSize),
    fopen: Module.findExportByName("libc.so", "fopen"),
    fclose: Module.findExportByName("libc.so", "fclose"),
    fwrite: Module.findExportByName("libc.so", "fwrite"),
    snprintf: Module.findExportByName("libc.so", "snprintf"),
    send: new NativeCallback((arg0) => {
        // console.log(arg0.readUtf8String())
    }, "void", ["pointer"])
});

var trace_config_func = {
    init_func: new NativeFunction(stalker_module.init_func, "pointer", ["pointer", "pointer", "pointer"]),
    end_func: new NativeFunction(stalker_module.end_func, "void", [])
}

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
//         var file = trace_config_func.init_func(
//             module.base,
//             module.base.add(module.size),
//             Memory.allocUtf8String(filename))
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
