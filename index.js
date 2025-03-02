const code = `
#include <gum/gumstalker.h>
#include <glib.h>
#include <stdio.h>
#include <capstone.h>

struct stalker_info {
    guint64 start;
    guint64 end;
    guint64 register_list[32];
    gboolean init;
} typedef stalker_info;

extern stalker_info *init_info;

extern FILE *fopen(char *filename, char *mode);

extern void *send(char *info);

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
        cs_arm64_op *ops = insn->detail->arm64.operands;
        for (int i = 0; i < insn->detail->arm64.op_count; ++i) {
            switch (ops[i].type) {
                case ARM64_OP_REG:
                    if (insn->detail->arm64.operands[i].access & CS_AC_READ) {
                        send("CS_AC_READ");
                    }
                    if (insn->detail->arm64.operands[i].access & CS_AC_WRITE) {
                        send("CS_AC_WRITE");
                    }
                    break;
                case ARM64_OP_MEM:
                    send("ARM64_OP_MEM");
                    if (insn->detail->arm64.operands[i].mem.index) {
                        send("index");
                    }
                    break;
                default:
                    break;
            }
        }
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
    stdout = fopen(filename, "w");
    return stdout;
}

const gchar *register_names[] = {
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "fp", "lr", "sp"
};
const gchar *register32_names[] = {
        "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
        "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
        "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
        "w24", "w25", "w26", "w27", "w28"
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
    arm64_reg *regs_write;        // 被修改的寄存器列表
    arm64_reg *regs_read;        // 被修改的寄存器列表
    gsize num_read;         // 读取寄存器数量
    gsize num_write;         // 写入寄存器数量
    gchar *instruction;
} InsnContext;

void stalker_callout(GumArm64CpuContext *cpu_context, gpointer user_data) {
    InsnContext *ctx = (InsnContext *) user_data;
    GString *log_line = g_string_new(NULL);

    /* 添加PC记录 */
    g_string_append_printf(log_line, "0x%llx: \\"%s\\" ", cpu_context->pc, ctx->instruction);
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

    for (gsize i = 0; i < ctx->num_read; ++i) {
        arm64_reg reg = ctx->regs_read[i];
        switch (reg) {
            case ARM64_REG_X0 ... ARM64_REG_X28:
                g_string_append_printf(
                        log_line, "%s=0x%llx ",
                        register_names[reg - ARM64_REG_X0],
                        init_info->register_list[reg - ARM64_REG_X0]
                );
                break;
            case ARM64_REG_W0 ... ARM64_REG_W28:
                g_string_append_printf(
                        log_line, "%s=0x%llx ",
                        register32_names[reg - ARM64_REG_W0],
                        init_info->register_list[reg - ARM64_REG_W0]
                );
                break;
            case ARM64_REG_LR:
                g_string_append_printf(
                        log_line, "%s=0x%llx ",
                        register_names[30],
                        cpu_context->pc+4
                );
                break;
            case ARM64_REG_SP:
                g_string_append_printf(
                        log_line, "%s=0x%llx ",
                        register_names[31],
                        init_info->register_list[31]
                );
                break;
            default:
                break;
        }
    }

    if (ctx->num_write) {
        g_string_append_printf(log_line, "=> ");
        for (gsize i = 0; i < ctx->num_write; ++i) {
            arm64_reg reg = ctx->regs_write[i];
            switch (reg) {
                case ARM64_REG_X0 ... ARM64_REG_X28:
                    g_string_append_printf(
                            log_line, "%s=0x%llx ",
                            register_names[reg - ARM64_REG_X0],
                            cpu_context->x[reg - ARM64_REG_X0]
                    );
                    init_info->register_list[reg - ARM64_REG_X0] = cpu_context->x[reg -
                                                                                  ARM64_REG_X0];
                    break;
                case ARM64_REG_W0 ... ARM64_REG_W28:
                    g_string_append_printf(
                            log_line, "%s=0x%llx ",
                            register32_names[reg - ARM64_REG_W0],
                            cpu_context->x[reg - ARM64_REG_W0]
                    );
                    init_info->register_list[reg - ARM64_REG_W0] = cpu_context->x[reg -
                                                                                  ARM64_REG_W0];
                    break;
                case ARM64_REG_SP:
                    g_string_append_printf(
                            log_line, "%s=0x%llx ",
                            register_names[31],
                            cpu_context->sp
                    );
                    init_info->register_list[31] = cpu_context->sp;
                default:
                    break;
            }
        }
    }

    /* 输出日志 */
    if (stdout) {
        fprintf(stdout, "%s\\n", log_line->str);
    }
    g_string_free(log_line, TRUE);
}

void transformer_callback_trace(GumStalkerIterator *iterator,
                                GumStalkerOutput *output, gpointer user_data) {
    if (init_info == NULL) return;

    while (true) {
        const cs_insn *insn;

        if (!gum_stalker_iterator_next(iterator, &insn)) {
            break;
        }

        /* 原子指令处理 */
        if (insn->id == ARM64_INS_STP || insn->id == ARM64_INS_STXP ||
            insn->id == ARM64_INS_STNP || insn->id == ARM64_INS_STLXP ||
            insn->id == ARM64_INS_LDP || insn->id == ARM64_INS_LDXP ||
            insn->id == ARM64_INS_LDNP ||
            insn->id == ARM64_INS_CAS || insn->id == ARM64_INS_CASP ||
            insn->id == ARM64_INS_LDADD || insn->id == ARM64_INS_LDARB ||
            insn->id == ARM64_INS_LDARH || insn->id == ARM64_INS_LDAR ||
            insn->id == ARM64_INS_LDAXP || insn->id == ARM64_INS_LDAXR ||
            insn->id == ARM64_INS_LDAXRB || insn->id == ARM64_INS_LDAXRH ||
            insn->id == ARM64_INS_LDCLR || insn->id == ARM64_INS_LDEOR ||
            insn->id == ARM64_INS_LDSET || insn->id == ARM64_INS_LDSMAX ||
            insn->id == ARM64_INS_LDSMIN || insn->id == ARM64_INS_LDUMAX ||
            insn->id == ARM64_INS_LDUMIN || insn->id == ARM64_INS_SWP) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        /* 地址过滤 */
        if (insn->address < init_info->start || insn->address > init_info->end) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        /* 解析指令操作数 */
        InsnContext *ctx = g_malloc(sizeof(InsnContext));
        ctx->regs_read = g_malloc(sizeof(arm64_reg) * 8); // 最多处理8个寄存器
        ctx->regs_write = g_malloc(sizeof(arm64_reg) * 8); // 最多处理8个寄存器
        ctx->num_read = 0;
        ctx->num_write = 0;
        ctx->instruction = g_strdup_printf("%s %s", insn->mnemonic, insn->op_str);
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
            insn->id == ARM64_INS_BLRAB) {
            // 处理修改 LR 的指令
            ctx->regs_read[ctx->num_read++] = ARM64_REG_LR;
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
                   insn->id == ARM64_INS_B ||
                   insn->id == ARM64_INS_RET) {
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
    send: new NativeCallback((arg0)=>{
        console.log(arg0.readUtf8String())
    }, "void", ["pointer"])
});

const init_func = new NativeFunction(stalker_module.init_func, "pointer", ["pointer", "pointer", "pointer"])
// 分配两个指针
const fclose = new NativeFunction(Module.findExportByName(null, "fclose"),
    "int", ["pointer"]
)
const fflush = new NativeFunction(Module.findExportByName(null, "fflush"),
    "int", ["pointer"]
);
var file = undefined;

function hook_dlopen(so_name) {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                console.log(path)
                if (path.indexOf(so_name) !== -1) {
                    this.match = true
                }
            }
        },
        onLeave: function (retval) {
            if (this.match) {
                console.log(so_name, "加载成功")
                const module = Process.findModuleByName("libDexHelper.so");
                Process.enumerateModules().forEach(_module=>{
                    if (_module.name !== "libDexHelper.so"){
                        Stalker.exclude({
                            base: _module.base,
                            size: _module.size
                        })
                    }
                })
                Interceptor.attach(module.findExportByName("JNI_OnLoad"), {
                        onEnter: function (args) {
                            var curTid = Process.getCurrentThreadId();
                            // init函数返回函数指针
                            file = init_func(
                                module.base,
                                module.base.add(module.size),
                                Memory.allocUtf8String("/data/data/com.mcdonalds.gma.cn/files/trace.txt"))
                            // 初始化相关参数
                            console.log(file)
                            // 开始stalker
                            Stalker.follow(curTid, {
                                // 直接创建block块，什么都不做
                                transform: stalker_module.transformer_callback_trace
                            })
                        },
                        onLeave: function (retval) {
                            console.log("结束");
                            // 保存结果
                            if (file){
                                fflush(file)
                                fclose(file)
                            }
                            Stalker.unfollow();
                            Stalker.garbageCollect();
                        }
                    }
                )
            }
        }
    });
}

hook_dlopen("libDexHelper.so")

// 0x77d48876d0
// 0x77d4852814
