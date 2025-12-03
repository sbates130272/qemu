// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe PRP1 Injection Kernel Module
 * 
 * This kernel module hooks nvme_submit_user_cmd() and injects the queue
 * physical address into PRP1 for CREATE_CQ/CREATE_SQ commands.
 * 
 * Usage:
 *   make
 *   sudo insmod nvme_prp1_inject.ko
 *   # Run your test program
 *   sudo rmmod nvme_prp1_inject
 *   dmesg | tail -50  # View logs
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/nvme.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Auto-generated");
MODULE_DESCRIPTION("Inject PRP1 for NVMe queue creation");
MODULE_VERSION("1.0");

static struct kprobe kp = {
    .symbol_name = "nvme_submit_user_cmd",
};

/* Pre-handler called before nvme_submit_user_cmd executes */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct nvme_command *cmd;
    u64 ubuffer;
    unsigned int bufflen;
    u8 opcode;
    
    /*
     * Function signature:
     * nvme_submit_user_cmd(struct request_queue *q,
     *                      struct nvme_command *cmd,
     *                      u64 ubuffer,
     *                      unsigned bufflen, ...)
     * 
     * x86_64 calling convention:
     * RDI = arg0 (q)
     * RSI = arg1 (cmd)
     * RDX = arg2 (ubuffer)
     * RCX = arg3 (bufflen)
     */
    
#ifdef CONFIG_X86_64
    cmd = (struct nvme_command *)regs->si;
    ubuffer = regs->dx;
    bufflen = (unsigned int)regs->cx;
#else
    #error "This module only supports x86_64"
#endif
    
    if (!cmd)
        return 0;
    
    opcode = cmd->common.opcode;
    
    /* Check if CREATE_CQ (0x05) or CREATE_SQ (0x01) */
    if ((opcode == 0x05 || opcode == 0x01) && bufflen == 0 && ubuffer != 0) {
        pr_info("nvme_prp1_inject: Intercepted %s command\n",
                opcode == 0x05 ? "CREATE_CQ" : "CREATE_SQ");
        pr_info("  Original PRP1: 0x%016llx\n",
                cmd->common.dptr.prp1);
        pr_info("  Injecting ubuffer: 0x%016llx\n", ubuffer);
        
        /* INJECT THE QUEUE ADDRESS INTO PRP1 */
        cmd->common.dptr.prp1 = ubuffer;
        
        pr_info("  ✅ PRP1 injection successful\n");
        pr_info("  cdw10: 0x%08x\n", le32_to_cpu(cmd->common.cdw10));
        pr_info("  cdw11: 0x%08x\n", le32_to_cpu(cmd->common.cdw11));
    }
    
    return 0;  /* Continue with original function */
}

static int __init nvme_prp1_inject_init(void)
{
    int ret;
    
    kp.pre_handler = handler_pre;
    
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("nvme_prp1_inject: Failed to register kprobe: %d\n", ret);
        return ret;
    }
    
    pr_info("nvme_prp1_inject: Module loaded successfully\n");
    pr_info("  Hooked: %s at %p\n", kp.symbol_name, kp.addr);
    pr_info("  Monitoring for CREATE_CQ/CREATE_SQ commands...\n");
    
    return 0;
}

static void __exit nvme_prp1_inject_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("nvme_prp1_inject: Module unloaded\n");
}

module_init(nvme_prp1_inject_init);
module_exit(nvme_prp1_inject_exit);

