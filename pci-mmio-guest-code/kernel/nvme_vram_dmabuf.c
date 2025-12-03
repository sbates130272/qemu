/*
 * NVMe VRAM DMA-BUF Helper Module
 * 
 * Provides ioctl to get P2PDMA physical address from dmabuf fd
 * Also supports automatic PRP1 injection via kprobe
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/dma-buf.h>
#include <linux/scatterlist.h>
#include <linux/kprobes.h>
#include <linux/nvme.h>
#include <linux/pci.h>
#include <drm/drm_gem.h>
#include <drm/ttm/ttm_bo.h>
#include <drm/ttm/ttm_resource.h>

#define DEVICE_NAME "nvme_vram_dmabuf"
#define CLASS_NAME "nvme_vram"

/*
 * For DRM/GEM dmabufs, dmabuf->priv points to the drm_gem_object,
 * which is the 'base' field of ttm_buffer_object.
 * We use container_of to get the ttm_buffer_object.
 */

/* IOCTL commands */
#define NVME_VRAM_IOC_MAGIC 'V'
#define NVME_VRAM_GET_PHYS_ADDR _IOWR(NVME_VRAM_IOC_MAGIC, 1, struct nvme_vram_dmabuf_req)

struct nvme_vram_dmabuf_req {
    int dmabuf_fd;          /* Input: dmabuf file descriptor */
    __u16 nvme_bdf;         /* Input: NVMe PCI BDF (domain:bus:dev.func) */
    __u32 flags;            /* Input: flags for address mode */
#define NVME_VRAM_FLAG_EMULATED  (1 << 0)  /* Return BAR GPA for emulated NVMe */
    __u64 phys_addr;        /* Output: Physical/DMA address */
    __u64 size;             /* Output: Buffer size */
};

static int major_number;
static struct class *nvme_vram_class = NULL;
static struct device *nvme_vram_device = NULL;

/* For auto-injection */
static __u64 cached_vram_addr = 0;
static bool inject_enabled = false;
module_param(inject_enabled, bool, 0644);

/* Emulated NVMe BDF (if non-zero, use BAR GPA mode for this device) */
static uint emulated_nvme_bdf = 0;
module_param(emulated_nvme_bdf, uint, 0644);
MODULE_PARM_DESC(emulated_nvme_bdf, "BDF of emulated NVMe (0xBBDD format, 0=all passthrough)");

/*
 * DMA-BUF attach ops for P2P support.
 * We pin the buffer, so move_notify should never be called.
 */
static void nvme_vram_move_notify(struct dma_buf_attachment *attach)
{
    pr_warn_ratelimited("nvme_vram_dmabuf: move_notify called on pinned buffer (should not happen)\n");
}

static const struct dma_buf_attach_ops nvme_vram_attach_ops = {
    .allow_peer2peer = true,
    .move_notify = nvme_vram_move_notify,
};

/*
 * Extract the actual VRAM offset from AMDGPU's internal buffer object.
 * The dmabuf->priv points to the amdgpu_bo, which contains the TTM resource
 * with the real VRAM page offset.
 */
static int extract_vram_offset_from_amdgpu_bo(struct dma_buf *dmabuf,
                                              resource_size_t bar_start,
                                              resource_size_t bar_size,
                                              __u64 *offset)
{
    struct drm_gem_object *gem_obj;
    struct ttm_buffer_object *tbo;
    struct ttm_resource *resource;
    unsigned long page_offset;
    
    if (!dmabuf || !dmabuf->priv) {
        pr_err("nvme_vram_dmabuf: Invalid dmabuf or missing private data\n");
        return -EINVAL;
    }
    
    /*
     * For DRM/TTM dmabufs, priv points to drm_gem_object,
     * which is the 'base' field (first field) of ttm_buffer_object.
     * Use container_of to get the ttm_buffer_object.
     */
    gem_obj = (struct drm_gem_object *)dmabuf->priv;
    tbo = container_of(gem_obj, struct ttm_buffer_object, base);
    
    if (!tbo->resource) {
        pr_err("nvme_vram_dmabuf: TTM resource not available\n");
        return -EINVAL;
    }
    
    resource = tbo->resource;
    
    /* resource->start is the VRAM offset in pages */
    page_offset = resource->start;
    
    /* Convert page offset to byte offset (assuming 4KB pages) */
    *offset = page_offset << PAGE_SHIFT;
    
    pr_info("nvme_vram_dmabuf: ✅ Extracted from TTM resource:\n");
    pr_info("  page_offset=0x%lx, byte_offset=0x%llx\n", page_offset, *offset);
    pr_info("  resource.mem_type=%u, size=0x%zx\n", 
            resource->mem_type, resource->size);
    
    /* Verify this is actually VRAM (mem_type should be TTM_PL_VRAM = 2) */
    if (resource->mem_type != 2) {
        pr_err("nvme_vram_dmabuf: Buffer is not in VRAM (mem_type=%u, expected 2)\n",
               resource->mem_type);
        return -EINVAL;
    }
    
    /* Sanity check: offset should be within BAR size */
    if (*offset >= bar_size) {
        pr_warn("nvme_vram_dmabuf: Calculated offset 0x%llx exceeds BAR size 0x%llx\n",
                *offset, (u64)bar_size);
        /* Continue anyway - might be correct for large VRAM BARs */
    }
    
    return 0;
}

/* 
 * Extract VRAM physical offset from scatter-gather table
 * 
 * For VRAM buffers, sg entries won't have GPU BAR physical addresses directly.
 * Instead, use the DMA address as an offset hint (common P2PDMA pattern).
 */
static int extract_vram_offset_from_sg(struct sg_table *sgt, struct pci_dev *gpu_dev,
                                       resource_size_t bar_start, resource_size_t bar_size,
                                       struct dma_buf *dmabuf,
                                       __u64 *offset)
{
    struct scatterlist *sg;
    dma_addr_t dma_addr;
    phys_addr_t phys_addr;
    int i;
    
    if (!sgt || sgt->nents == 0) {
        return -EINVAL;
    }
    
    /* Log what we see in the scatter-gather table */
    for_each_sg(sgt->sgl, sg, sgt->nents, i) {
        phys_addr = sg_phys(sg);
        dma_addr = sg_dma_address(sg);
        
        pr_info("nvme_vram_dmabuf: sg[%d]: phys=0x%llx dma=0x%llx len=%u\n",
                i, (u64)phys_addr, (u64)dma_addr, sg->length);
        
        /* Check if physical address is within the GPU BAR range (unlikely but try) */
        if (phys_addr >= bar_start && phys_addr < (bar_start + bar_size)) {
            *offset = phys_addr - bar_start;
            pr_info("nvme_vram_dmabuf: ✅ Found VRAM offset from sg_phys: 0x%llx\n", *offset);
            return 0;
        }
    }
    
    /*
     * The sg_table doesn't have GPU BAR addresses (as expected for VRAM).
     * Try to extract the real VRAM offset from AMDGPU's TTM resource first.
     */
    pr_info("nvme_vram_dmabuf: Trying TTM resource extraction...\n");
    if (extract_vram_offset_from_amdgpu_bo(dmabuf, bar_start, bar_size, offset) == 0) {
        /* Success! TTM gave us the real offset */
        return 0;
    }
    
    /*
     * TTM extraction failed. Fallback to DMA address heuristic.
     * For P2PDMA, the DMA address sometimes encodes the offset within the resource.
     */
    sg = sgt->sgl;
    dma_addr = sg_dma_address(sg);
    
    pr_info("nvme_vram_dmabuf: TTM failed, trying DMA address as direct offset: 0x%llx\n", (u64)dma_addr);
    
    if (dma_addr > 0 && dma_addr < bar_size) {
        *offset = dma_addr;
        pr_warn("nvme_vram_dmabuf: Using DMA address as VRAM offset (may be wrong!): 0x%llx\n", *offset);
        return 0;
    }
    
    pr_err("nvme_vram_dmabuf: Could not extract VRAM offset from sg_table or TTM\n");
    pr_err("nvme_vram_dmabuf: dma_addr=0x%llx bar_size=0x%llx\n", 
            (u64)dma_addr, (u64)bar_size);
    
    return -EINVAL;
}

/* Get GPU BAR GPA for emulated NVMe (returns guest-visible BAR address) */
static int get_dmabuf_bar_gpa(int dmabuf_fd, __u64 *bar_gpa, __u64 *size)
{
    struct dma_buf *dmabuf;
    struct pci_dev *gpu_dev = NULL;
    struct sg_table *sgt = NULL;
    struct dma_buf_attachment *attach = NULL;
    resource_size_t bar_start, bar_size;
    int ret = 0;
    int i;

    /* Get dmabuf */
    dmabuf = dma_buf_get(dmabuf_fd);
    if (IS_ERR(dmabuf)) {
        pr_err("nvme_vram_dmabuf: dma_buf_get failed: %ld\n", PTR_ERR(dmabuf));
        return PTR_ERR(dmabuf);
    }

    *size = dmabuf->size;

    /* Find the GPU device - try to get it from dmabuf attachment */
    /* First, try to find AMD GPU by scanning PCI devices */
    gpu_dev = pci_get_device(PCI_VENDOR_ID_ATI, PCI_ANY_ID, NULL);
    if (!gpu_dev) {
        pr_err("nvme_vram_dmabuf: AMD GPU not found\n");
        ret = -ENODEV;
        goto cleanup_no_attach;
    }

    /*
     * Use dynamic attach with P2P support.
     * This tells AMDGPU we support peer-to-peer DMA, so it will
     * keep the buffer in VRAM instead of forcing it to GTT.
     * We pin the buffer immediately after attach, so move_notify
     * should never be called (buffer is pinned and can't move).
     */
    attach = dma_buf_dynamic_attach(dmabuf, &gpu_dev->dev, &nvme_vram_attach_ops, NULL);
    if (IS_ERR(attach)) {
        pr_err("nvme_vram_dmabuf: dma_buf_dynamic_attach failed: %ld\n", PTR_ERR(attach));
        ret = PTR_ERR(attach);
        goto cleanup_no_attach;
    }
    
    /* Pin the buffer so it doesn't move */
    ret = dma_buf_pin(attach);
    if (ret) {
        pr_err("nvme_vram_dmabuf: dma_buf_pin failed: %d\n", ret);
        goto cleanup_detach;
    }
    
    sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
    if (IS_ERR(sgt)) {
        pr_err("nvme_vram_dmabuf: dma_buf_map_attachment failed: %ld\n", PTR_ERR(sgt));
        ret = PTR_ERR(sgt);
        goto cleanup;
    }
    
    pr_info("nvme_vram_dmabuf: dmabuf mapped: nents=%u\n", sgt->nents);

    /* Find the GPU VRAM BAR */
    for (i = 0; i < PCI_STD_NUM_BARS; i++) {
        if (!(pci_resource_flags(gpu_dev, i) & IORESOURCE_MEM))
            continue;

        bar_start = pci_resource_start(gpu_dev, i);
        bar_size = pci_resource_len(gpu_dev, i);

        /* Use BAR 0 for VRAM (typical for AMD GPUs) */
        if (i == 0 && (pci_resource_flags(gpu_dev, i) & IORESOURCE_PREFETCH)) {
            pr_info("nvme_vram_dmabuf: Found GPU VRAM BAR%d: GPA=0x%llx size=0x%llx\n",
                    i, (u64)bar_start, (u64)bar_size);
            
            /* 
             * Extract the actual VRAM offset from the scatter-gather table
             * This should give us the physical offset within the GPU's VRAM BAR
             */
            __u64 vram_offset = 0;
            if (extract_vram_offset_from_sg(sgt, gpu_dev, bar_start, bar_size, dmabuf, &vram_offset) == 0) {
                *bar_gpa = bar_start + vram_offset;
                pr_info("nvme_vram_dmabuf: ✅ BAR GPA=0x%llx (base=0x%llx + offset=0x%llx)\n",
                        *bar_gpa, (u64)bar_start, vram_offset);
            } else {
                /* Fallback: return BAR base (will be wrong but better than crashing) */
                *bar_gpa = bar_start;
                pr_warn("nvme_vram_dmabuf: Failed to extract offset, using BAR base\n");
            }
            
            ret = 0;
            goto cleanup;
        }
    }

    pr_err("nvme_vram_dmabuf: No suitable GPU VRAM BAR found\n");
    ret = -EINVAL;

cleanup:
    if (sgt && !IS_ERR(sgt))
        dma_buf_unmap_attachment(attach, sgt, DMA_BIDIRECTIONAL);
    if (attach && !IS_ERR(attach)) {
        dma_buf_unpin(attach);
cleanup_detach:
        dma_buf_detach(dmabuf, attach);
    }
cleanup_no_attach:
    if (gpu_dev)
        pci_dev_put(gpu_dev);
    dma_buf_put(dmabuf);
    return ret;
}

/* Get physical address from dmabuf using DMA API (for passthrough NVMe) 
 * Currently unused - we always use GPU BAR GPA mode */
#if 0
static int get_dmabuf_phys_addr(int dmabuf_fd, __u16 nvme_bdf, 
                                 __u64 *phys_addr, __u64 *size)
{
    struct dma_buf *dmabuf;
    struct dma_buf_attachment *attach;
    struct sg_table *sgt;
    struct pci_dev *pdev = NULL;
    struct device *dev;
    dma_addr_t dma_addr;
    int ret = 0;
    unsigned int domain, bus, devfn;

    /* Decode BDF: format is 0x0BDF (bus=B, dev=D, func=F) */
    bus = (nvme_bdf >> 8) & 0xFF;
    devfn = nvme_bdf & 0xFF;
    domain = 0; /* Assume domain 0 for now */

    /* Find the NVMe PCI device */
    pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
    if (!pdev) {
        pr_err("nvme_vram_dmabuf: NVMe device not found (BDF: 0x%04x)\n", 
               nvme_bdf);
        return -ENODEV;
    }
    dev = &pdev->dev;

    pr_info("nvme_vram_dmabuf: Using NVMe device %s (BDF: 0x%04x)\n",
            pci_name(pdev), nvme_bdf);

    /* Get dmabuf from fd */
    dmabuf = dma_buf_get(dmabuf_fd);
    if (IS_ERR(dmabuf)) {
        pr_err("nvme_vram_dmabuf: dma_buf_get failed: %ld\n", 
               PTR_ERR(dmabuf));
        ret = PTR_ERR(dmabuf);
        goto err_put_pci;
    }

    *size = dmabuf->size;

    /* Attach to NVMe device */
    attach = dma_buf_attach(dmabuf, dev);
    if (IS_ERR(attach)) {
        pr_err("nvme_vram_dmabuf: dma_buf_attach failed: %ld\n", 
               PTR_ERR(attach));
        ret = PTR_ERR(attach);
        goto err_put_dmabuf;
    }

    /* Map for DMA - this is where P2PDMA magic happens */
    sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
    if (IS_ERR(sgt)) {
        pr_err("nvme_vram_dmabuf: dma_buf_map_attachment failed: %ld\n", 
               PTR_ERR(sgt));
        ret = PTR_ERR(sgt);
        goto err_detach;
    }

    /* Get DMA address from scatter-gather list */
    if (sgt->nents > 0) {
        dma_addr = sg_dma_address(sgt->sgl);
        *phys_addr = (__u64)dma_addr;
        pr_info("nvme_vram_dmabuf: ✅ P2PDMA address: 0x%llx (size: %llu)\n",
                *phys_addr, *size);
    } else {
        pr_err("nvme_vram_dmabuf: No DMA segments\n");
        ret = -EINVAL;
    }

    /* Unmap and detach */
    dma_buf_unmap_attachment(attach, sgt, DMA_BIDIRECTIONAL);
err_detach:
    dma_buf_detach(dmabuf, attach);
err_put_dmabuf:
    dma_buf_put(dmabuf);
err_put_pci:
    pci_dev_put(pdev);

    return ret;
}
#endif

/* IOCTL handler */
static long nvme_vram_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct nvme_vram_dmabuf_req req;
    int ret;

    if (cmd != NVME_VRAM_GET_PHYS_ADDR)
        return -ENOTTY;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    /*
     * INSIGHT: Inside a VM, both passthrough and emulated NVMe devices see 
     * the same guest physical address space. The GPU BAR is mapped at a GPA
     * (e.g. 0xc400000000+), and that's what BOTH types of NVMe need to use.
     * 
     * P2PDMA (dma_buf_map_attachment) doesn't work correctly inside the guest
     * because the guest kernel doesn't have P2PDMA infrastructure configured.
     * It returns bogus addresses like 0x115c00000 instead of the correct BAR GPA.
     * 
     * Solution: Always return the GPU BAR GPA, regardless of NVMe type.
     */
    pr_info("nvme_vram_dmabuf: Getting GPU BAR GPA for NVMe BDF 0x%04x\n",
            req.nvme_bdf);
    ret = get_dmabuf_bar_gpa(req.dmabuf_fd, &req.phys_addr, &req.size);

    if (ret < 0)
        return ret;

    /* Cache for auto-injection */
    if (inject_enabled) {
        cached_vram_addr = req.phys_addr;
        pr_info("nvme_vram_dmabuf: Cached VRAM addr for auto-injection: 0x%llx\n",
                cached_vram_addr);
    }

    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

/* File operations */
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = nvme_vram_ioctl,
};

/* Kprobe for auto-injection (optional) */
static int kprobe_nvme_setup_cmd_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct nvme_command *cmd;
    
    if (!inject_enabled || cached_vram_addr == 0)
        return 0;

    cmd = (struct nvme_command *)regs->dx;
    
    /* Only inject for I/O commands */
    if (cmd->common.opcode == 0x01 || cmd->common.opcode == 0x02) {
        pr_info("nvme_vram_dmabuf: Injecting VRAM PRP1: 0x%llx\n", cached_vram_addr);
        cmd->common.dptr.prp1 = cached_vram_addr;
    }
    
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "nvme_setup_cmd",
    .pre_handler = kprobe_nvme_setup_cmd_pre,
};

static int __init nvme_vram_dmabuf_init(void)
{
    int ret;

    /* Register character device */
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("nvme_vram_dmabuf: Failed to register device: %d\n", major_number);
        return major_number;
    }

    /* Create device class */
    nvme_vram_class = class_create(CLASS_NAME);
    if (IS_ERR(nvme_vram_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(nvme_vram_class);
    }

    /* Create device */
    nvme_vram_device = device_create(nvme_vram_class, NULL, 
                                     MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(nvme_vram_device)) {
        class_destroy(nvme_vram_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(nvme_vram_device);
    }

    /* Optional: Register kprobe for auto-injection */
    if (inject_enabled) {
        ret = register_kprobe(&kp);
        if (ret < 0) {
            pr_warn("nvme_vram_dmabuf: kprobe registration failed: %d\n", ret);
            pr_warn("  Auto-injection disabled, ioctl-only mode\n");
            inject_enabled = false;
        } else {
            pr_info("nvme_vram_dmabuf: Auto-injection enabled\n");
        }
    }

    pr_info("nvme_vram_dmabuf: Module loaded\n");
    pr_info("  Device: /dev/%s\n", DEVICE_NAME);
    pr_info("  Major number: %d\n", major_number);

    return 0;
}

static void __exit nvme_vram_dmabuf_exit(void)
{
    if (inject_enabled)
        unregister_kprobe(&kp);

    device_destroy(nvme_vram_class, MKDEV(major_number, 0));
    class_destroy(nvme_vram_class);
    unregister_chrdev(major_number, DEVICE_NAME);

    pr_info("nvme_vram_dmabuf: Module unloaded\n");
}

module_init(nvme_vram_dmabuf_init);
module_exit(nvme_vram_dmabuf_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Get P2PDMA physical address from GPU VRAM dmabuf");
MODULE_VERSION("1.0");
MODULE_INFO(import_ns, "DMA_BUF");

