/*
 * QEMU BPF-capable PCI device
 *
 * Copyright (c) 2012-2015 Jiri Slaby
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h" /* iothread mutex */
#include "qapi/visitor.h"
#include "qapi/error.h"
#include <ubpf.h>
#include <elf.h>

#define TYPE_PCI_BPF_DEVICE "pcie-ubpf"
#define BPF(obj)        OBJECT_CHECK(BpfState, obj, TYPE_PCI_BPF_DEVICE)

#define FACT_IRQ        0x00000001
#define DMA_IRQ         0x00000100

#define DMA_START       0x40000
#define DMA_SIZE        4096

#define EBPF_PROG_LEN_OFFSET    0x0
#define EBPF_MEM_LEN_OFFSET     0x4
#define EBPF_PROG_OFFSET        0x1000
#define EBPF_RET_OFFSET         0x200000
#define EBPF_REGS_OFFSET        0x200004
#define EBPF_MEM_OFFSET         0x300000
#define EBPF_START              0x1

typedef struct {
    PCIDevice pdev;
    MemoryRegion bpf_bar;
    MemoryRegion bpf_ram;
    MemoryRegion bpf_mmio;

    struct ubpf_vm *vm;

    QemuThread thread;
    QemuMutex thr_mutex;
    QemuCond thr_cond;
    bool stopping;

    uint32_t addr4;
    uint32_t fact;
#define BPF_STATUS_COMPUTING    0x01
#define BPF_STATUS_IRQFACT      0x80
    uint32_t status;

    uint32_t irq_status;

#define BPF_DMA_RUN             0x1
#define BPF_DMA_DIR(cmd)        (((cmd) & 0x2) >> 1)
# define BPF_DMA_FROM_PCI       0
# define BPF_DMA_TO_PCI         1
#define BPF_DMA_IRQ             0x4
    struct dma_state {
        dma_addr_t src;
        dma_addr_t dst;
        dma_addr_t cnt;
        dma_addr_t cmd;
    } dma;
    QEMUTimer dma_timer;
    char dma_buf[DMA_SIZE];
    uint64_t dma_mask;
} BpfState;

static bool bpf_msi_enabled(BpfState *bpf)
{
    return msi_enabled(&bpf->pdev);
}

static void bpf_raise_irq(BpfState *bpf, uint32_t val)
{
    bpf->irq_status |= val;
    if (bpf->irq_status) {
        if (bpf_msi_enabled(bpf)) {
            msi_notify(&bpf->pdev, 0);
        } else {
            pci_set_irq(&bpf->pdev, 1);
        }
    }
}

static bool within(uint32_t addr, uint32_t start, uint32_t end)
{
    return start <= addr && addr < end;
}

static void bpf_check_range(uint32_t addr, uint32_t size1, uint32_t start,
                uint32_t size2)
{
    uint32_t end1 = addr + size1;
    uint32_t end2 = start + size2;

    if (within(addr, start, end2) &&
            end1 > addr && within(end1, start, end2)) {
        return;
    }

    hw_error("BPF: DMA range 0x%.8x-0x%.8x out of bounds (0x%.8x-0x%.8x)!",
            addr, end1 - 1, start, end2 - 1);
}

static dma_addr_t bpf_clamp_addr(const BpfState *bpf, dma_addr_t addr)
{
    dma_addr_t res = addr & bpf->dma_mask;

    if (addr != res) {
        printf("BPF: clamping DMA %#.16"PRIx64" to %#.16"PRIx64"!\n", addr, res);
    }

    return res;
}

static void bpf_dma_timer(void *opaque)
{
    BpfState *bpf = opaque;
    bool raise_irq = false;

    if (!(bpf->dma.cmd & BPF_DMA_RUN)) {
        return;
    }

    if (BPF_DMA_DIR(bpf->dma.cmd) == BPF_DMA_FROM_PCI) {
        uint32_t dst = bpf->dma.dst;
        bpf_check_range(dst, bpf->dma.cnt, DMA_START, DMA_SIZE);
        dst -= DMA_START;
        pci_dma_read(&bpf->pdev, bpf_clamp_addr(bpf, bpf->dma.src),
                bpf->dma_buf + dst, bpf->dma.cnt);
    } else {
        uint32_t src = bpf->dma.src;
        bpf_check_range(src, bpf->dma.cnt, DMA_START, DMA_SIZE);
        src -= DMA_START;
        pci_dma_write(&bpf->pdev, bpf_clamp_addr(bpf, bpf->dma.dst),
                bpf->dma_buf + src, bpf->dma.cnt);
    }

    bpf->dma.cmd &= ~BPF_DMA_RUN;
    if (bpf->dma.cmd & BPF_DMA_IRQ) {
        raise_irq = true;
    }

    if (raise_irq) {
        bpf_raise_irq(bpf, DMA_IRQ);
    }
}

static int bpf_start_program(BpfState *bpf)
{
    char *bpf_ram_ptr = (char*) memory_region_get_ram_ptr(&bpf->bpf_ram);
    int32_t code_len = *(int32_t*) (bpf_ram_ptr + EBPF_PROG_LEN_OFFSET);
    int32_t mem_len =  *(int32_t*) (bpf_ram_ptr + EBPF_MEM_LEN_OFFSET);
    void* code = bpf_ram_ptr + EBPF_PROG_OFFSET;
    void* mem  = bpf_ram_ptr + EBPF_MEM_OFFSET;
    uint64_t* regs = (uint64_t*) (bpf_ram_ptr + EBPF_REGS_OFFSET);
    uint64_t *ret_addr = (uint64_t*) (bpf_ram_ptr + EBPF_RET_OFFSET);

    char *errmsg;
    int32_t rv;
    uint64_t ret;
    bool elf;

    bpf->vm = ubpf_create();
    if (!bpf->vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    /* Check magic number (first 4 bytes) */
    elf = code_len >= 4 && !memcmp(code, ELFMAG, 4);
    if (elf) {
        rv = ubpf_load_elf(bpf->vm, code, code_len, &errmsg);
    }
    else {
        rv = ubpf_load(bpf->vm, code, code_len, &errmsg);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        ubpf_destroy(bpf->vm);
        bpf->vm = NULL;
        free(errmsg);
        return 1;
    }

    ubpf_set_registers(bpf->vm, regs);
    if (mem_len > 0) {
        ret = ubpf_exec(bpf->vm, mem, mem_len);
    }
    else {
        ret = ubpf_exec(bpf->vm, NULL, 0);
    }

    *ret_addr = ret;

    ubpf_destroy(bpf->vm);
    bpf->vm = NULL;

    return 0;
}

static int bpf_stop_program(BpfState *bpf)
{
    if (bpf->vm) {
        ubpf_destroy(bpf->vm);
        bpf->vm = NULL;
    }
    return 0;
}

static uint64_t bpf_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    BpfState *bpf = opaque;
    uint64_t val = ~0ULL;

    switch (addr) {
    case 0x00:
        val = (bpf->vm == NULL);
        break;
    default:
        fprintf(stderr, "Invalid read (reserved)\n");
        break;
    }

    return val;
}

static void bpf_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    BpfState *bpf = opaque;

    switch (addr) {
    case 0x0:
        if (val & EBPF_START) {
            bpf_stop_program(bpf);
            bpf_start_program(bpf);
        }
        else {
            bpf_stop_program(bpf);
        }
        break;
    default:
        fprintf(stderr, "Invalid address (reserved) \n");
        break;
    }
}

static const MemoryRegionOps bpf_mmio_ops = {
    .read = bpf_mmio_read,
    .write = bpf_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

/*
 * We purposely use a thread, so that users are forced to wait for the status
 * register.
 */
static void *bpf_fact_thread(void *opaque)
{
    BpfState *bpf = opaque;

    while (1) {
        uint32_t val, ret = 1;

        qemu_mutex_lock(&bpf->thr_mutex);
        while ((atomic_read(&bpf->status) & BPF_STATUS_COMPUTING) == 0 &&
                        !bpf->stopping) {
            qemu_cond_wait(&bpf->thr_cond, &bpf->thr_mutex);
        }

        if (bpf->stopping) {
            qemu_mutex_unlock(&bpf->thr_mutex);
            break;
        }

        val = bpf->fact;
        qemu_mutex_unlock(&bpf->thr_mutex);

        while (val > 0) {
            ret *= val--;
        }

        /*
         * We should sleep for a random period here, so that students are
         * forced to check the status properly.
         */

        qemu_mutex_lock(&bpf->thr_mutex);
        bpf->fact = ret;
        qemu_mutex_unlock(&bpf->thr_mutex);
        atomic_and(&bpf->status, ~BPF_STATUS_COMPUTING);

        if (atomic_read(&bpf->status) & BPF_STATUS_IRQFACT) {
            qemu_mutex_lock_iothread();
            bpf_raise_irq(bpf, FACT_IRQ);
            qemu_mutex_unlock_iothread();
        }
    }

    return NULL;
}

static void pci_bpf_realize(PCIDevice *pdev, Error **errp)
{
    BpfState *bpf = BPF(pdev);
    uint8_t *pci_conf = pdev->config;

    pci_config_set_interrupt_pin(pci_conf, 1);

    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    timer_init_ms(&bpf->dma_timer, QEMU_CLOCK_VIRTUAL, bpf_dma_timer, bpf);

    qemu_mutex_init(&bpf->thr_mutex);
    qemu_cond_init(&bpf->thr_cond);
    qemu_thread_create(&bpf->thread, "bpf", bpf_fact_thread,
                       bpf, QEMU_THREAD_JOINABLE);

    memory_region_init(&bpf->bpf_bar, OBJECT(bpf), "bpf-bar", 16 * MiB);
    memory_region_init_ram(&bpf->bpf_ram, OBJECT(bpf), "bpf-ram", 16 * MiB, &error_fatal);
    memory_region_init_io(&bpf->bpf_mmio, OBJECT(bpf), &bpf_mmio_ops, bpf,
                    "bpf-mmio", 1 * MiB);
    memory_region_add_subregion_overlap(&bpf->bpf_bar, 0x0, &bpf->bpf_ram, 1);
    memory_region_add_subregion_overlap(&bpf->bpf_bar, 1 * MiB, &bpf->bpf_mmio, 2);
    pci_register_bar(pdev, 4, PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_PREFETCH, &bpf->bpf_bar);
}

static void pci_bpf_uninit(PCIDevice *pdev)
{
    BpfState *bpf = BPF(pdev);

    qemu_mutex_lock(&bpf->thr_mutex);
    bpf->stopping = true;
    qemu_mutex_unlock(&bpf->thr_mutex);
    qemu_cond_signal(&bpf->thr_cond);
    qemu_thread_join(&bpf->thread);

    qemu_cond_destroy(&bpf->thr_cond);
    qemu_mutex_destroy(&bpf->thr_mutex);

    timer_del(&bpf->dma_timer);
}

static void bpf_obj_uint64(Object *obj, Visitor *v, const char *name,
                           void *opaque, Error **errp)
{
    uint64_t *val = opaque;

    visit_type_uint64(v, name, val, errp);
}

static void bpf_instance_init(Object *obj)
{
    BpfState *bpf = BPF(obj);

    bpf->dma_mask = (1UL << 28) - 1;
    object_property_add(obj, "dma_mask", "uint64", bpf_obj_uint64,
                    bpf_obj_uint64, NULL, &bpf->dma_mask, NULL);
}

static void bpf_class_init(ObjectClass *class, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_bpf_realize;
    k->exit = pci_bpf_uninit;
    k->vendor_id = 0x1de5; /* Eideticom */
    k->device_id = 0x3000;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
}

static void pci_bpf_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    static const TypeInfo bpf_info = {
        .name          = TYPE_PCI_BPF_DEVICE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(BpfState),
        .instance_init = bpf_instance_init,
        .class_init    = bpf_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&bpf_info);
}
type_init(pci_bpf_register_types)
