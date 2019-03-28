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

#define EBPF_TEXT_LEN_OFFSET    0x0
#define EBPF_MEM_LEN_OFFSET     0x4
#define EBPF_TEXT_OFFSET        0x1000
#define EBPF_RET_OFFSET         0x200000
#define EBPF_READY_OFFSET       0x200004
#define EBPF_REGS_OFFSET        0x200008
#define EBPF_MEM_OFFSET         0x400000
#define EBPF_P2P_OFFSET         0x800000
#define EBPF_START              0x1

#define EBPF_OFFLOAD_OPCODE_DMA_TEXT      0x00
#define EBPF_OFFLOAD_OPCODE_MOVE_P2P_TEXT 0x01
#define EBPF_OFFLOAD_OPCODE_DMA_DATA      0x02
#define EBPF_OFFLOAD_OPCODE_MOVE_P2P_DATA 0x03
#define EBPF_OFFLOAD_OPCODE_RUN_PROG      0x04
#define EBPF_OFFLOAD_OPCODE_GET_REGS      0x05
#define EBPF_OFFLOAD_OPCODE_DUMP_MEM      0xff

#define EBPF_NOT_READY          0x0
#define EBPF_READY              0x1
#define DMA_DONE                0x4

#define EBPF_BAR_SIZE           (16 * MiB)
#define EBPF_RAM_SIZE           EBPF_BAR_SIZE
#define EBPF_MMIO_SIZE          (1 * MiB)
#define EBPF_RAM_OFFSET         (0x0)
#define EBPF_MMIO_OFFSET        (1 * MiB)

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

    struct command {
        uint8_t opcode;
        uint8_t ctrl;
        uint32_t length;
        uint32_t offset;
        uint64_t addr;
    } cmd;
    char dma_buf[DMA_SIZE];
    uint64_t dma_mask;
} BpfState;

/* Function hexDump was copied from https://stackoverflow.com/a/7776146 */
static void hexDump (const char *desc, void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s (%d bytes):\n", desc, len);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}


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

static int bpf_start_program(BpfState *bpf)
{
    char *bpf_ram_ptr = (char*) memory_region_get_ram_ptr(&bpf->bpf_ram);
    uint32_t code_len = *(uint32_t*) (bpf_ram_ptr + EBPF_TEXT_LEN_OFFSET);
    uint32_t mem_len =  *(uint32_t*) (bpf_ram_ptr + EBPF_MEM_LEN_OFFSET);
    void *code = bpf_ram_ptr + EBPF_TEXT_OFFSET;
    void *mem  = bpf_ram_ptr + EBPF_MEM_OFFSET + bpf->cmd.offset;
    uint64_t *regs = (uint64_t*) (bpf_ram_ptr + EBPF_REGS_OFFSET);
    bool *ready_addr = (bool*) (bpf_ram_ptr + EBPF_READY_OFFSET);
    uint64_t *ret_addr = (uint64_t*) (bpf_ram_ptr + EBPF_RET_OFFSET);

    char *errmsg;
    int32_t rv;
    uint64_t ret;
    bool elf;

    *ready_addr = EBPF_NOT_READY;

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
    *ready_addr = EBPF_READY;

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
    case 0x0:
        val = bpf->cmd.opcode;
        break;
    case 0x1:
        val = bpf->cmd.ctrl;
        break;
    case 0x4:
        val = bpf->cmd.length;
        break;
    case 0x8:
        val = bpf->cmd.offset;
        break;
    case 0xc:
        val = bpf->cmd.addr;
        break;
    default:
        //fprintf(stderr, "Invalid read (reserved)\n");
        break;
    }

    return val;
}

static void load_text(BpfState *bpf, bool inp2p)
{
    char *bpf_ram_ptr = (char*) memory_region_get_ram_ptr(&bpf->bpf_ram);
    void *code = bpf_ram_ptr + EBPF_TEXT_OFFSET;
    uint32_t *code_len = (uint32_t*) (bpf_ram_ptr + EBPF_TEXT_LEN_OFFSET);

    if (inp2p)
        memcpy(code, bpf_ram_ptr + EBPF_P2P_OFFSET + bpf->cmd.offset, bpf->cmd.length);
    else
        pci_dma_read(&bpf->pdev, bpf->cmd.addr, code + bpf->cmd.offset, bpf->cmd.length);
    if (bpf->cmd.offset == 0)
        *code_len = bpf->cmd.length;
    else
        *code_len += bpf->cmd.length;

    atomic_or(&bpf->cmd.ctrl, DMA_DONE);
}

static void load_data(BpfState *bpf, bool inp2p)
{
    char *bpf_ram_ptr = (char*) memory_region_get_ram_ptr(&bpf->bpf_ram);
    void *mem = bpf_ram_ptr + EBPF_MEM_OFFSET;
    uint32_t *mem_len =  (uint32_t*) (bpf_ram_ptr + EBPF_MEM_LEN_OFFSET);

    if (inp2p)
        memcpy(mem, bpf_ram_ptr + EBPF_P2P_OFFSET + bpf->cmd.offset, bpf->cmd.length);
    else
        pci_dma_read(&bpf->pdev, bpf->cmd.addr, mem + bpf->cmd.offset, bpf->cmd.length);
    if (bpf->cmd.offset == 0)
        *mem_len = bpf->cmd.length;
    else
        *mem_len += bpf->cmd.length;

    atomic_or(&bpf->cmd.ctrl, DMA_DONE);
}

static void run_program(BpfState *bpf)
{
    bpf_stop_program(bpf);
    bpf_start_program(bpf);
}

static void dump_memory(BpfState *bpf)
{
    char *bpf_ram_ptr = (char*) memory_region_get_ram_ptr(&bpf->bpf_ram);
    uint32_t code_len = *(uint32_t*) (bpf_ram_ptr + EBPF_TEXT_LEN_OFFSET);
    uint32_t mem_len =  *(uint32_t*) (bpf_ram_ptr + EBPF_MEM_LEN_OFFSET);

    hexDump("prog", bpf_ram_ptr + EBPF_TEXT_OFFSET, code_len);
    hexDump("data", bpf_ram_ptr + EBPF_MEM_OFFSET, mem_len);
}

static void process_command(BpfState *bpf)
{
    fprintf(stderr, "Process Command: Opcode: [0x%02x]\tLength: [%u]\tAddr: [0x%08lx]\tOffset: [0x%u]\n",
            bpf->cmd.opcode, bpf->cmd.length, bpf->cmd.addr, bpf->cmd.offset);

    switch (bpf->cmd.opcode) {
        case EBPF_OFFLOAD_OPCODE_DMA_TEXT:
        case EBPF_OFFLOAD_OPCODE_MOVE_P2P_TEXT:
            load_text(bpf, bpf->cmd.opcode); break;
        case EBPF_OFFLOAD_OPCODE_DMA_DATA:
        case EBPF_OFFLOAD_OPCODE_MOVE_P2P_DATA:
            load_data(bpf, bpf->cmd.opcode == EBPF_OFFLOAD_OPCODE_MOVE_P2P_DATA); break;
        case EBPF_OFFLOAD_OPCODE_RUN_PROG:
            run_program(bpf); break;
        case EBPF_OFFLOAD_OPCODE_DUMP_MEM:
            dump_memory(bpf); break;
        default:
            fprintf(stderr, "Invalid opcode: %u\n", bpf->cmd.opcode & 0xff);
    }
}

static void check_size(const char *name, unsigned expected, unsigned received)
{
    if (expected != received)
        fprintf(stderr, "WARNING: %s should have size %u, received %u instead\n", name, expected, received);
}

static void bpf_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    BpfState *bpf = opaque;

    fprintf(stderr, "Write of %d bytes at addr 0x%08lx with val %lu\n",
        size, addr, val);

    switch (addr & 0xff) {
        case 0x0:
            check_size("opcode", 1, size);
            bpf->cmd.opcode = val & 0xff;
            break;
        case 0x1:
            check_size("ctrl", 1, size);
            bpf->dma.ctrl = val & 0xff;
            process_command(bpf);
            break;
        case 0x4:
            check_size("length", 4, size);
            bpf->cmd.length = val & 0xffffffff;
            break;
        case 0x8:
            check_size("offset", 4, size);
            bpf->cmd.offset = val & 0xffffffff;
            break;
        case 0xc:
            check_size("addr", 8, size);
            bpf->cmd.addr = val;
            break;
    }
}

static const MemoryRegionOps bpf_mmio_ops = {
    .read = bpf_mmio_read,
    .write = bpf_mmio_write,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
    .impl.min_access_size = 1,
    .impl.max_access_size = 8,
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

    qemu_mutex_init(&bpf->thr_mutex);
    qemu_cond_init(&bpf->thr_cond);
    qemu_thread_create(&bpf->thread, "bpf", bpf_fact_thread,
                       bpf, QEMU_THREAD_JOINABLE);

    memory_region_init(&bpf->bpf_bar, OBJECT(bpf), "bpf-bar", EBPF_BAR_SIZE);
    memory_region_init_ram(&bpf->bpf_ram, OBJECT(bpf), "bpf-ram", EBPF_RAM_SIZE, &error_fatal);
    memory_region_init_io(&bpf->bpf_mmio, OBJECT(bpf), &bpf_mmio_ops, bpf,
                    "bpf-mmio", EBPF_MMIO_SIZE);
    memory_region_add_subregion_overlap(&bpf->bpf_bar, EBPF_RAM_OFFSET, &bpf->bpf_ram, 1);
    memory_region_add_subregion_overlap(&bpf->bpf_bar, EBPF_MMIO_OFFSET, &bpf->bpf_mmio, 2);
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

    bpf->dma_mask = ~0ULL; /* 64-bit */
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
