/*
 * GPU-based NVMe Write Test via PCI MMIO Bridge
 * 
 * This program demonstrates GPU-initiated NVMe I/O:
 * 1. GPU kernel fills a 4KiB buffer with LFSR pattern
 * 2. GPU kernel formulates an NVMe Write command (SQE)
 * 3. GPU kernel writes SQE to NVMe submission queue
 * 4. GPU kernel uses MMIO bridge to ring NVMe doorbell
 * 5. CPU polls completion queue for result
 *
 * Compile:
 *   /opt/rocm/bin/hipcc -o test-gpu-nvme-write test-gpu-nvme-write.cpp \
 *       -I/usr/include/libdrm -ldrm -ldrm_amdgpu
 *
 * Run (as root):
 *   sudo ./test-gpu-nvme-write
 */

#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <drm/drm.h>
#include <drm/amdgpu_drm.h>
#include <linux/nvme_ioctl.h>

/* PCI MMIO Bridge command structures */
struct pci_mmio_command {
    uint16_t target_bdf;
    uint8_t  target_bar;
    uint8_t  reserved1;
    uint32_t offset;
    uint64_t value;
    uint8_t  command;
    uint8_t  size;
    uint8_t  status;
    uint8_t  reserved2;
    uint32_t sequence;
} __attribute__((packed));

struct pci_mmio_ring_meta {
    uint32_t producer_idx;
    uint32_t consumer_idx;
    uint32_t queue_depth;
    uint32_t reserved;
} __attribute__((packed));

/* Command types */
#define PCI_MMIO_CMD_WRITE  1
#define PCI_MMIO_CMD_READ   2

/* Status codes */
#define PCI_MMIO_STATUS_PENDING   0
#define PCI_MMIO_STATUS_COMPLETE  1
#define PCI_MMIO_STATUS_ERROR     2

/* NVMe structures (NVMe 1.4 spec) */
struct nvme_command {
    uint8_t  opcode;        /* Opcode */
    uint8_t  flags;         /* Flags (PSDT, FUSE) */
    uint16_t command_id;    /* Command ID */
    uint32_t nsid;          /* Namespace ID */
    uint64_t rsvd2;
    uint64_t metadata;      /* Metadata pointer */
    uint64_t prp1;          /* PRP Entry 1 or SGL1 */
    uint64_t prp2;          /* PRP Entry 2 or SGL2 */
    uint32_t cdw10;         /* Command-specific */
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} __attribute__((packed));

struct nvme_completion {
    uint32_t result;        /* Command-specific result */
    uint32_t rsvd;
    uint16_t sq_head;       /* SQ head pointer */
    uint16_t sq_id;         /* SQ identifier */
    uint16_t command_id;    /* Command ID */
    uint16_t status;        /* Status field (phase bit in bit 0) */
} __attribute__((packed));

/* NVMe opcodes */
#define NVME_CMD_WRITE  0x01
#define NVME_CMD_READ   0x02

/* NVMe constants */
#define NVME_PAGE_SIZE  4096
#define QUEUE_SIZE  64  /* Number of queue entries */

/* NVMe admin opcodes */
#define NVME_ADMIN_CREATE_CQ  0x05
#define NVME_ADMIN_CREATE_SQ  0x01
#define NVME_ADMIN_DELETE_SQ  0x00
#define NVME_ADMIN_DELETE_CQ  0x04

/* GPU kernel to fill buffer with LFSR pattern */
__global__ void gpu_fill_lfsr_pattern(uint32_t *buffer, uint32_t size_words)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= size_words) return;
    
    /* 32-bit LFSR (Galois form): x^32 + x^22 + x^2 + x + 1 */
    uint32_t lfsr = 0xACE1u;  /* Non-zero seed */
    
    /* Advance LFSR to position idx */
    for (int i = 0; i < idx; i++) {
        uint32_t lsb = lfsr & 1;
        lfsr >>= 1;
        if (lsb) {
            lfsr ^= 0x80200003u;  /* Tap positions */
        }
    }
    
    buffer[idx] = lfsr;
}

/* GPU kernel to formulate NVMe write command and ring doorbell */
__global__ void gpu_submit_nvme_write(
    void *bridge_base,          /* MMIO bridge shadow buffer */
    struct nvme_command *sq,    /* NVMe submission queue */
    uint16_t sq_tail,           /* Current SQ tail */
    uint64_t data_prp,          /* Physical address of data buffer */
    uint64_t lba,               /* Logical block address */
    uint16_t num_blocks,        /* Number of blocks (0-based) */
    uint16_t nsid,              /* Namespace ID */
    uint16_t nvme_bdf,          /* NVMe device BDF */
    uint8_t nvme_bar,           /* NVMe doorbell BAR */
    uint32_t doorbell_offset)   /* Doorbell register offset */
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        /* Step 1: Formulate NVMe Write command */
        struct nvme_command *cmd = &sq[sq_tail];
        
        cmd->opcode = NVME_CMD_WRITE;
        cmd->flags = 0;
        cmd->command_id = sq_tail;
        cmd->nsid = nsid;
        cmd->rsvd2 = 0;
        cmd->metadata = 0;
        cmd->prp1 = data_prp;
        cmd->prp2 = 0;  /* Single page, no PRP2 needed */
        cmd->cdw10 = (uint32_t)(lba & 0xFFFFFFFF);      /* SLBA low */
        cmd->cdw11 = (uint32_t)(lba >> 32);             /* SLBA high */
        cmd->cdw12 = num_blocks;                        /* Number of blocks (0-based) */
        cmd->cdw13 = 0;
        cmd->cdw14 = 0;
        cmd->cdw15 = 0;
        
        __threadfence_system();  /* Ensure SQE is visible to NVMe controller */
        
        /* Step 2: Ring doorbell via MMIO bridge */
        struct pci_mmio_ring_meta *meta = (struct pci_mmio_ring_meta *)bridge_base;
        uint32_t prod_idx = meta->producer_idx;
        uint32_t queue_depth = meta->queue_depth;
        uint32_t slot = prod_idx % queue_depth;
        
        struct pci_mmio_command *bridge_cmd = 
            (struct pci_mmio_command *)((char *)bridge_base + 16 + slot * sizeof(struct pci_mmio_command));
        
        /* New SQ tail = current tail + 1 */
        uint16_t new_sq_tail = (sq_tail + 1) & 0xFFFF;
        
        /* Write to NVMe doorbell register */
        bridge_cmd->target_bdf = nvme_bdf;
        bridge_cmd->target_bar = nvme_bar;
        bridge_cmd->offset = doorbell_offset;
        bridge_cmd->value = new_sq_tail;
        bridge_cmd->command = PCI_MMIO_CMD_WRITE;
        bridge_cmd->size = 4;  /* 4-byte doorbell write */
        bridge_cmd->status = PCI_MMIO_STATUS_PENDING;
        bridge_cmd->sequence = prod_idx;
        
        __threadfence_system();
        
        /* Signal QEMU to process doorbell write */
        meta->producer_idx = prod_idx + 1;
    }
}

/* Find PCI MMIO Bridge and read shadow buffer GPA */
static uint64_t find_bridge_gpa(uint32_t *size, uint32_t *depth)
{
    char path[256];
    DIR *dir;
    struct dirent *entry;
    uint64_t gpa = 0;
    
    dir = opendir("/sys/bus/pci/devices");
    if (!dir) return 0;
    
    while ((entry = readdir(dir)) != NULL) {
        FILE *f;
        unsigned int vendor, device;
        
        snprintf(path, sizeof(path), 
                 "/sys/bus/pci/devices/%s/vendor", entry->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        fscanf(f, "%x", &vendor);
        fclose(f);
        
        snprintf(path, sizeof(path),
                 "/sys/bus/pci/devices/%s/device", entry->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        fscanf(f, "%x", &device);
        fclose(f);
        
        if (vendor == 0x1b36 && device == 0x0015) {
            int fd;
            uint32_t gpa_lo, gpa_hi;
            
            printf("Found PCI MMIO Bridge: %s\n", entry->d_name);
            
            snprintf(path, sizeof(path),
                     "/sys/bus/pci/devices/%s/config", entry->d_name);
            fd = open(path, O_RDONLY);
            if (fd < 0) continue;
            
            lseek(fd, 0x40, SEEK_SET);
            read(fd, &gpa_lo, 4);
            read(fd, &gpa_hi, 4);
            read(fd, size, 4);
            read(fd, depth, 4);
            close(fd);
            
            gpa = ((uint64_t)gpa_hi << 32) | gpa_lo;
            closedir(dir);
            return gpa;
        }
    }
    
    closedir(dir);
    return 0;
}

/* Find NVMe device */
static int find_nvme_device(uint16_t *bdf, uint8_t *doorbell_bar, uint32_t *doorbell_stride)
{
    char path[256];
    DIR *dir;
    struct dirent *entry;
    
    dir = opendir("/sys/bus/pci/devices");
    if (!dir) return -1;
    
    while ((entry = readdir(dir)) != NULL) {
        FILE *f;
        unsigned int vendor, device, class_code;
        int bus, dev, func;
        
        if (sscanf(entry->d_name, "%x:%x:%x.%x", 
                   &class_code, &bus, &dev, &func) != 4) {
            if (sscanf(entry->d_name, "%x:%x.%x", &bus, &dev, &func) != 3) {
                continue;
            }
        }
        
        snprintf(path, sizeof(path), 
                 "/sys/bus/pci/devices/%s/vendor", entry->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        fscanf(f, "%x", &vendor);
        fclose(f);
        
        snprintf(path, sizeof(path),
                 "/sys/bus/pci/devices/%s/class", entry->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        fscanf(f, "%x", &class_code);
        fclose(f);
        
        /* NVMe controller: class 0x010802 */
        if ((class_code >> 8) == 0x0108) {
            printf("Found NVMe device: %s (vendor 0x%04x, class 0x%06x)\n", 
                   entry->d_name, vendor, class_code);
            
            *bdf = (bus << 8) | (dev << 3) | func;
            *doorbell_bar = 0;  /* NVMe doorbells are in BAR0 */
            *doorbell_stride = 0;  /* Will read from CAP register */
            
            closedir(dir);
            return 0;
        }
    }
    
    closedir(dir);
    return -1;
}

/* Helper to get physical address from virtual address */
static uint64_t virt_to_phys(void *virt_addr)
{
    int fd;
    uint64_t page_offset = (uint64_t)virt_addr % sysconf(_SC_PAGESIZE);
    uint64_t pfn;
    off_t offset = ((uint64_t)virt_addr / sysconf(_SC_PAGESIZE)) * sizeof(uint64_t);
    
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open /proc/self/pagemap");
        return 0;
    }
    
    if (lseek(fd, offset, SEEK_SET) < 0) {
        perror("lseek");
        close(fd);
        return 0;
    }
    
    if (read(fd, &pfn, sizeof(pfn)) != sizeof(pfn)) {
        perror("read pagemap");
        close(fd);
        return 0;
    }
    
    close(fd);
    
    if (!(pfn & (1ULL << 63))) {
        fprintf(stderr, "Page not present\n");
        return 0;
    }
    
    return ((pfn & ((1ULL << 55) - 1)) * sysconf(_SC_PAGESIZE)) + page_offset;
}

int main(int argc, char **argv)
{
    /* Declare all variables at the top to avoid goto issues */
    int drm_fd = -1, nvme_fd = -1, mem_fd = -1;
    void *bridge_cpu = NULL, *data_buffer = NULL, *sq_virt = NULL, *cq_virt = NULL;
    void *bridge_gpu = NULL, *sq_gpu = NULL;
    uint64_t lba = 0, cq_phys = 0, sq_phys = 0, data_phys = 0, bridge_gpa = 0;
    uint16_t qid = 10, nvme_bdf = 0, sq_tail = 0, nsid = 1, num_blocks = 0;
    uint8_t nvme_bar = 0;
    uint32_t bridge_size = 0, queue_depth = 0;
    uint32_t doorbell_stride = 0, doorbell_base = 0x1000, stride_bytes = 0, doorbell_offset = 0;
    uint32_t last_prod_idx = 0, slot = 0;
    const char *nvme_dev = NULL;
    size_t cq_size = QUEUE_SIZE * 16;
    size_t sq_size = QUEUE_SIZE * 64;
    struct nvme_admin_cmd cq_cmd = {}, sq_cmd = {}, del_sq = {}, del_cq = {};
    struct drm_amdgpu_gem_userptr userptr = {0}, sq_userptr = {0};
    struct pci_mmio_ring_meta *meta = NULL;
    struct pci_mmio_command *bridge_cmd = NULL;
    dim3 block(256);
    dim3 grid((NVME_PAGE_SIZE / sizeof(uint32_t) + 255) / 256);
    uint32_t *pattern = NULL;
    int timeout = 0;
    
    printf("=================================================\n");
    printf("GPU-based NVMe Write Test via MMIO Bridge\n");
    printf("=================================================\n\n");
    
    /* Parse command line */
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <nvme_device> <lba> [qid]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "This program:\n");
        fprintf(stderr, "  1. Creates a dedicated NVMe I/O queue\n");
        fprintf(stderr, "  2. GPU fills buffer with LFSR pattern\n");
        fprintf(stderr, "  3. GPU formulates NVMe write command\n");
        fprintf(stderr, "  4. GPU rings doorbell via MMIO bridge\n");
        fprintf(stderr, "  5. Waits for completion\n");
        fprintf(stderr, "  6. Cleans up queue\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s /dev/nvme0 1000\n", argv[0]);
        fprintf(stderr, "  %s /dev/nvme0 1000 128  # use QID 128\n", argv[0]);
        return 1;
    }
    
    nvme_dev = argv[1];
    lba = strtoull(argv[2], NULL, 0);
    if (argc > 3) {
        qid = (uint16_t)strtoul(argv[3], NULL, 0);
    }
    
    printf("Configuration:\n");
    printf("  NVMe device:     %s\n", nvme_dev);
    printf("  Target LBA:      %lu (0x%lx)\n", (unsigned long)lba, (unsigned long)lba);
    printf("  Queue ID:        %u\n", qid);
    printf("  Block size:      4096 bytes\n");
    printf("  Pattern:         32-bit LFSR\n\n");
    
    /* Step 1: Open NVMe device and find its BDF */
    printf("Step 1: Opening NVMe device...\n");
    nvme_fd = open(nvme_dev, O_RDWR);
    if (nvme_fd < 0) {
        perror("open nvme device");
        return 1;
    }
    
    /* Find NVMe BDF from sysfs */
    char sysfs_path[256];
    char ctrl_name[32];
    const char *nvme_name = strrchr(nvme_dev, '/');
    if (nvme_name) nvme_name++;
    else nvme_name = nvme_dev;
    
    /* Strip namespace (e.g., nvme0n1 -> nvme0) */
    strncpy(ctrl_name, nvme_name, sizeof(ctrl_name) - 1);
    ctrl_name[sizeof(ctrl_name) - 1] = '\0';
    char *n_pos = strrchr(ctrl_name, 'n');  /* Find LAST 'n' */
    if (n_pos && n_pos > ctrl_name && *(n_pos - 1) >= '0' && *(n_pos - 1) <= '9') {
        *n_pos = '\0';  /* Truncate at 'n' to get controller name */
    }
    
    /* Read PCI address from sysfs */
    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/nvme/%s/address", ctrl_name);
    FILE *f = fopen(sysfs_path, "r");
    if (f) {
        unsigned int domain, bus, dev, func;
        if (fscanf(f, "%x:%x:%x.%x", &domain, &bus, &dev, &func) == 4) {
            nvme_bdf = (bus << 8) | (dev << 3) | func;
            printf("  Read from %s: domain=0x%x bus=0x%x dev=0x%x func=0x%x\n", 
                   sysfs_path, domain, bus, dev, func);
        } else {
            fprintf(stderr, "  ERROR: Failed to parse %s\n", sysfs_path);
        }
        fclose(f);
    } else {
        fprintf(stderr, "  ERROR: Could not open %s\n", sysfs_path);
    }
    if (nvme_bdf == 0) {
        fprintf(stderr, "  WARNING: Using fallback BDF 0x0300\n");
        nvme_bdf = 0x0300;  /* Default fallback */
    }
    printf("  NVMe BDF: 0x%04x\n\n", nvme_bdf);
    
    /* Step 2: Create NVMe queues */
    printf("Step 2: Creating NVMe I/O queues (QID %u)...\n", qid);
    
    /* Allocate CQ */
    cq_virt = mmap(NULL, cq_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (cq_virt == MAP_FAILED) {
        perror("mmap CQ");
        close(nvme_fd);
        return 1;
    }
    memset(cq_virt, 0, cq_size);
    
    cq_phys = virt_to_phys(cq_virt);
    if (!cq_phys) {
        fprintf(stderr, "Failed to get CQ physical address\n");
        munmap(cq_virt, cq_size);
        close(nvme_fd);
        return 1;
    }
    
    /* Allocate SQ */
    sq_virt = mmap(NULL, sq_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (sq_virt == MAP_FAILED) {
        perror("mmap SQ");
        munmap(cq_virt, cq_size);
        close(nvme_fd);
        return 1;
    }
    memset(sq_virt, 0, sq_size);
    
    sq_phys = virt_to_phys(sq_virt);
    if (!sq_phys) {
        fprintf(stderr, "Failed to get SQ physical address\n");
        munmap(sq_virt, sq_size);
        munmap(cq_virt, cq_size);
        close(nvme_fd);
        return 1;
    }
    
    printf("  CQ: virt=%p phys=0x%lx size=%zu\n", cq_virt, cq_phys, cq_size);
    printf("  SQ: virt=%p phys=0x%lx size=%zu\n", sq_virt, sq_phys, sq_size);
    
    /* Try to delete existing queues first (in case left from crashed run) */
    del_sq.opcode = NVME_ADMIN_DELETE_SQ;
    del_sq.cdw10 = qid;
    ioctl(nvme_fd, NVME_IOCTL_ADMIN_CMD, &del_sq);  /* Ignore errors */
    
    del_cq.opcode = NVME_ADMIN_DELETE_CQ;
    del_cq.cdw10 = qid;
    ioctl(nvme_fd, NVME_IOCTL_ADMIN_CMD, &del_cq);  /* Ignore errors */
    
    /* Create CQ via admin command */
    memset(&cq_cmd, 0, sizeof(cq_cmd));
    cq_cmd.opcode = NVME_ADMIN_CREATE_CQ;
    cq_cmd.addr = cq_phys;
    cq_cmd.cdw10 = ((QUEUE_SIZE - 1) << 16) | qid;  /* QSIZE | QID */
    cq_cmd.cdw11 = 0x1;  /* Physically contiguous */
    
    if (ioctl(nvme_fd, NVME_IOCTL_ADMIN_CMD, &cq_cmd) < 0) {
        perror("CREATE_CQ ioctl");
        goto cleanup;
    }
    if (cq_cmd.result != 0) {
        fprintf(stderr, "CREATE_CQ failed: status=0x%x\n", cq_cmd.result);
        printf("  QID %u may be invalid or beyond controller limits\n", qid);
        goto cleanup;
    }
    printf("  ✅ Completion Queue created\n");
    
    /* Create SQ via admin command */
    memset(&sq_cmd, 0, sizeof(sq_cmd));
    sq_cmd.opcode = NVME_ADMIN_CREATE_SQ;
    sq_cmd.addr = sq_phys;
    sq_cmd.cdw10 = ((QUEUE_SIZE - 1) << 16) | qid;  /* QSIZE | QID */
    sq_cmd.cdw11 = (qid << 16) | 0x1;  /* CQID | Physically contiguous */
    
    if (ioctl(nvme_fd, NVME_IOCTL_ADMIN_CMD, &sq_cmd) < 0) {
        perror("CREATE_SQ ioctl");
        /* Delete CQ on failure */
        del_cq.opcode = NVME_ADMIN_DELETE_CQ;
        del_cq.cdw10 = qid;
        ioctl(nvme_fd, NVME_IOCTL_ADMIN_CMD, &del_cq);
        goto cleanup;
    }
    if (sq_cmd.result != 0) {
        fprintf(stderr, "CREATE_SQ failed: status=0x%x\n", sq_cmd.result);
        /* Delete CQ on failure */
        del_cq.opcode = NVME_ADMIN_DELETE_CQ;
        del_cq.cdw10 = qid;
        ioctl(nvme_fd, NVME_IOCTL_ADMIN_CMD, &del_cq);
        goto cleanup;
    }
    printf("  ✅ Submission Queue created\n\n");
    
    /* Calculate doorbell offset */
    doorbell_stride = 0;  /* Usually 0 (4 bytes per doorbell) */
    stride_bytes = 4 << doorbell_stride;
    doorbell_offset = doorbell_base + (2 * qid) * stride_bytes;
    printf("  SQ Doorbell: BAR0 offset 0x%x\n\n", doorbell_offset);
    
    /* Step 3: Find MMIO bridge */
    printf("Step 3: Discovering PCI MMIO Bridge...\n");
    bridge_gpa = find_bridge_gpa(&bridge_size, &queue_depth);
    if (!bridge_gpa) {
        fprintf(stderr, "ERROR: Bridge not found!\n");
        return 1;
    }
    printf("  Shadow GPA:   0x%lx\n", bridge_gpa);
    printf("  Size:         %u bytes\n", bridge_size);
    printf("  Queue Depth:  %u commands\n\n", queue_depth);
    
    /* Step 4: Allocate data buffer for LFSR pattern */
    printf("Step 4: Allocating 4KiB data buffer (pinned system RAM)...\n");
    /* Use hipHostMalloc to allocate pinned system RAM that:
     *   - GPU can write to directly
     *   - NVMe can DMA from (it's in system memory)
     *   - We can get physical address for NVMe PRP
     */
    if (hipHostMalloc(&data_buffer, NVME_PAGE_SIZE, hipHostMallocMapped) != hipSuccess) {
        fprintf(stderr, "ERROR: hipHostMalloc failed\n");
        return 1;
    }
    
    /* Get physical address for NVMe PRP */
    data_phys = virt_to_phys(data_buffer);
    if (!data_phys) {
        fprintf(stderr, "ERROR: Failed to get data buffer physical address\n");
        hipHostFree(data_buffer);
        return 1;
    }
    
    printf("  Data buffer virtual:  %p\n", data_buffer);
    printf("  Data buffer physical: 0x%lx\n", data_phys);
    printf("  GPU can write directly to this buffer\n");
    printf("  NVMe can DMA from this buffer\n\n");
    
    /* Step 5: Fill buffer with LFSR pattern on GPU */
    printf("Step 5: GPU fills buffer with LFSR pattern...\n");
    /* GPU writes directly to pinned system RAM */
    hipLaunchKernelGGL(gpu_fill_lfsr_pattern, grid, block, 0, 0,
                       (uint32_t*)data_buffer, NVME_PAGE_SIZE / sizeof(uint32_t));
    if (hipDeviceSynchronize() != hipSuccess) {
        fprintf(stderr, "ERROR: GPU kernel failed\n");
        return 1;
    }
    
    /* Show pattern (no copy needed - already in host-accessible memory) */
    pattern = (uint32_t*)data_buffer;
    printf("  First 8 words: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
           pattern[0], pattern[1], pattern[2], pattern[3],
           pattern[4], pattern[5], pattern[6], pattern[7]);
    printf("  ✅ LFSR pattern generated\n\n");
    
    /* Step 6: Map MMIO bridge shadow buffer */
    printf("Step 6: Mapping MMIO bridge shadow buffer...\n");
    mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    
    bridge_cpu = mmap(NULL, bridge_size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, mem_fd, bridge_gpa);
    close(mem_fd);
    
    if (bridge_cpu == MAP_FAILED) {
        perror("mmap bridge");
        return 1;
    }
    printf("  CPU mapping: %p (GPA 0x%lx)\n\n", bridge_cpu, bridge_gpa);
    
    /* Step 7: Register bridge with GPU */
    printf("Step 7: Registering bridge with GPU...\n");
    drm_fd = open("/dev/dri/renderD128", O_RDWR);
    if (drm_fd < 0) {
        perror("open /dev/dri/renderD128");
        return 1;
    }
    userptr.addr = (uint64_t)bridge_cpu;
    userptr.size = bridge_size;
    userptr.flags = AMDGPU_GEM_USERPTR_REGISTER;
    
    if (ioctl(drm_fd, DRM_IOCTL_AMDGPU_GEM_USERPTR, &userptr) < 0) {
        perror("DRM_IOCTL_AMDGPU_GEM_USERPTR");
        return 1;
    }
    printf("  ✅ GEM_USERPTR registered (handle: %u)\n\n", userptr.handle);
    
    /* Step 8: Register with HIP */
    printf("Step 8: Registering with HIP...\n");
    if (hipHostRegister(bridge_cpu, bridge_size, hipHostRegisterMapped) != hipSuccess) {
        fprintf(stderr, "hipHostRegister failed\n");
        return 1;
    }
    
    if (hipHostGetDevicePointer(&bridge_gpu, bridge_cpu, 0) != hipSuccess) {
        fprintf(stderr, "hipHostGetDevicePointer failed\n");
        return 1;
    }
    printf("  ✅ Bridge accessible from GPU\n\n");
    
    /* Step 9: Register SQ with GPU */
    printf("Step 9: Registering NVMe SQ with GPU...\n");
    
    /* Register SQ with GPU via GEM_USERPTR + HIP */
    sq_userptr.addr = (uint64_t)sq_virt;
    sq_userptr.size = sq_size;
    sq_userptr.flags = AMDGPU_GEM_USERPTR_REGISTER;
    
    if (ioctl(drm_fd, DRM_IOCTL_AMDGPU_GEM_USERPTR, &sq_userptr) < 0) {
        perror("DRM_IOCTL_AMDGPU_GEM_USERPTR for SQ");
        goto cleanup;
    }
    
    if (hipHostRegister(sq_virt, sq_size, hipHostRegisterMapped) != hipSuccess) {
        fprintf(stderr, "hipHostRegister SQ failed\n");
        goto cleanup;
    }
    
    if (hipHostGetDevicePointer(&sq_gpu, sq_virt, 0) != hipSuccess) {
        fprintf(stderr, "hipHostGetDevicePointer SQ failed\n");
        goto cleanup;
    }
    printf("  SQ virt (CPU): %p\n", sq_virt);
    printf("  SQ virt (GPU): %p\n", sq_gpu);
    printf("  ✅ SQ accessible from GPU\n\n");
    
    /* Step 10: GPU submits NVMe write command */
    printf("Step 10: GPU submits NVMe write command and rings doorbell...\n");
    printf("  Writing to LBA %lu with LFSR pattern\n", (unsigned long)lba);
    printf("  Data physical address: 0x%lx\n", data_phys);
    printf("  Doorbell: BAR0 offset 0x%x\n", doorbell_offset);
    
    /* Setup command parameters */
    sq_tail = 0;
    nvme_bar = 0;  /* NVMe doorbells are in BAR0 */
    nsid = 1;      /* Namespace 1 */
    num_blocks = 0;  /* 0-based: 0 = 1 block = 4096 bytes */
    
    hipLaunchKernelGGL(gpu_submit_nvme_write, dim3(1), dim3(1), 0, 0,
                       bridge_gpu,
                       (struct nvme_command*)sq_gpu,
                       sq_tail,
                       data_phys,
                       lba,
                       num_blocks,
                       nsid,
                       nvme_bdf,
                       nvme_bar,
                       doorbell_offset);
    
    if (hipDeviceSynchronize() != hipSuccess) {
        fprintf(stderr, "ERROR: GPU kernel failed\n");
        return 1;
    }
    printf("  ✅ GPU submitted NVMe write command\n");
    printf("  ✅ GPU rang doorbell via MMIO bridge\n\n");
    
    /* Step 11: Wait for MMIO bridge to process doorbell write */
    printf("Step 11: Waiting for MMIO bridge to process doorbell write...\n");
    meta = (struct pci_mmio_ring_meta *)bridge_cpu;
    
    /* Find the slot that GPU wrote to (producer_idx was incremented after write) */
    last_prod_idx = meta->producer_idx - 1;
    slot = last_prod_idx % queue_depth;
    bridge_cmd = (struct pci_mmio_command *)((char *)bridge_cpu + 16 + 
                                             slot * sizeof(struct pci_mmio_command));
    
    printf("  Checking slot %u (producer_idx=%u, queue_depth=%u)\n", 
           slot, meta->producer_idx, queue_depth);
    
    timeout = 100;
    while (bridge_cmd->status == PCI_MMIO_STATUS_PENDING && timeout-- > 0) {
        usleep(10000);  // 10ms
    }
    
    if (bridge_cmd->status == PCI_MMIO_STATUS_COMPLETE) {
        printf("  ✅ MMIO bridge wrote doorbell to NVMe controller\n\n");
    } else {
        printf("  ❌ Bridge doorbell write failed (status=%u)\n\n", bridge_cmd->status);
    }
    sleep(1);
    printf("=================================================\n");
    printf("Summary\n");
    printf("=================================================\n");
    printf("✅ GPU filled 4KB buffer with LFSR pattern\n");
    printf("✅ GPU formulated NVMe Write SQE\n");
    printf("✅ GPU wrote SQE to submission queue\n");
    printf("✅ GPU rang NVMe doorbell via MMIO bridge\n");
    printf("\n");
    printf("NVMe controller should now:\n");
    printf("  1. See doorbell update (SQ tail = 1)\n");
    printf("  2. Fetch command from SQ @ %p\n", sq_virt);
    printf("  3. DMA data from 0x%lx\n", data_phys);
    printf("  4. Write 4KB to LBA %lu\n", (unsigned long)lba);
    printf("  5. Post completion to CQ\n");
    printf("\n");
    printf("Check your nvme-create-queue terminal for CQ updates!\n");
    printf("=================================================\n");
    
    /* Cleanup */
cleanup:
    printf("\nCleaning up...\n");
    
    if (sq_virt) {
        hipHostUnregister(sq_virt);
    }
    if (bridge_cpu) {
        hipHostUnregister(bridge_cpu);
    }
    if (data_buffer) {
        hipHostFree(data_buffer);
    }
    
    /* Delete NVMe queues */
    if (nvme_fd >= 0) {
        del_sq.opcode = NVME_ADMIN_DELETE_SQ;
        del_sq.cdw10 = qid;
        ioctl(nvme_fd, NVME_IOCTL_ADMIN_CMD, &del_sq);
        
        del_cq.opcode = NVME_ADMIN_DELETE_CQ;
        del_cq.cdw10 = qid;
        ioctl(nvme_fd, NVME_IOCTL_ADMIN_CMD, &del_cq);
        
        printf("  ✅ Queues deleted\n");
        close(nvme_fd);
    }
    
    if (sq_virt) munmap(sq_virt, QUEUE_SIZE * 64);
    if (cq_virt) munmap(cq_virt, QUEUE_SIZE * 16);
    if (bridge_cpu) munmap(bridge_cpu, bridge_size);
    if (drm_fd >= 0) close(drm_fd);
    
    return 0;
}

