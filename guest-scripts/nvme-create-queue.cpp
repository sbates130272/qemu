/*
 * NVMe Queue Creation Helper
 * 
 * Creates a new I/O queue pair (SQ/CQ) and returns the addresses
 * and doorbell offsets needed for GPU-initiated I/O.
 *
 * This uses the Linux NVMe ioctl interface to send admin commands.
 *
 * Compile: g++ -o nvme-create-queue nvme-create-queue.cpp
 * Run: sudo ./nvme-create-queue /dev/nvme0
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/nvme_ioctl.h>

/* NVMe admin opcodes */
#define NVME_ADMIN_CREATE_CQ  0x05
#define NVME_ADMIN_CREATE_SQ  0x01
#define NVME_ADMIN_DELETE_SQ  0x00
#define NVME_ADMIN_DELETE_CQ  0x04
#define NVME_ADMIN_GET_FEATURES 0x0A

/* NVMe feature IDs */
#define NVME_FEAT_NUM_QUEUES  0x07

/* Queue sizes */
#define QUEUE_SIZE  64  /* Number of entries (must be power of 2) */

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

/* Get NVMe controller capabilities and doorbell stride */
static int get_nvme_info(const char *nvme_dev, uint32_t *doorbell_stride)
{
    char path[256];
    int fd;
    uint64_t cap;
    
    /* Get PCI BDF from /sys */
    snprintf(path, sizeof(path), "/sys/class/nvme/%s/device/config", 
             strrchr(nvme_dev, '/') + 1);
    
    /* For simplicity, read doorbell stride from sysfs if available */
    /* Default: doorbell stride = 0 (4 bytes per doorbell) */
    *doorbell_stride = 0;
    
    printf("Note: Using default doorbell stride of 4 bytes\n");
    printf("      (Read CAP.DSTRD from NVMe BAR0 for exact value)\n");
    
    return 0;
}

/* Get number of queues via Get Features command */
static int get_num_queues(int fd, uint32_t *num_sq, uint32_t *num_cq)
{
    struct nvme_admin_cmd cmd = {};
    cmd.opcode = NVME_ADMIN_GET_FEATURES;
    cmd.cdw10 = NVME_FEAT_NUM_QUEUES;
    
    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
        return -1;
    }
    
    /* Result format: CQC (31:16) | SQC (15:0) (0-based, so add 1) */
    *num_sq = (cmd.result & 0xFFFF) + 1;
    *num_cq = ((cmd.result >> 16) & 0xFFFF) + 1;
    
    return 0;
}

/* Count current I/O queues from sysfs */
static int count_current_queues(const char *nvme_dev)
{
    char path[256];
    char line[256];
    FILE *f;
    int count = 0;
    
    /* Extract nvme controller name (e.g., nvme0 from /dev/nvme0) */
    const char *nvme_name = strrchr(nvme_dev, '/');
    if (nvme_name) nvme_name++;
    else nvme_name = nvme_dev;
    
    /* Read queue count from sysfs - this shows kernel-allocated queues */
    snprintf(path, sizeof(path), "/sys/class/nvme/%s/queue_count", nvme_name);
    f = fopen(path, "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            count = atoi(line);
        }
        fclose(f);
        return count;
    }
    
    /* Fallback: count CPUs (kernel typically creates 1 queue per CPU) */
    f = fopen("/proc/cpuinfo", "r");
    if (!f) return -1;
    
    count = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "processor", 9) == 0) {
            count++;
        }
    }
    fclose(f);
    
    return count;  /* I/O queues (QID 1..N), admin queue is QID 0 */
}

/* Display queue information */
static int show_queue_info(const char *nvme_dev)
{
    int fd = open(nvme_dev, O_RDWR);
    if (fd < 0) {
        perror("open nvme device");
        return 1;
    }
    
    printf("=================================================\n");
    printf("NVMe Queue Information\n");
    printf("=================================================\n\n");
    
    printf("Device: %s\n\n", nvme_dev);
    
    /* Get maximum queues supported by controller */
    uint32_t max_sq, max_cq;
    if (get_num_queues(fd, &max_sq, &max_cq) == 0) {
        printf("Maximum Queues (Controller Capability):\n");
        printf("  Submission Queues (SQ): %u\n", max_sq);
        printf("  Completion Queues (CQ): %u\n\n", max_cq);
    } else {
        printf("Failed to query maximum queue count\n\n");
    }
    
    /* Get current queue count */
    int current_queues = count_current_queues(nvme_dev);
    if (current_queues >= 0) {
        printf("Current I/O Queues (Kernel-allocated):\n");
        printf("  Active I/O queues: %d\n", current_queues);
        printf("  Admin queue: 1 (QID 0)\n");
        printf("  Total queues: %d\n\n", current_queues + 1);
    }
    
    printf("Queue ID Recommendations:\n");
    printf("  - Kernel typically uses QIDs 1-%d\n", current_queues);
    printf("  - Safe QID for custom queue: %d or higher\n", current_queues + 1);
    printf("  - Example: nvme-create-queue %s %d\n\n", nvme_dev, current_queues + 1);
    
    printf("To create a custom queue for GPU I/O:\n");
    printf("  nvme-create-queue %s <qid>\n", nvme_dev);
    printf("\n");
    
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nvme_device> [qid]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Without qid: Show queue information\n");
        fprintf(stderr, "  Example: %s /dev/nvme0\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "With qid: Create custom I/O queue\n");
        fprintf(stderr, "  Example: %s /dev/nvme0 128\n", argv[0]);
        return 1;
    }
    
    const char *nvme_dev = argv[1];
    
    /* If no queue ID specified, just show information */
    if (argc == 2) {
        return show_queue_info(nvme_dev);
    }
    
    uint16_t qid = atoi(argv[2]);
    
    printf("=================================================\n");
    printf("NVMe Queue Creation for GPU I/O\n");
    printf("=================================================\n\n");
    
    printf("Device: %s\n", nvme_dev);
    printf("Queue ID: %u\n", qid);
    printf("Queue Size: %u entries\n\n", QUEUE_SIZE);
    
    /* Open NVMe character device */
    int fd = open(nvme_dev, O_RDWR);
    if (fd < 0) {
        perror("open nvme device");
        return 1;
    }
    
    /* Allocate completion queue (CQ) */
    printf("Step 1: Allocating Completion Queue...\n");
    void *cq_buffer = mmap(NULL, QUEUE_SIZE * 16, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (cq_buffer == MAP_FAILED) {
        perror("mmap CQ");
        close(fd);
        return 1;
    }
    memset(cq_buffer, 0, QUEUE_SIZE * 16);
    
    uint64_t cq_phys = virt_to_phys(cq_buffer);
    if (!cq_phys) {
        fprintf(stderr, "Failed to get CQ physical address\n");
        munmap(cq_buffer, QUEUE_SIZE * 16);
        close(fd);
        return 1;
    }
    
    printf("  CQ virtual:  %p\n", cq_buffer);
    printf("  CQ physical: 0x%lx\n", cq_phys);
    printf("  CQ size:     %u bytes (%u entries x 16 bytes)\n\n", 
           QUEUE_SIZE * 16, QUEUE_SIZE);
    
    /* Allocate submission queue (SQ) */
    printf("Step 2: Allocating Submission Queue...\n");
    void *sq_buffer = mmap(NULL, QUEUE_SIZE * 64, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (sq_buffer == MAP_FAILED) {
        perror("mmap SQ");
        munmap(cq_buffer, QUEUE_SIZE * 16);
        close(fd);
        return 1;
    }
    memset(sq_buffer, 0, QUEUE_SIZE * 64);
    
    uint64_t sq_phys = virt_to_phys(sq_buffer);
    if (!sq_phys) {
        fprintf(stderr, "Failed to get SQ physical address\n");
        munmap(sq_buffer, QUEUE_SIZE * 64);
        munmap(cq_buffer, QUEUE_SIZE * 16);
        close(fd);
        return 1;
    }
    
    printf("  SQ virtual:  %p\n", sq_buffer);
    printf("  SQ physical: 0x%lx\n", sq_phys);
    printf("  SQ size:     %u bytes (%u entries x 64 bytes)\n\n",
           QUEUE_SIZE * 64, QUEUE_SIZE);
    
    /* Create completion queue via admin command */
    printf("Step 3: Creating Completion Queue (Admin Command)...\n");
    struct nvme_admin_cmd cq_cmd = {};
    cq_cmd.opcode = NVME_ADMIN_CREATE_CQ;
    cq_cmd.cdw10 = ((QUEUE_SIZE - 1) << 16) | qid;  /* QSIZE | QID */
    cq_cmd.cdw11 = 0x1;  /* Physically contiguous */
    cq_cmd.addr = cq_phys;
    
    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cq_cmd) < 0) {
        perror("CREATE_CQ ioctl");
        printf("  Note: Queue ID %u may already exist or be in use by kernel\n", qid);
        printf("  Try a different queue ID (e.g., 200)\n");
        munmap(sq_buffer, QUEUE_SIZE * 64);
        munmap(cq_buffer, QUEUE_SIZE * 16);
        close(fd);
        return 1;
    }
    printf("  ✅ Completion Queue created (QID %u)\n\n", qid);
    
    /* Create submission queue via admin command */
    printf("Step 4: Creating Submission Queue (Admin Command)...\n");
    struct nvme_admin_cmd sq_cmd = {};
    sq_cmd.opcode = NVME_ADMIN_CREATE_SQ;
    sq_cmd.cdw10 = ((QUEUE_SIZE - 1) << 16) | qid;  /* QSIZE | QID */
    sq_cmd.cdw11 = (qid << 16) | 0x1;  /* CQID | Physically contiguous */
    sq_cmd.addr = sq_phys;
    
    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &sq_cmd) < 0) {
        perror("CREATE_SQ ioctl");
        
        /* Delete CQ on failure */
        struct nvme_admin_cmd del_cq = {};
        del_cq.opcode = NVME_ADMIN_DELETE_CQ;
        del_cq.cdw10 = qid;
        ioctl(fd, NVME_IOCTL_ADMIN_CMD, &del_cq);
        
        munmap(sq_buffer, QUEUE_SIZE * 64);
        munmap(cq_buffer, QUEUE_SIZE * 16);
        close(fd);
        return 1;
    }
    printf("  ✅ Submission Queue created (QID %u)\n\n", qid);
    
    /* Calculate doorbell offsets */
    printf("Step 5: Doorbell Register Information\n");
    uint32_t doorbell_stride;
    get_nvme_info(nvme_dev, &doorbell_stride);
    
    /* Doorbell offset = 0x1000 + (2 * qid * (4 << doorbell_stride)) */
    uint32_t doorbell_base = 0x1000;
    uint32_t stride_bytes = 4 << doorbell_stride;
    uint32_t sq_doorbell_offset = doorbell_base + (2 * qid) * stride_bytes;
    uint32_t cq_doorbell_offset = doorbell_base + (2 * qid + 1) * stride_bytes;
    
    printf("  SQ Doorbell: BAR0 offset 0x%x\n", sq_doorbell_offset);
    printf("  CQ Doorbell: BAR0 offset 0x%x\n", cq_doorbell_offset);
    printf("  (Write new tail pointer to ring doorbell)\n\n");
    
    /* Print summary for GPU program */
    printf("=================================================\n");
    printf("Summary - Use these values in GPU program:\n");
    printf("=================================================\n");
    printf("Queue ID:             %u\n", qid);
    printf("SQ virtual address:   %p\n", sq_buffer);
    printf("SQ physical address:  0x%lx\n", sq_phys);
    printf("SQ size:              %u entries\n", QUEUE_SIZE);
    printf("SQ doorbell offset:   0x%x (BAR0)\n", sq_doorbell_offset);
    printf("\n");
    printf("CQ virtual address:   %p\n", cq_buffer);
    printf("CQ physical address:  0x%lx\n", cq_phys);
    printf("CQ size:              %u entries\n", QUEUE_SIZE);
    printf("CQ doorbell offset:   0x%x (BAR0)\n", cq_doorbell_offset);
    printf("\n");
    printf("GPU can now:\n");
    printf("  1. Write NVMe commands to SQ at %p\n", sq_buffer);
    printf("  2. Ring SQ doorbell via MMIO bridge (offset 0x%x)\n", sq_doorbell_offset);
    printf("  3. Poll CQ at %p for completions\n", cq_buffer);
    printf("=================================================\n");
    
    printf("\nPress Enter to delete queues and exit...");
    getchar();
    
    /* Cleanup: Delete queues */
    printf("\nCleaning up...\n");
    
    struct nvme_admin_cmd del_sq = {};
    del_sq.opcode = NVME_ADMIN_DELETE_SQ;
    del_sq.cdw10 = qid;
    ioctl(fd, NVME_IOCTL_ADMIN_CMD, &del_sq);
    
    struct nvme_admin_cmd del_cq = {};
    del_cq.opcode = NVME_ADMIN_DELETE_CQ;
    del_cq.cdw10 = qid;
    ioctl(fd, NVME_IOCTL_ADMIN_CMD, &del_cq);
    
    munmap(sq_buffer, QUEUE_SIZE * 64);
    munmap(cq_buffer, QUEUE_SIZE * 16);
    close(fd);
    
    printf("✅ Queues deleted\n");
    
    return 0;
}

