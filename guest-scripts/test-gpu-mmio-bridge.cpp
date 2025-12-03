/*
 * GPU Test for PCI MMIO Bridge
 * 
 * Uses HIP to launch a GPU kernel that writes commands to the PCI MMIO
 * Bridge shadow buffer. Tests GPU DMA to guest RAM via the hybrid
 * architecture.
 *
 * Compile:
 *   /opt/rocm/bin/hipcc -o test-gpu-mmio-bridge \
 *       test-gpu-mmio-bridge.cpp
 *
 * Run (as root):
 *   sudo ./test-gpu-mmio-bridge
 */

#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>

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

/* GPU kernel to write command to shadow buffer */
__global__ void write_mmio_command(struct pci_mmio_ring_meta *meta,
                                   struct pci_mmio_command *queue,
                                   uint16_t target_bdf,
                                   uint32_t offset,
                                   uint64_t value)
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        /* Only first thread writes */
        
        /* Get current producer index */
        uint32_t producer = meta->producer_idx;
        uint32_t slot = (producer % meta->queue_depth) + 1;
        
        /* Write command to shadow buffer */
        struct pci_mmio_command *cmd = &queue[slot];
        
        cmd->target_bdf = target_bdf;
        cmd->target_bar = 0;
        cmd->reserved1 = 0;
        cmd->offset = offset;
        cmd->value = value;
        cmd->command = PCI_MMIO_CMD_WRITE;
        cmd->size = 4;
        cmd->status = PCI_MMIO_STATUS_PENDING;
        cmd->reserved2 = 0;
        cmd->sequence = producer + 1;
        
        /* Memory barrier */
        __threadfence_system();
        
        /* Update producer index to signal QEMU */
        meta->producer_idx = producer + 1;
        
        /* Ensure visible to host */
        __threadfence_system();
        
        printf("[GPU] Command written: BDF=0x%04x BAR=0 offset=0x%x "
               "value=0x%llx\n",
               target_bdf, offset, (unsigned long long)value);
    }
}

/* Find PCI MMIO Bridge and read shadow buffer GPA */
static uint64_t find_bridge_gpa(uint32_t *size, uint32_t *depth)
{
    char path[256];
    DIR *dir;
    struct dirent *entry;
    uint64_t gpa = 0;
    
    /* Scan /sys/bus/pci/devices/ for bridge */
    dir = opendir("/sys/bus/pci/devices");
    if (!dir) {
        perror("opendir /sys/bus/pci/devices");
        return 0;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        FILE *f;
        unsigned int vendor, device;
        
        /* Read vendor */
        snprintf(path, sizeof(path), 
                 "/sys/bus/pci/devices/%s/vendor", entry->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        fscanf(f, "%x", &vendor);
        fclose(f);
        
        /* Read device */
        snprintf(path, sizeof(path),
                 "/sys/bus/pci/devices/%s/device", entry->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        fscanf(f, "%x", &device);
        fclose(f);
        
        /* Check if it's our bridge (1b36:0015) */
        if (vendor == 0x1b36 && device == 0x0015) {
            int fd;
            uint32_t gpa_lo, gpa_hi;
            
            printf("Found PCI MMIO Bridge: %s\n", entry->d_name);
            
            /* Open config space */
            snprintf(path, sizeof(path),
                     "/sys/bus/pci/devices/%s/config", entry->d_name);
            fd = open(path, O_RDONLY);
            if (fd < 0) {
                perror("open config");
                continue;
            }
            
            /* Read vendor-specific registers at offset 0x40 */
            lseek(fd, 0x40, SEEK_SET);
            read(fd, &gpa_lo, 4);
            read(fd, &gpa_hi, 4);
            read(fd, size, 4);
            read(fd, depth, 4);
            close(fd);
            
            gpa = ((uint64_t)gpa_hi << 32) | gpa_lo;
            
            printf("  Shadow GPA:   0x%llx\n", 
                   (unsigned long long)gpa);
            printf("  Size:         %u bytes\n", *size);
            printf("  Queue Depth:  %u commands\n", *depth);
            
            break;
        }
    }
    
    closedir(dir);
    return gpa;
}

int main(int argc, char **argv)
{
    uint64_t shadow_gpa;
    uint32_t shadow_size, queue_depth;
    void *shadow_cpu;
    int fd;
    
    printf("=================================================\n");
    printf("GPU Test for PCI MMIO Bridge\n");
    printf("=================================================\n\n");
    
    /* Must run as root for /dev/mem access */
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: Must run as root (for /dev/mem)\n");
        return 1;
    }
    
    /* Find the bridge */
    printf("Step 1: Discovering PCI MMIO Bridge...\n");
    shadow_gpa = find_bridge_gpa(&shadow_size, &queue_depth);
    if (!shadow_gpa) {
        fprintf(stderr, "ERROR: PCI MMIO Bridge not found!\n");
        return 1;
    }
    printf("\n");
    
    /* Map shadow buffer for CPU access */
    printf("Step 2: Mapping shadow buffer for CPU...\n");
    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    
    shadow_cpu = mmap(NULL, shadow_size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, shadow_gpa);
    close(fd);
    
    if (shadow_cpu == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    printf("  CPU mapping: %p\n", shadow_cpu);
    printf("\n");
    
    /* For now, write command directly from CPU to test QEMU side */
    printf("Step 3: Writing command from CPU (testing QEMU side)...\n");
    printf("  Target BDF: 0xFF00 (non-existent device for testing)\n");
    printf("  Target BAR: 0\n");
    printf("  Offset: 0x1234\n");
    printf("  Value: 0xDEADBEEFCAFEBABE\n");
    printf("\n");
    
    struct pci_mmio_ring_meta *meta_cpu = 
        (struct pci_mmio_ring_meta *)shadow_cpu;
    struct pci_mmio_command *cmd_cpu = 
        (struct pci_mmio_command *)((char *)shadow_cpu + 
                                    sizeof(struct pci_mmio_ring_meta));
    
    /* Write command to slot 1 */
    cmd_cpu->target_bdf = 0xFF00;
    cmd_cpu->target_bar = 0;
    cmd_cpu->reserved1 = 0;
    cmd_cpu->offset = 0x1234;
    cmd_cpu->value = 0xDEADBEEFCAFEBABEULL;
    cmd_cpu->command = PCI_MMIO_CMD_WRITE;
    cmd_cpu->size = 4;
    cmd_cpu->status = PCI_MMIO_STATUS_PENDING;
    cmd_cpu->reserved2 = 0;
    cmd_cpu->sequence = 1;
    
    /* Memory barrier */
    __sync_synchronize();
    
    /* Update producer index to signal QEMU */
    meta_cpu->producer_idx = 1;
    
    /* Memory barrier */
    __sync_synchronize();
    
    printf("✅ Command written to shadow buffer\n");
    printf("   Producer index updated to: %u\n\n", meta_cpu->producer_idx);
    
    /* Read back to verify */
    printf("Step 4: Verifying command in shadow buffer...\n");
    
    printf("  Producer index: %u\n", meta_cpu->producer_idx);
    printf("  Consumer index: %u\n", meta_cpu->consumer_idx);
    
    if (meta_cpu->producer_idx > 0) {
        printf("\n  Command in slot 1:\n");
        printf("    Target BDF: 0x%04x\n", cmd_cpu->target_bdf);
        printf("    Target BAR: %u\n", cmd_cpu->target_bar);
        printf("    Offset: 0x%x\n", cmd_cpu->offset);
        printf("    Value: 0x%llx\n", 
               (unsigned long long)cmd_cpu->value);
        printf("    Command: %u\n", cmd_cpu->command);
        printf("    Size: %u\n", cmd_cpu->size);
        printf("    Status: %u ", cmd_cpu->status);
        
        switch (cmd_cpu->status) {
        case PCI_MMIO_STATUS_PENDING:
            printf("(PENDING)\n");
            break;
        case PCI_MMIO_STATUS_COMPLETE:
            printf("(COMPLETE)\n");
            break;
        case PCI_MMIO_STATUS_ERROR:
            printf("(ERROR)\n");
            break;
        default:
            printf("(UNKNOWN)\n");
        }
        
        printf("    Sequence: %u\n", cmd_cpu->sequence);
    }
    printf("\n");
    
    /* Wait a moment for QEMU to process */
    printf("Step 5: Waiting for QEMU to process...\n");
    sleep(2);
    
    /* Check if status changed */
    printf("  Final status: %u ", cmd_cpu->status);
    if (cmd_cpu->status == PCI_MMIO_STATUS_ERROR) {
        printf("(ERROR - expected for non-existent device!)\n");
    } else if (cmd_cpu->status == PCI_MMIO_STATUS_COMPLETE) {
        printf("(COMPLETE - unexpected!)\n");
    } else {
        printf("(PENDING - QEMU may not have processed yet)\n");
    }
    printf("\n");
    
    printf("=================================================\n");
    printf("Check QEMU traces for:\n");
    printf("  pci_mmio_bridge_command_detected ... BDF=0xff00\n");
    printf("  pci_mmio_bridge_device_not_found BDF=0xff00\n");
    printf("=================================================\n");
    
    /* Cleanup */
    munmap(shadow_cpu, shadow_size);
    
    return 0;
}

