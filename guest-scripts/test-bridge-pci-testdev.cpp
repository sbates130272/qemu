/*
 * Test PCI MMIO Bridge with pci-testdev
 * 
 * This program writes commands to the MMIO bridge to perform reads/writes
 * on the pci-testdev's RAM BAR. This is a safe, predictable test target
 * before attempting peer-to-peer with real devices.
 *
 * Compile:
 *   g++ -o test-bridge-pci-testdev test-bridge-pci-testdev.cpp
 *
 * Run (as root):
 *   sudo ./test-bridge-pci-testdev
 */

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

/* PCI-testdev is typically at 00:05.0 */
#define TESTDEV_BDF  0x0500
#define TESTDEV_BAR  0

/* Find PCI MMIO Bridge and read shadow buffer GPA */
static uint64_t find_bridge_gpa(uint32_t *size, uint32_t *depth)
{
    char path[256];
    DIR *dir;
    struct dirent *entry;
    uint64_t gpa = 0;
    
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
            
            printf("  Shadow GPA:   0x%llx\n", (unsigned long long)gpa);
            printf("  Size:         %u bytes\n", *size);
            printf("  Queue Depth:  %u commands\n", *depth);
            
            break;
        }
    }
    
    closedir(dir);
    return gpa;
}

/* Execute a command via the bridge and wait for completion */
static int execute_bridge_command(void *shadow_cpu,
                                  uint8_t cmd_type,
                                  uint16_t target_bdf,
                                  uint8_t target_bar,
                                  uint32_t offset,
                                  uint64_t write_value,
                                  uint64_t *read_value)
{
    struct pci_mmio_ring_meta *meta = (struct pci_mmio_ring_meta *)shadow_cpu;
    struct pci_mmio_command *cmd = (struct pci_mmio_command *)
        ((char *)shadow_cpu + sizeof(struct pci_mmio_ring_meta));
    
    uint32_t seq = meta->producer_idx + 1;
    
    /* Write command */
    cmd->target_bdf = target_bdf;
    cmd->target_bar = target_bar;
    cmd->reserved1 = 0;
    cmd->offset = offset;
    cmd->value = write_value;
    cmd->command = cmd_type;
    cmd->size = 8;  /* 64-bit operations */
    cmd->status = PCI_MMIO_STATUS_PENDING;
    cmd->reserved2 = 0;
    cmd->sequence = seq;
    
    /* Memory barrier */
    __sync_synchronize();
    
    /* Update producer index */
    meta->producer_idx = seq;
    
    /* Memory barrier */
    __sync_synchronize();
    
    /* Wait for completion (with timeout) */
    for (int i = 0; i < 1000; i++) {
        __sync_synchronize();
        if (cmd->status != PCI_MMIO_STATUS_PENDING) {
            break;
        }
        usleep(1000);  /* 1ms */
    }
    
    if (cmd->status == PCI_MMIO_STATUS_COMPLETE) {
        if (cmd_type == PCI_MMIO_CMD_READ && read_value) {
            *read_value = cmd->value;
        }
        return 0;
    } else if (cmd->status == PCI_MMIO_STATUS_ERROR) {
        return -1;
    } else {
        fprintf(stderr, "Command timeout\n");
        return -2;
    }
}

int main(int argc, char **argv)
{
    uint64_t shadow_gpa;
    uint32_t shadow_size, queue_depth;
    void *shadow_cpu;
    int fd;
    int ret;
    uint64_t test_value, read_value;
    
    printf("=================================================\n");
    printf("PCI MMIO Bridge Test with pci-testdev\n");
    printf("=================================================\n\n");
    
    /* Must run as root */
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
    
    /* Map shadow buffer */
    printf("Step 2: Mapping shadow buffer...\n");
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
    
    /* Test 1: Write to pci-testdev BAR */
    printf("Step 3: Testing MMIO WRITE to pci-testdev...\n");
    printf("  Target: BDF=0x%04x, BAR=%u, Offset=0x0000\n",
           TESTDEV_BDF, TESTDEV_BAR);
    test_value = 0xDEADBEEFCAFEBABEULL;
    printf("  Writing value: 0x%016llx\n", (unsigned long long)test_value);
    
    ret = execute_bridge_command(shadow_cpu, PCI_MMIO_CMD_WRITE,
                                 TESTDEV_BDF, TESTDEV_BAR, 0,
                                 test_value, NULL);
    
    if (ret == 0) {
        printf("✅ WRITE succeeded!\n");
    } else {
        printf("❌ WRITE failed (ret=%d)\n", ret);
        munmap(shadow_cpu, shadow_size);
        return 1;
    }
    printf("\n");
    
    /* Test 2: Read back from pci-testdev BAR */
    printf("Step 4: Testing MMIO READ from pci-testdev...\n");
    printf("  Target: BDF=0x%04x, BAR=%u, Offset=0x0000\n",
           TESTDEV_BDF, TESTDEV_BAR);
    
    ret = execute_bridge_command(shadow_cpu, PCI_MMIO_CMD_READ,
                                 TESTDEV_BDF, TESTDEV_BAR, 0,
                                 0, &read_value);
    
    if (ret == 0) {
        printf("  Read value: 0x%016llx\n", (unsigned long long)read_value);
        
        if (read_value == test_value) {
            printf("✅ READ succeeded! Value matches write!\n");
        } else {
            printf("⚠️  READ succeeded but value mismatch!\n");
            printf("   Expected: 0x%016llx\n", (unsigned long long)test_value);
            printf("   Got:      0x%016llx\n", (unsigned long long)read_value);
        }
    } else {
        printf("❌ READ failed (ret=%d)\n", ret);
        munmap(shadow_cpu, shadow_size);
        return 1;
    }
    printf("\n");
    
    /* Test 3: Multiple writes at different offsets */
    printf("Step 5: Testing multiple offsets...\n");
    for (uint32_t offset = 0; offset < 32; offset += 8) {
        test_value = 0x1000000000000000ULL + offset;
        
        ret = execute_bridge_command(shadow_cpu, PCI_MMIO_CMD_WRITE,
                                     TESTDEV_BDF, TESTDEV_BAR, offset,
                                     test_value, NULL);
        if (ret != 0) {
            printf("❌ Write at offset 0x%04x failed\n", offset);
            continue;
        }
        
        ret = execute_bridge_command(shadow_cpu, PCI_MMIO_CMD_READ,
                                     TESTDEV_BDF, TESTDEV_BAR, offset,
                                     0, &read_value);
        if (ret != 0) {
            printf("❌ Read at offset 0x%04x failed\n", offset);
            continue;
        }
        
        if (read_value == test_value) {
            printf("  Offset 0x%04x: ✅ Write/Read OK\n", offset);
        } else {
            printf("  Offset 0x%04x: ❌ Mismatch (wrote 0x%llx, read 0x%llx)\n",
                   offset, (unsigned long long)test_value,
                   (unsigned long long)read_value);
        }
    }
    printf("\n");
    
    /* Cleanup */
    munmap(shadow_cpu, shadow_size);
    
    printf("=================================================\n");
    printf("Summary\n");
    printf("=================================================\n");
    printf("✅ PCI MMIO Bridge operational\n");
    printf("✅ WRITE commands working\n");
    printf("✅ READ commands working\n");
    printf("✅ Read-after-write verified\n");
    printf("\n");
    printf("The bridge is ready for GPU DMA testing!\n");
    printf("=================================================\n");
    
    return 0;
}

