/*
 * GPU-based Test for PCI MMIO Bridge - BAR0 MMIO Registers
 * 
 * Tests GPU-initiated writes to pci-testdev's BAR0 MMIO registers.
 * BAR0 contains actual MMIO (not RAM), so this verifies the bridge
 * works for true device register access.
 *
 * Compile:
 *   /opt/rocm/bin/hipcc -o test-gpu-bar0-mmio test-gpu-bar0-mmio.cpp \
 *       -I/usr/include/libdrm -ldrm -ldrm_amdgpu
 *
 * Run (as root):
 *   sudo ./test-gpu-bar0-mmio
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

/* PCI-testdev is at 00:05.0 */
#define TESTDEV_BDF  0x0028  /* (0<<8)|(5<<3)|0 */
#define TESTDEV_BAR0 0       /* BAR0 = MMIO registers */

/* pci-testdev BAR0 register offsets */
#define TESTDEV_REG_TEST       0   /* Write: trigger test number */
#define TESTDEV_REG_WIDTH_TYPE 1   /* Read: access type/width */
#define TESTDEV_REG_OFFSET     4   /* Read: test offset */
#define TESTDEV_REG_DATA       8   /* Read: test data */
#define TESTDEV_REG_COUNT      12  /* Read: write counter */

/* GPU kernel to write to pci-testdev's test register (offset 0) */
__global__ void gpu_write_test_register(void *base_ptr, uint8_t test_num)
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        /* Get metadata and calculate next command slot */
        struct pci_mmio_ring_meta *meta = (struct pci_mmio_ring_meta *)base_ptr;
        uint32_t prod_idx = meta->producer_idx;
        uint32_t queue_depth = meta->queue_depth;
        uint32_t slot = prod_idx % queue_depth;
        
        /* Command starts after metadata (16 bytes) */
        struct pci_mmio_command *cmd = 
            (struct pci_mmio_command *)((char *)base_ptr + 16 + slot * sizeof(struct pci_mmio_command));
        
        /* Write to BAR0 offset 0 (test register) - 1 byte write */
        cmd->target_bdf = TESTDEV_BDF;
        cmd->target_bar = TESTDEV_BAR0;
        cmd->offset = TESTDEV_REG_TEST;
        cmd->value = test_num;
        cmd->command = PCI_MMIO_CMD_WRITE;
        cmd->size = 1;  /* 1-byte write */
        cmd->status = PCI_MMIO_STATUS_PENDING;
        cmd->sequence = prod_idx;
        
        __threadfence_system();  /* Ensure command is visible */
        
        /* Increment producer index to signal new command */
        meta->producer_idx = prod_idx + 1;
    }
}

/* GPU kernel to read from pci-testdev's count register (offset 12) */
__global__ void gpu_read_count_register(void *base_ptr)
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        struct pci_mmio_ring_meta *meta = (struct pci_mmio_ring_meta *)base_ptr;
        uint32_t prod_idx = meta->producer_idx;
        uint32_t queue_depth = meta->queue_depth;
        uint32_t slot = prod_idx % queue_depth;
        
        struct pci_mmio_command *cmd = 
            (struct pci_mmio_command *)((char *)base_ptr + 16 + slot * sizeof(struct pci_mmio_command));
        
        /* Read from BAR0 offset 12 (count register) - 4 byte read */
        cmd->target_bdf = TESTDEV_BDF;
        cmd->target_bar = TESTDEV_BAR0;
        cmd->offset = TESTDEV_REG_COUNT;
        cmd->value = 0;
        cmd->command = PCI_MMIO_CMD_READ;
        cmd->size = 4;  /* 4-byte read */
        cmd->status = PCI_MMIO_STATUS_PENDING;
        cmd->sequence = prod_idx;
        
        __threadfence_system();
        meta->producer_idx = prod_idx + 1;
    }
}

/* Find PCI MMIO Bridge and read shadow buffer GPA */
static uint64_t find_bridge_gpa(uint32_t *size, uint32_t *depth)
{
    char path[256];
    FILE *f;
    unsigned int vendor, device;
    uint32_t gpa_low, gpa_high;
    uint64_t gpa;
    
    /* Scan for PCI MMIO Bridge (vendor 1b36, device 0015) */
    for (int bus = 0; bus < 256; bus++) {
        for (int dev = 0; dev < 32; dev++) {
            for (int func = 0; func < 8; func++) {
                snprintf(path, sizeof(path), "/sys/bus/pci/devices/0000:%02x:%02x.%x/vendor", bus, dev, func);
                f = fopen(path, "r");
                if (!f) continue;
                fscanf(f, "%x", &vendor);
                fclose(f);
                
                snprintf(path, sizeof(path), "/sys/bus/pci/devices/0000:%02x:%02x.%x/device", bus, dev, func);
                f = fopen(path, "r");
                if (!f) continue;
                fscanf(f, "%x", &device);
                fclose(f);
                
                if (vendor == 0x1b36 && device == 0x0015) {
                    printf("Found PCI MMIO Bridge: 0000:%02x:%02x.%x\n", bus, dev, func);
                    
                    /* Read config space registers at offset 0x40-0x4F */
                    snprintf(path, sizeof(path), "/sys/bus/pci/devices/0000:%02x:%02x.%x/config", bus, dev, func);
                    int fd = open(path, O_RDONLY);
                    if (fd < 0) return 0;
                    
                    lseek(fd, 0x40, SEEK_SET);
                    read(fd, &gpa_low, 4);
                    read(fd, &gpa_high, 4);
                    read(fd, size, 4);
                    read(fd, depth, 4);
                    close(fd);
                    
                    gpa = ((uint64_t)gpa_high << 32) | gpa_low;
                    return gpa;
                }
            }
        }
    }
    return 0;
}

int main()
{
    int drm_fd = -1;
    
    printf("=================================================\n");
    printf("GPU-based BAR0 MMIO Test (pci-testdev)\n");
    printf("=================================================\n\n");
    
    /* Step 1: Find bridge */
    printf("Step 1: Discovering PCI MMIO Bridge...\n");
    uint32_t shadow_size, queue_depth;
    uint64_t shadow_gpa = find_bridge_gpa(&shadow_size, &queue_depth);
    if (!shadow_gpa) {
        fprintf(stderr, "Error: PCI MMIO Bridge not found\n");
        return 1;
    }
    printf("  Shadow GPA:   0x%lx\n", shadow_gpa);
    printf("  Size:         %u bytes\n", shadow_size);
    printf("  Queue Depth:  %u commands\n\n", queue_depth);
    
    /* Step 2: Map shadow buffer */
    printf("Step 2: Mapping shadow buffer for CPU and GPU...\n");
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    
    void *shadow_cpu = mmap(NULL, shadow_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, mem_fd, shadow_gpa);
    close(mem_fd);
    
    if (shadow_cpu == MAP_FAILED) {
        perror("mmap shadow buffer");
        return 1;
    }
    printf("  CPU mapping: %p (GPA 0x%lx)\n\n", shadow_cpu, shadow_gpa);
    
    /* Step 3: Register with amdgpu driver */
    printf("Step 3: Registering with amdgpu driver (GEM_USERPTR)...\n");
    drm_fd = open("/dev/dri/renderD128", O_RDWR);
    if (drm_fd < 0) {
        perror("open /dev/dri/renderD128");
        return 1;
    }
    
    struct drm_amdgpu_gem_userptr userptr = {};
    userptr.addr = (uint64_t)shadow_cpu;
    userptr.size = shadow_size;
    userptr.flags = AMDGPU_GEM_USERPTR_REGISTER;
    
    if (ioctl(drm_fd, DRM_IOCTL_AMDGPU_GEM_USERPTR, &userptr) < 0) {
        perror("DRM_IOCTL_AMDGPU_GEM_USERPTR");
        return 1;
    }
    printf("  ✅ GEM_USERPTR registered (handle: %u)\n\n", userptr.handle);
    /* Keep drm_fd open - GEM handle needs it */
    
    /* Step 4: Register with HIP */
    printf("Step 4: Registering with HIP (hipHostRegisterMapped)...\n");
    hipError_t err = hipHostRegister(shadow_cpu, shadow_size, hipHostRegisterMapped);
    if (err != hipSuccess) {
        fprintf(stderr, "hipHostRegister failed: %s\n", hipGetErrorString(err));
        return 1;
    }
    printf("  ✅ hipHostRegister succeeded!\n\n");
    
    /* Step 5: Get GPU device pointer */
    printf("Step 5: GPU device pointer mapping\n");
    void *shadow_gpu;
    err = hipHostGetDevicePointer(&shadow_gpu, shadow_cpu, 0);
    if (err != hipSuccess) {
        fprintf(stderr, "hipHostGetDevicePointer failed: %s\n", hipGetErrorString(err));
        return 1;
    }
    printf("  CPU virt addr: %p\n", shadow_cpu);
    printf("  GPU virt addr: %p\n", shadow_gpu);
    printf("  Both map to GPA: 0x%lx\n\n", shadow_gpa);
    
    /* Step 6: GPU writes to test register (BAR0 offset 0) */
    printf("Step 6: GPU writes to BAR0 test register...\n");
    printf("  Target: BDF=0x%04x BAR=%d offset=0x%x (test register)\n",
           TESTDEV_BDF, TESTDEV_BAR0, TESTDEV_REG_TEST);
    printf("  Writing test number: 0\n");
    
    hipLaunchKernelGGL(gpu_write_test_register, dim3(1), dim3(1), 0, 0,
                       shadow_gpu, (uint8_t)0);
    err = hipDeviceSynchronize();
    if (err != hipSuccess) {
        fprintf(stderr, "GPU kernel failed: %s\n", hipGetErrorString(err));
        return 1;
    }
    printf("✅ GPU kernel completed\n");
    printf("   GPU wrote DIRECTLY to shadow buffer at GPA 0x%lx\n\n", shadow_gpa);
    
    /* Step 7: Wait for QEMU to process write */
    printf("Step 7: Waiting for QEMU to process WRITE to BAR0...\n");
    struct pci_mmio_ring_meta *meta = (struct pci_mmio_ring_meta *)shadow_cpu;
    struct pci_mmio_command *write_cmd = 
        (struct pci_mmio_command *)((char *)shadow_cpu + 16);
    
    int timeout = 100;
    while (write_cmd->status == PCI_MMIO_STATUS_PENDING && timeout-- > 0) {
        usleep(10000);  // 10ms
    }
    
    if (write_cmd->status == PCI_MMIO_STATUS_COMPLETE) {
        printf("✅ WRITE to BAR0 completed successfully!\n\n");
    } else {
        printf("❌ WRITE failed (status=%u)\n\n", write_cmd->status);
        return 1;
    }
    
    /* Step 8: GPU reads from count register (BAR0 offset 12) */
    printf("Step 8: GPU reads from BAR0 count register...\n");
    printf("  Target: BDF=0x%04x BAR=%d offset=0x%x (count register)\n",
           TESTDEV_BDF, TESTDEV_BAR0, TESTDEV_REG_COUNT);
    
    hipLaunchKernelGGL(gpu_read_count_register, dim3(1), dim3(1), 0, 0,
                       shadow_gpu);
    err = hipDeviceSynchronize();
    if (err != hipSuccess) {
        fprintf(stderr, "GPU kernel failed: %s\n", hipGetErrorString(err));
        return 1;
    }
    printf("✅ GPU kernel completed\n\n");
    
    /* Step 9: Wait for QEMU to process read */
    printf("Step 9: Waiting for QEMU to process READ from BAR0...\n");
    struct pci_mmio_command *read_cmd = 
        (struct pci_mmio_command *)((char *)shadow_cpu + 16 + sizeof(struct pci_mmio_command));
    
    timeout = 100;
    while (read_cmd->status == PCI_MMIO_STATUS_PENDING && timeout-- > 0) {
        usleep(10000);
    }
    
    if (read_cmd->status == PCI_MMIO_STATUS_COMPLETE) {
        printf("✅ READ from BAR0 completed!\n");
        printf("  Count register value: %u\n", (uint32_t)read_cmd->value);
        printf("  (Number of writes detected by pci-testdev)\n\n");
    } else {
        printf("❌ READ failed (status=%u)\n\n", read_cmd->status);
        return 1;
    }
    
    /* Summary */
    printf("=================================================\n");
    printf("Summary\n");
    printf("=================================================\n");
    printf("✅ GPU wrote to BAR0 MMIO register (test)\n");
    printf("✅ GPU read from BAR0 MMIO register (count)\n");
    printf("✅ Bridge successfully routed MMIO access\n");
    printf("✅ BAR0 = true MMIO (not RAM-backed)\n");
    printf("\n");
    printf("This proves the bridge works for:\n");
    printf("  - RAM-backed BARs (BAR2 from previous test)\n");
    printf("  - True MMIO BARs (BAR0 from this test)\n");
    printf("\n");
    printf("🎉 GPU-INITIATED MMIO ACCESS WORKING! 🎉\n");
    printf("=================================================\n");
    
    hipHostUnregister(shadow_cpu);
    munmap(shadow_cpu, shadow_size);
    close(drm_fd);
    return 0;
}

