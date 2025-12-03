/*
 * Get Physical Address of GPU VRAM Allocation
 * 
 * Explores multiple methods to obtain the physical address of a
 * hipMalloc() allocation for P2P DMA purposes.
 * 
 * Compile:
 *   /opt/rocm/bin/hipcc -o get-vram-physical get-vram-physical.cpp \
 *       -I/usr/include/libdrm -ldrm -ldrm_amdgpu
 */

#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <drm/drm.h>
#include <drm/amdgpu_drm.h>

#define TEST_SIZE (4 * 1024)  /* 4 KiB */

/* Read GPU BAR base address from sysfs */
static int get_gpu_bar0_address(uint64_t *bar_addr, uint64_t *bar_size)
{
    FILE *f;
    char path[256];
    unsigned long long start, end, flags;
    
    /* Assume GPU is card0 - adjust if needed */
    snprintf(path, sizeof(path), 
             "/sys/class/drm/card0/device/resource");
    
    f = fopen(path, "r");
    if (!f) {
        /* Try renderD128 */
        snprintf(path, sizeof(path),
                 "/sys/class/drm/renderD128/device/resource");
        f = fopen(path, "r");
        if (!f) {
            perror("open GPU resource file");
            return -1;
        }
    }
    
    /* Read BAR0 (first line in resource file) */
    if (fscanf(f, "0x%llx 0x%llx 0x%llx", &start, &end, &flags) == 3) {
        *bar_addr = start;
        *bar_size = end - start + 1;
        fclose(f);
        
        /* Verify it's 64-bit prefetchable (typical for VRAM) */
        if ((flags & 0x1200) == 0x1200) {
            return 0;
        }
        
        fprintf(stderr, "BAR0 flags unexpected: 0x%llx\n", flags);
        return -1;
    }
    
    fclose(f);
    return -1;
}

/* Method 1: Try to get GEM handle from device pointer using DRM */
static int method1_gem_handle(void *dev_ptr)
{
    printf("\n=== Method 1: DRM GEM Handle Lookup ===\n");
    
    /* Open DRM device */
    int drm_fd = open("/dev/dri/card0", O_RDWR);
    if (drm_fd < 0) {
        drm_fd = open("/dev/dri/renderD128", O_RDWR);
        if (drm_fd < 0) {
            perror("open DRM");
            return -1;
        }
    }
    
    printf("DRM device opened: fd=%d\n", drm_fd);
    
    /*
     * Problem: We have a HIP device pointer but need the GEM handle.
     * HIP doesn't expose this directly.
     * 
     * The GEM handle is created internally by HIP runtime when
     * hipMalloc() is called, but there's no public API to retrieve it.
     */
    
    printf("❌ Cannot get GEM handle from HIP device pointer\n");
    printf("   HIP runtime doesn't expose this mapping\n");
    
    close(drm_fd);
    return -1;
}

/* Method 2: Parse /proc/self/maps to find VRAM mapping */
static int method2_proc_maps(void *dev_ptr, uint64_t bar_addr)
{
    printf("\n=== Method 2: Parse /proc/self/maps ===\n");
    
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        perror("open /proc/self/maps");
        return -1;
    }
    
    char line[512];
    unsigned long start, end;
    uint64_t dev_addr = (uint64_t)dev_ptr;
    
    printf("Looking for device pointer %p in process mappings...\n", dev_ptr);
    
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (dev_addr >= start && dev_addr < end) {
                printf("Found mapping: %s", line);
                
                /* Check if it's a device mapping */
                if (strstr(line, "/dev/dri/") || strstr(line, "render")) {
                    uint64_t offset_in_mapping = dev_addr - start;
                    printf("  Offset in mapping: 0x%lx\n", offset_in_mapping);
                    printf("  ❓ This is a device file mapping\n");
                    printf("  Need to correlate with BAR offset\n");
                }
                fclose(f);
                return 0;
            }
        }
    }
    
    fclose(f);
    printf("❌ Device pointer not found in /proc/self/maps\n");
    printf("   HIP might use special memory mapping\n");
    return -1;
}

/* Method 3: Check if GPU supports exportable allocations */
static int method3_exportable_memory(void *dev_ptr)
{
    printf("\n=== Method 3: Exportable Memory Handle ===\n");
    
    hipExternalMemoryHandleDesc externalMemDesc = {};
    
    printf("HIP doesn't support exporting device allocations yet\n");
    printf("❌ hipImportExternalMemory only imports, doesn't export\n");
    
    return -1;
}

/* Method 4: Try direct BAR mapping approach */
static int method4_bar_mapping(void *dev_ptr, uint64_t bar_addr, 
                               uint64_t bar_size)
{
    printf("\n=== Method 4: Direct BAR Mapping ===\n");
    
    printf("Concept:\n");
    printf("  1. Map GPU BAR0 via /dev/mem\n");
    printf("  2. Write pattern to VRAM using HIP\n");
    printf("  3. Scan BAR mapping for the pattern\n");
    printf("  4. Calculate offset = (pattern_location - bar_base)\n");
    printf("  5. Physical addr = bar_addr + offset\n\n");
    
    printf("Attempting direct BAR scan...\n");
    
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        printf("❌ Need CONFIG_STRICT_DEVMEM=n or root privileges\n");
        return -1;
    }
    
    /* Try to map a small portion of the BAR */
    size_t map_size = 256 * 1024 * 1024;  /* 256 MB */
    if (map_size > bar_size) map_size = bar_size;
    
    void *bar_mapping = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                             MAP_SHARED, mem_fd, bar_addr);
    if (bar_mapping == MAP_FAILED) {
        perror("mmap GPU BAR");
        close(mem_fd);
        return -1;
    }
    
    printf("  ✅ Mapped GPU BAR: %p (size: %zu MB)\n",
           bar_mapping, map_size / (1024*1024));
    
    /* Write a unique pattern to VRAM using HIP */
    uint32_t magic_pattern = 0xDEADBEEF;
    printf("  Writing magic pattern 0x%08x to VRAM via HIP...\n", magic_pattern);
    
    if (hipMemcpy(dev_ptr, &magic_pattern, sizeof(magic_pattern),
                  hipMemcpyHostToDevice) != hipSuccess) {
        fprintf(stderr, "ERROR: hipMemcpy failed\n");
        munmap(bar_mapping, map_size);
        close(mem_fd);
        return -1;
    }
    
    hipDeviceSynchronize();
    printf("  ✅ Pattern written\n");
    
    /* Scan BAR for the pattern */
    printf("  Scanning BAR for pattern...\n");
    uint32_t *bar_u32 = (uint32_t *)bar_mapping;
    size_t num_dwords = map_size / sizeof(uint32_t);
    
    for (size_t i = 0; i < num_dwords; i++) {
        if (bar_u32[i] == magic_pattern) {
            uint64_t offset = i * sizeof(uint32_t);
            uint64_t phys_addr = bar_addr + offset;
            
            printf("  🎯 FOUND at offset 0x%lx!\n", offset);
            printf("  Physical address: 0x%016lx\n", phys_addr);
            printf("  ✅ This is the NVMe-accessible address!\n");
            
            munmap(bar_mapping, map_size);
            close(mem_fd);
            return 0;
        }
    }
    
    printf("  ❌ Pattern not found in scanned region\n");
    printf("  (May be beyond first %zu MB of BAR)\n", map_size / (1024*1024));
    
    munmap(bar_mapping, map_size);
    close(mem_fd);
    return -1;
}

int main(int argc, char **argv)
{
    void *vram_ptr = NULL;
    void *host_ptr = NULL;
    uint64_t bar_addr = 0, bar_size = 0;
    char gpu_bdf[32] = {0};
    
    printf("=================================================\n");
    printf("GPU VRAM P2P Physical Address Discovery\n");
    printf("=================================================\n\n");
    
    printf("Goal: Get physical address of hipMalloc() allocation\n");
    printf("      so NVMe can DMA directly from GPU VRAM\n\n");
    
    /* Get GPU BAR information */
    if (get_gpu_bar0_address(&bar_addr, &bar_size) == 0) {
        printf("GPU BAR0 Information:\n");
        printf("  Base address: 0x%016lx\n", bar_addr);
        printf("  Size: %lu GB\n\n", bar_size / (1024*1024*1024));
    }
    
    /* Allocate test buffers */
    printf("Allocating test buffers...\n");
    if (hipMalloc(&vram_ptr, TEST_SIZE) != hipSuccess) {
        fprintf(stderr, "ERROR: hipMalloc failed\n");
        return 1;
    }
    printf("  VRAM buffer: %p (hipMalloc)\n", vram_ptr);
    
    if (hipHostMalloc(&host_ptr, TEST_SIZE, 
                      hipHostMallocMapped) != hipSuccess) {
        fprintf(stderr, "ERROR: hipHostMalloc failed\n");
        hipFree(vram_ptr);
        return 1;
    }
    printf("  Host buffer: %p (hipHostMalloc)\n\n", host_ptr);
    
    /* Try different methods */
    int success = 0;
    
    success |= (method1_gem_handle(vram_ptr) == 0);
    success |= (method2_proc_maps(vram_ptr, bar_addr) == 0);
    success |= (method3_exportable_memory(vram_ptr) == 0);
    
    if (!success && bar_addr != 0) {
        success |= (method4_bar_mapping(vram_ptr, bar_addr, bar_size) == 0);
    }
    
    printf("\n=================================================\n");
    printf("Results Summary\n");
    printf("=================================================\n");
    if (success) {
        printf("✅ Found a working method to get VRAM physical address!\n");
        printf("   Can proceed with GPU VRAM → NVMe P2P test\n");
    } else {
        printf("❌ No method succeeded\n");
        printf("   Current hipHostMalloc approach is recommended\n");
    }
    
    /* Cleanup */
    hipFree(vram_ptr);
    hipFree(host_ptr);
    
    return success ? 0 : 1;
}

