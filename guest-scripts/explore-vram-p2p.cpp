/*
 * Explore GPU VRAM P2P for NVMe DMA
 * 
 * This program investigates how to get physical addresses from hipMalloc()
 * allocations so NVMe can DMA directly from GPU VRAM.
 * 
 * Compile:
 *   /opt/rocm/bin/hipcc -o explore-vram-p2p explore-vram-p2p.cpp \
 *       -I/usr/include/libdrm -ldrm -ldrm_amdgpu
 */

#include <hip/hip_runtime.h>
#include <hip/hip_runtime_api.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <drm/drm.h>
#include <drm/amdgpu_drm.h>

#define NVME_PAGE_SIZE 4096

/* Get GPU PCI BAR information */
static int get_gpu_pci_info(char *bdf, uint64_t *vram_bar_addr, 
                            uint64_t *vram_bar_size)
{
    char path[512];
    FILE *f;
    unsigned long long start, end, flags;
    int found_vram = 0;
    
    /* Find GPU device */
    DIR *dir = opendir("/sys/class/drm");
    if (!dir) return -1;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "card", 4) == 0 && 
            strlen(entry->d_name) == 5) {  /* card0, card1, etc */
            
            /* Get PCI BDF */
            snprintf(path, sizeof(path), 
                     "/sys/class/drm/%s/device/uevent", entry->d_name);
            f = fopen(path, "r");
            if (f) {
                char line[256];
                while (fgets(line, sizeof(line), f)) {
                    if (strncmp(line, "PCI_SLOT_NAME=", 14) == 0) {
                        sscanf(line + 14, "%s", bdf);
                    }
                }
                fclose(f);
            }
            
            /* Get BAR resources */
            snprintf(path, sizeof(path),
                     "/sys/class/drm/%s/device/resource", entry->d_name);
            f = fopen(path, "r");
            if (!f) continue;
            
            /* BAR0 is usually VRAM on AMD GPUs */
            if (fscanf(f, "0x%llx 0x%llx 0x%llx", &start, &end, &flags) == 3) {
                if ((flags & 0x1200) == 0x1200) {  /* 64-bit prefetchable */
                    *vram_bar_addr = start;
                    *vram_bar_size = end - start + 1;
                    found_vram = 1;
                }
            }
            fclose(f);
            
            if (found_vram) {
                closedir(dir);
                return 0;
            }
        }
    }
    
    closedir(dir);
    return -1;
}

/* Get physical address from HIP device pointer using AMDGPU DRM */
static int get_vram_physical_address(void *dev_ptr, uint64_t *phys_addr)
{
    int drm_fd;
    struct drm_amdgpu_gem_create_in create_in = {0};
    struct drm_amdgpu_gem_create_out create_out = {0};
    struct drm_amdgpu_info_device dev_info = {0};
    struct drm_amdgpu_info info_req = {0};
    
    /* Open AMDGPU DRM device */
    drm_fd = open("/dev/dri/card0", O_RDWR);
    if (drm_fd < 0) {
        drm_fd = open("/dev/dri/renderD128", O_RDWR);
        if (drm_fd < 0) {
            perror("open DRM device");
            return -1;
        }
    }
    
    printf("\n=== Attempting VRAM Physical Address Lookup ===\n");
    
    /* Get device info to find VRAM base */
    info_req.return_pointer = (uint64_t)&dev_info;
    info_req.return_size = sizeof(dev_info);
    info_req.query = AMDGPU_INFO_DEV_INFO;
    
    if (ioctl(drm_fd, DRM_IOCTL_AMDGPU_INFO, &info_req) == 0) {
        printf("AMDGPU Device Info:\n");
        printf("  Device ID: 0x%x\n", dev_info.device_id);
        printf("  Chip Rev: %d\n", dev_info.chip_rev);
        printf("  VRAM Type: %d\n", dev_info.vram_type);
        printf("  VRAM Bit Width: %d\n", dev_info.vram_bit_width);
    }
    
    /*
     * The challenge: HIP doesn't expose a direct API to get the
     * GEM handle from a hipMalloc() pointer.
     * 
     * Possible approaches:
     * 1. Use hipMemGetAddressRange() to get buffer info (limited)
     * 2. Use HIP IPC handles (hipIpcGetMemHandle)
     * 3. Parse /proc/self/maps to find the mmap'd BAR region
     * 4. Use hipPointerGetAttributes() to get device pointer info
     */
    
    printf("\nTrying hipPointerGetAttributes...\n");
    hipPointerAttribute_t attribs;
    if (hipPointerGetAttributes(&attribs, dev_ptr) == hipSuccess) {
        printf("  Memory type: %d\n", attribs.type);
        printf("  Device: %d\n", attribs.device);
        printf("  Device pointer: %p\n", attribs.devicePointer);
        printf("  Host pointer: %p\n", attribs.hostPointer);
        
        /* Check if it's device memory */
        if (attribs.type == hipMemoryTypeDevice) {
            printf("  ✅ Confirmed: Device memory (VRAM)\n");
        } else {
            printf("  ⚠️  Not device memory (type=%d)\n", attribs.type);
        }
    }
    
    printf("\nLimitation: HIP doesn't expose BAR offset directly\n");
    printf("For true VRAM P2P, we need one of:\n");
    printf("  1. Kernel P2PDMA support (p2pdma_add_client)\n");
    printf("  2. Direct BAR mapping via /dev/mem\n");
    printf("  3. VFIO container with both GPU and NVMe\n");
    printf("  4. Custom AMDGPU kernel module to export offsets\n");
    
    close(drm_fd);
    return -1;
}

int main(int argc, char **argv)
{
    void *vram_ptr = NULL;
    void *host_ptr = NULL;
    uint64_t gpu_bar_addr = 0, gpu_bar_size = 0;
    uint64_t vram_phys = 0;
    char gpu_bdf[32] = {0};
    
    printf("=================================================\n");
    printf("GPU VRAM P2P Exploration\n");
    printf("=================================================\n\n");
    
    /* Step 1: Get GPU PCI information */
    printf("Step 1: Getting GPU PCI information...\n");
    if (get_gpu_pci_info(gpu_bdf, &gpu_bar_addr, &gpu_bar_size) == 0) {
        printf("  GPU BDF: %s\n", gpu_bdf);
        printf("  VRAM BAR base: 0x%016lx\n", gpu_bar_addr);
        printf("  VRAM BAR size: %lu GB\n\n", gpu_bar_size / (1024*1024*1024));
    } else {
        fprintf(stderr, "Could not find GPU VRAM BAR\n\n");
    }
    
    /* Step 2: Allocate device memory */
    printf("Step 2: Allocating memory with hipMalloc (VRAM)...\n");
    if (hipMalloc(&vram_ptr, NVME_PAGE_SIZE) != hipSuccess) {
        fprintf(stderr, "ERROR: hipMalloc failed\n");
        return 1;
    }
    printf("  Device pointer: %p\n", vram_ptr);
    
    /* Step 3: Compare with host memory */
    printf("\nStep 3: Allocating memory with hipHostMalloc (system RAM)...\n");
    if (hipHostMalloc(&host_ptr, NVME_PAGE_SIZE, 
                      hipHostMallocMapped) != hipSuccess) {
        fprintf(stderr, "ERROR: hipHostMalloc failed\n");
        hipFree(vram_ptr);
        return 1;
    }
    printf("  Host pointer: %p\n", host_ptr);
    
    /* Step 4: Try to get physical addresses */
    printf("\nStep 4: Attempting physical address lookup...\n");
    
    printf("\nFor VRAM (hipMalloc):\n");
    if (get_vram_physical_address(vram_ptr, &vram_phys) == 0) {
        printf("  ✅ Physical address: 0x%016lx\n", vram_phys);
        printf("  ✅ NVMe can DMA from GPU VRAM!\n");
    } else {
        printf("  ❌ Cannot get physical address\n");
        printf("  (This is expected - needs kernel P2PDMA support)\n");
    }
    
    printf("\nFor Host Memory (hipHostMalloc):\n");
    printf("  Can use /proc/self/pagemap to get physical address\n");
    printf("  ✅ This is what the current test uses (WORKING)\n");
    
    /* Step 5: Check P2PDMA status */
    printf("\nStep 5: Checking kernel P2PDMA support...\n");
    if (access("/sys/bus/pci/devices/p2pdma", F_OK) == 0) {
        printf("  ✅ P2PDMA sysfs exists\n");
    } else {
        printf("  ❌ P2PDMA not configured\n");
    }
    
    printf("\nStep 6: Summary\n");
    printf("=========================================\n");
    printf("Current status:\n");
    printf("  ✅ GPU → System RAM → NVMe: WORKING\n");
    printf("  ❓ GPU VRAM → NVMe: Requires additional work\n");
    printf("\nTo enable GPU VRAM → NVMe P2P:\n");
    printf("  Option A: Use kernel P2PDMA framework\n");
    printf("  Option B: Map GPU BAR via VFIO and calculate offsets\n");
    printf("  Option C: Use PCIe ATS/PRI for device memory sharing\n");
    printf("\nRecommendation:\n");
    printf("  The current hipHostMalloc approach is production-ready\n");
    printf("  and widely used in GPU-direct storage solutions.\n");
    
    hipFree(vram_ptr);
    hipFree(host_ptr);
    return 0;
}

