/*
 * Find where GPU virtual address actually maps to
 * 
 * Uses /proc/self/pagemap to find the physical address that
 * a GPU device pointer maps to.
 *
 * Compile: hipcc -o find-gpu-physical-addr find-gpu-physical-addr.cpp
 * Run: sudo ./find-gpu-physical-addr
 */

#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

/* Get physical address from virtual address using /proc/self/pagemap */
static uint64_t vtop(void *vaddr)
{
    uint64_t pinfo;
    uintptr_t addr = (uintptr_t)vaddr;
    uintptr_t pagesize = sysconf(_SC_PAGE_SIZE);
    off_t offset = (addr / pagesize) * sizeof(pinfo);
    int fd;
    
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1) {
        perror("open /proc/self/pagemap");
        return (uint64_t)-1;
    }
    
    if (pread(fd, &pinfo, sizeof(pinfo), offset) != sizeof(pinfo)) {
        perror("pread pagemap");
        close(fd);
        return (uint64_t)-1;
    }
    
    close(fd);
    
    /* Check if page is present */
    if ((pinfo & (1ULL << 63)) == 0) {
        fprintf(stderr, "Page not present\n");
        return (uint64_t)-1;
    }
    
    /* Extract PFN and compute physical address */
    uint64_t pfn = pinfo & 0x007FFFFFFFFFFFFFULL;
    uint64_t phys = (pfn * pagesize) | (addr & (pagesize - 1));
    
    return phys;
}

__global__ void gpu_write_marker(uint32_t *ptr)
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        *ptr = 0xDEADBEEF;
        __threadfence_system();
        printf("[GPU] Wrote 0xDEADBEEF to %p\n", ptr);
    }
}

int main()
{
    void *shadow_cpu;
    void *gpu_buffer;
    int fd;
    uint64_t shadow_gpa = 0x80000000;
    uint32_t shadow_size = 4096;
    hipError_t err;
    
    printf("=================================================\n");
    printf("Find GPU Physical Address Mapping\n");
    printf("=================================================\n\n");
    
    /* Map shadow buffer at known GPA */
    printf("Step 1: Map shadow buffer at GPA 0x%llx...\n", 
           (unsigned long long)shadow_gpa);
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
    
    printf("  CPU virtual:  %p\n", shadow_cpu);
    printf("  Target GPA:   0x%llx\n\n", (unsigned long long)shadow_gpa);
    
    /* Clear it */
    *(uint32_t*)shadow_cpu = 0;
    
    /* Register with HIP */
    printf("Step 2: Register with HIP...\n");
    err = hipHostRegister(shadow_cpu, shadow_size, 
                          hipHostRegisterMapped | hipExtHostRegisterUncached);
    if (err != hipSuccess) {
        fprintf(stderr, "ERROR: hipHostRegister failed: %s\n",
                hipGetErrorString(err));
        munmap(shadow_cpu, shadow_size);
        return 1;
    }
    
    /* Get GPU device pointer */
    err = hipHostGetDevicePointer(&gpu_buffer, shadow_cpu, 0);
    if (err != hipSuccess) {
        fprintf(stderr, "ERROR: hipHostGetDevicePointer failed: %s\n",
                hipGetErrorString(err));
        hipHostUnregister(shadow_cpu);
        munmap(shadow_cpu, shadow_size);
        return 1;
    }
    
    printf("  GPU virtual:  %p\n\n", gpu_buffer);
    
    /* Find physical address of CPU mapping */
    printf("Step 3: Find physical addresses...\n");
    uint64_t cpu_phys = vtop(shadow_cpu);
    if (cpu_phys != (uint64_t)-1) {
        printf("  CPU virtual %p → Physical 0x%llx\n",
               shadow_cpu, (unsigned long long)cpu_phys);
        if (cpu_phys == shadow_gpa) {
            printf("    ✅ CPU mapping points to correct GPA!\n");
        } else {
            printf("    ⚠️  CPU mapping points to different physical address!\n");
        }
    } else {
        printf("  ❌ Could not resolve CPU virtual address\n");
    }
    
    /* Try to find physical address of GPU mapping */
    uint64_t gpu_phys = vtop(gpu_buffer);
    if (gpu_phys != (uint64_t)-1) {
        printf("  GPU virtual %p → Physical 0x%llx\n",
               gpu_buffer, (unsigned long long)gpu_phys);
        if (gpu_phys == shadow_gpa) {
            printf("    ✅ GPU mapping points to target GPA 0x%llx!\n",
                   (unsigned long long)shadow_gpa);
        } else {
            printf("    ⚠️  GPU mapping points to different physical address!\n");
            printf("    → GPU writes will go to 0x%llx, not 0x%llx\n",
                   (unsigned long long)gpu_phys,
                   (unsigned long long)shadow_gpa);
        }
    } else {
        printf("  ⚠️  Could not resolve GPU virtual address from /proc/self/pagemap\n");
        printf("     (GPU memory may not be in process page tables)\n");
    }
    printf("\n");
    
    /* Test GPU write */
    printf("Step 4: GPU writes test marker...\n");
    hipLaunchKernelGGL(gpu_write_marker, dim3(1), dim3(1), 0, 0,
                       (uint32_t*)gpu_buffer);
    hipDeviceSynchronize();
    printf("\n");
    
    /* Check results */
    printf("Step 5: Check where GPU wrote...\n");
    printf("  Value at CPU ptr (%p): 0x%08x\n",
           shadow_cpu, *(uint32_t*)shadow_cpu);
    
    /* Re-read from /dev/mem to be sure */
    fd = open("/dev/mem", O_RDONLY | O_SYNC);
    void *check = mmap(NULL, 4, PROT_READ, MAP_SHARED, fd, shadow_gpa);
    printf("  Value at GPA 0x%llx: 0x%08x\n",
           (unsigned long long)shadow_gpa, *(uint32_t*)check);
    munmap(check, 4);
    close(fd);
    
    /* If GPU phys was different, check there */
    if (gpu_phys != (uint64_t)-1 && gpu_phys != shadow_gpa) {
        printf("\n  Checking GPU's physical address (0x%llx)...\n",
               (unsigned long long)gpu_phys);
        fd = open("/dev/mem", O_RDONLY | O_SYNC);
        if (fd >= 0) {
            check = mmap(NULL, 4, PROT_READ, MAP_SHARED, fd, gpu_phys);
            if (check != MAP_FAILED) {
                printf("  Value at GPU phys 0x%llx: 0x%08x\n",
                       (unsigned long long)gpu_phys, *(uint32_t*)check);
                munmap(check, 4);
            }
            close(fd);
        }
    }
    printf("\n");
    
    printf("=================================================\n");
    printf("Summary\n");
    printf("=================================================\n");
    if (cpu_phys != (uint64_t)-1 && cpu_phys == shadow_gpa) {
        printf("✅ CPU mapping correct (0x%llx)\n", (unsigned long long)shadow_gpa);
    }
    if (gpu_phys != (uint64_t)-1) {
        if (gpu_phys == shadow_gpa) {
            printf("✅ GPU mapping correct (0x%llx)\n", (unsigned long long)shadow_gpa);
            printf("   → GPU writes should reach QEMU!\n");
        } else {
            printf("❌ GPU mapping WRONG!\n");
            printf("   Target GPA:  0x%llx\n", (unsigned long long)shadow_gpa);
            printf("   Actual phys: 0x%llx\n", (unsigned long long)gpu_phys);
            printf("   → GPU writes go to wrong address\n");
        }
    } else {
        printf("⚠️  GPU mapping unknown (not in process page tables)\n");
        printf("   → GPU may be using IOMMU/separate address space\n");
    }
    printf("=================================================\n");
    
    hipHostUnregister(shadow_cpu);
    munmap(shadow_cpu, shadow_size);
    
    return 0;
}

