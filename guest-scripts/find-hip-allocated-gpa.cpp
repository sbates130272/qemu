/*
 * Allocate memory with HIP, find its GPA, use that for shadow buffer
 * 
 * Instead of trying to make GPU write to predetermined GPA 0x80000000,
 * let HIP allocate memory GPU can write to, find its GPA, and use that.
 *
 * Compile: hipcc -o find-hip-allocated-gpa find-hip-allocated-gpa.cpp
 * Run: sudo ./find-hip-allocated-gpa
 */

#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/mman.h>

/* Find GPA by scanning /proc/self/maps and /proc/self/pagemap */
static uint64_t find_gpa_of_allocation(void *vaddr, size_t size)
{
    /* Read /proc/self/maps to find the mapping */
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("fopen /proc/self/maps");
        return 0;
    }
    
    char line[256];
    uint64_t start_addr = (uint64_t)vaddr;
    bool found = false;
    
    printf("  Searching for VA %p in /proc/self/maps...\n", vaddr);
    
    while (fgets(line, sizeof(line), maps)) {
        uint64_t start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (start <= start_addr && start_addr < end) {
                printf("  Found mapping: %s", line);
                found = true;
                break;
            }
        }
    }
    fclose(maps);
    
    if (!found) {
        printf("  VA not found in /proc/self/maps\n");
        return 0;
    }
    
    /* Try /proc/self/pagemap */
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1) {
        perror("  open /proc/self/pagemap");
        return 0;
    }
    
    uintptr_t pagesize = sysconf(_SC_PAGE_SIZE);
    off_t offset = (start_addr / pagesize) * sizeof(uint64_t);
    uint64_t pinfo;
    
    if (pread(fd, &pinfo, sizeof(pinfo), offset) != sizeof(pinfo)) {
        perror("  pread pagemap");
        close(fd);
        return 0;
    }
    close(fd);
    
    printf("  Pagemap entry: 0x%016llx\n", (unsigned long long)pinfo);
    printf("    Present: %s\n", (pinfo & (1ULL << 63)) ? "yes" : "no");
    printf("    Swapped: %s\n", (pinfo & (1ULL << 62)) ? "yes" : "no");
    
    if ((pinfo & (1ULL << 63)) == 0) {
        printf("  Page not present in pagemap\n");
        return 0;
    }
    
    uint64_t pfn = pinfo & 0x007FFFFFFFFFFFFFULL;
    uint64_t gpa = (pfn * pagesize) | (start_addr & (pagesize - 1));
    
    return gpa;
}

__global__ void gpu_write_test(uint32_t *ptr, uint32_t value)
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        *ptr = value;
        __threadfence_system();
        printf("[GPU] Wrote 0x%08x to %p\n", value, ptr);
    }
}

int main()
{
    void *host_ptr = nullptr;
    void *device_ptr = nullptr;
    size_t size = 8192;
    hipError_t err;
    
    printf("=================================================\n");
    printf("Find GPA of HIP-Allocated Memory\n");
    printf("=================================================\n\n");
    
    /* Allocate with hipHostMalloc (CPU+GPU accessible) */
    printf("Step 1: Allocate with hipHostMalloc...\n");
    err = hipHostMalloc(&host_ptr, size, hipHostMallocMapped);
    if (err != hipSuccess) {
        fprintf(stderr, "ERROR: hipHostMalloc failed: %s\n", 
                hipGetErrorString(err));
        return 1;
    }
    printf("  Host ptr: %p\n", host_ptr);
    
    /* Get GPU device pointer */
    err = hipHostGetDevicePointer(&device_ptr, host_ptr, 0);
    if (err != hipSuccess) {
        fprintf(stderr, "ERROR: hipHostGetDevicePointer failed: %s\n",
                hipGetErrorString(err));
        hipHostFree(host_ptr);
        return 1;
    }
    printf("  Device ptr: %p\n\n", device_ptr);
    
    /* Find GPA */
    printf("Step 2: Find GPA of allocation...\n");
    uint64_t gpa = find_gpa_of_allocation(host_ptr, size);
    if (gpa) {
        printf("  ✅ GPA: 0x%llx\n\n", (unsigned long long)gpa);
    } else {
        printf("  ❌ Could not determine GPA\n\n");
    }
    
    /* Test GPU write */
    printf("Step 3: Test GPU write...\n");
    memset(host_ptr, 0, size);
    
    hipLaunchKernelGGL(gpu_write_test, dim3(1), dim3(1), 0, 0,
                       (uint32_t*)device_ptr, 0xDEADBEEF);
    err = hipDeviceSynchronize();
    if (err != hipSuccess) {
        fprintf(stderr, "ERROR: Kernel failed: %s\n", hipGetErrorString(err));
    }
    
    printf("  CPU reads back: 0x%08x\n", *(uint32_t*)host_ptr);
    
    if (*(uint32_t*)host_ptr == 0xDEADBEEF) {
        printf("  ✅ GPU write visible to CPU!\n\n");
    } else {
        printf("  ❌ GPU write NOT visible to CPU\n\n");
    }
    
    /* If we found the GPA, verify via /dev/mem */
    if (gpa && *(uint32_t*)host_ptr == 0xDEADBEEF) {
        printf("Step 4: Verify via /dev/mem...\n");
        int fd = open("/dev/mem", O_RDONLY | O_SYNC);
        if (fd >= 0) {
            void *check = mmap(NULL, 4, PROT_READ, MAP_SHARED, fd, gpa);
            if (check != MAP_FAILED) {
                uint32_t val = *(uint32_t*)check;
                printf("  Read from GPA 0x%llx: 0x%08x\n", 
                       (unsigned long long)gpa, val);
                if (val == 0xDEADBEEF) {
                    printf("  ✅ GPU write visible at GPA!\n");
                } else {
                    printf("  ⚠️  Value mismatch at GPA\n");
                }
                munmap(check, 4);
            } else {
                perror("  mmap /dev/mem");
            }
            close(fd);
        }
    }
    printf("\n");
    
    /* Summary */
    printf("=================================================\n");
    printf("Summary\n");
    printf("=================================================\n");
    if (gpa && *(uint32_t*)host_ptr == 0xDEADBEEF) {
        printf("✅ SUCCESS!\n");
        printf("   HIP allocated memory at GPA: 0x%llx\n", 
               (unsigned long long)gpa);
        printf("   GPU can write to it\n");
        printf("   CPU can read it\n");
        printf("\n");
        printf("💡 SOLUTION:\n");
        printf("   1. Use hipHostMalloc for shadow buffer\n");
        printf("   2. Find its GPA (0x%llx)\n", (unsigned long long)gpa);
        printf("   3. Configure PCI MMIO Bridge to use this GPA\n");
        printf("   4. GPU writes will work!\n");
    } else {
        printf("⚠️  Could not determine GPA or GPU write failed\n");
    }
    printf("=================================================\n");
    
    hipHostFree(host_ptr);
    return 0;
}

