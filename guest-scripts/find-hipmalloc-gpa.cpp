#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

uint64_t virt_to_phys(void *virt_addr) {
    uint64_t value;
    int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) {
        perror("open pagemap");
        return 0;
    }
    
    uint64_t virt = (uint64_t)virt_addr;
    uint64_t offset = (virt / PAGE_SIZE) * sizeof(uint64_t);
    
    if (lseek(pagemap_fd, offset, SEEK_SET) != (off_t)offset) {
        perror("lseek");
        close(pagemap_fd);
        return 0;
    }
    
    if (read(pagemap_fd, &value, sizeof(value)) != sizeof(value)) {
        perror("read");
        close(pagemap_fd);
        return 0;
    }
    
    close(pagemap_fd);
    
    if (!(value & (1ULL << 63))) {
        printf("  Page not present in RAM\n");
        return 0;
    }
    
    uint64_t pfn = value & ((1ULL << 55) - 1);
    uint64_t page_offset = virt & (PAGE_SIZE - 1);
    return (pfn * PAGE_SIZE) + page_offset;
}

int main() {
    printf("=================================================\n");
    printf("Find GPA of hipMallocHost allocation\n");
    printf("=================================================\n\n");
    
    void *host_ptr = NULL;
    size_t size = 8192;
    
    printf("Allocating %zu bytes with hipMallocHost...\n", size);
    hipError_t err = hipMallocHost(&host_ptr, size);
    if (err != hipSuccess) {
        printf("❌ hipMallocHost failed: %s\n", hipGetErrorString(err));
        return 1;
    }
    
    printf("  ✅ Allocated at virtual address: %p\n\n", host_ptr);
    
    // Touch the memory to ensure pages are resident
    memset(host_ptr, 0, size);
    
    printf("Finding physical addresses:\n");
    uint64_t gpa = virt_to_phys(host_ptr);
    
    if (gpa) {
        printf("  ✅ GPA of first page: 0x%lx\n", gpa);
        printf("\n");
        printf("=================================================\n");
        printf("To use this with the MMIO bridge:\n");
        printf("=================================================\n");
        printf("In QEMU launch script, change:\n");
        printf("  -device pci-mmio-bridge,shadow-gpa=0x%lx\n", gpa);
        printf("\n");
        printf("Or make shadow-gpa configurable and set it to: 0x%lx\n", gpa);
    } else {
        printf("  ❌ Failed to find GPA\n");
    }
    
    hipHostFree(host_ptr);
    return 0;
}
