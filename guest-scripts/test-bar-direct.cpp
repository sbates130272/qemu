#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main() {
    printf("=== Direct BAR2 Access Test ===\n\n");
    
    // BAR2 address from lspci
    uint64_t bar2_addr = 0xc810000000ULL;
    size_t size = 4096;
    
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    
    void *bar2 = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, bar2_addr);
    close(fd);
    
    if (bar2 == MAP_FAILED) {
        perror("mmap BAR2");
        return 1;
    }
    
    uint64_t *ptr = (uint64_t*)bar2;
    
    printf("Step 1: Direct write to BAR2 @ 0x%llx\n", bar2_addr);
    ptr[0] = 0xDEADBEEFCAFEBABEULL;
    printf("  Wrote: 0x%016llx\n", 0xDEADBEEFCAFEBABEULL);
    
    printf("\nStep 2: Direct read from BAR2\n");
    uint64_t value = ptr[0];
    printf("  Read:  0x%016llx\n", value);
    
    if (value == 0xDEADBEEFCAFEBABEULL) {
        printf("\n✅ BAR2 is RAM-backed and working!\n");
    } else {
        printf("\n❌ BAR2 read-back failed (got 0x%llx)\n", value);
    }
    
    munmap(bar2, size);
    return 0;
}
