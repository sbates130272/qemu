#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main() {
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    
    void *mem = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0x80000000);
    close(fd);
    
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    uint32_t *data = (uint32_t*)mem;
    
    printf("Shadow buffer at GPA 0x80000000:\n");
    printf("  producer_idx: %u (0x%08x)\n", data[0], data[0]);
    printf("  consumer_idx: %u (0x%08x)\n", data[1], data[1]);
    printf("  queue_depth:  %u (0x%08x)\n", data[2], data[2]);
    printf("  reserved:     %u (0x%08x)\n", data[3], data[3]);
    printf("\nFirst command (offset 16):\n");
    for (int i = 4; i < 16; i++) {
        printf("  [%2d] 0x%08x\n", (i-4)*4, data[i]);
    }
    
    munmap(mem, 4096);
    return 0;
}
