/*
 * Check NVMe Completion Queue
 * 
 * Quick utility to inspect the CQ for completions after running
 * the GPU NVMe write test.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

struct nvme_completion {
    uint32_t result;
    uint32_t rsvd;
    uint16_t sq_head;
    uint16_t sq_id;
    uint16_t command_id;
    uint16_t status;  /* Phase bit in bit 0 */
} __attribute__((packed));

int main() {
    /* Map the CQ physical address from the test output */
    /* Update this with the actual CQ physical address from test output! */
    uint64_t cq_phys = 0x16b4d0000ULL;  /* Example from the test */
    size_t cq_size = 1024;  /* 64 entries * 16 bytes */
    
    printf("Checking NVMe Completion Queue\n");
    printf("  CQ physical: 0x%lx\n", cq_phys);
    printf("  CQ size: %zu bytes\n\n", cq_size);
    
    int fd = open("/dev/mem", O_RDONLY | O_SYNC);
    if (fd < 0) {
        perror("open /dev/mem");
        printf("\nNote: Specify CQ physical address as argument:\n");
        printf("  sudo ./check-nvme-cq 0x<cq_phys_addr>\n");
        return 1;
    }
    
    void *cq = mmap(NULL, cq_size, PROT_READ, MAP_SHARED, fd, cq_phys);
    close(fd);
    
    if (cq == MAP_FAILED) {
        perror("mmap CQ");
        return 1;
    }
    
    struct nvme_completion *entries = (struct nvme_completion *)cq;
    
    printf("First 4 CQ entries:\n");
    for (int i = 0; i < 4; i++) {
        printf("Entry %d:\n", i);
        printf("  result:     0x%08x\n", entries[i].result);
        printf("  sq_head:    %u\n", entries[i].sq_head);
        printf("  sq_id:      %u\n", entries[i].sq_id);
        printf("  command_id: %u\n", entries[i].command_id);
        printf("  status:     0x%04x (phase=%u, status=0x%x)\n", 
               entries[i].status,
               entries[i].status & 1,
               (entries[i].status >> 1) & 0x7FF);
        printf("\n");
    }
    
    munmap(cq, cq_size);
    return 0;
}

