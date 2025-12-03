#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

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

int main() {
    printf("Structure sizes:\n");
    printf("  sizeof(pci_mmio_ring_meta) = %zu (expected: 16)\n", sizeof(struct pci_mmio_ring_meta));
    printf("  sizeof(pci_mmio_command)   = %zu (expected: 24)\n", sizeof(struct pci_mmio_command));
    printf("\nField offsets in pci_mmio_command:\n");
    printf("  target_bdf = %zu\n", offsetof(struct pci_mmio_command, target_bdf));
    printf("  offset     = %zu\n", offsetof(struct pci_mmio_command, offset));
    printf("  value      = %zu (this is where 0xDEADBEEF should be)\n", offsetof(struct pci_mmio_command, value));
    printf("  command    = %zu\n", offsetof(struct pci_mmio_command, command));
    printf("  status     = %zu\n", offsetof(struct pci_mmio_command, status));
    return 0;
}
