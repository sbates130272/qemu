# Makefile for PCI MMIO Bridge tests

HIPCC = /opt/rocm/bin/hipcc
CXX = g++
CFLAGS = -O2 -g -Wno-unused-result
DRM_CFLAGS = -I/usr/include/drm -I/usr/include/libdrm
HSA_LIBS = -lhsa-runtime64
DRM_LIBS = -ldrm -ldrm_amdgpu

all: test-gpu-mmio-bridge test-bridge-pci-testdev test-gpu-bridge-testdev test-gpu-bar0-mmio test-gpu-nvme-write nvme-create-queue check-gpu-writes find-gpu-physical-addr find-hip-allocated-gpa test-amdgpu-userptr simple-test simple-test-mem diagnose-gpu-mapping dump-shadow check-sizes test-gpu-pattern test-bar-direct

test-gpu-mmio-bridge: test-gpu-mmio-bridge.cpp
	$(HIPCC) $(CFLAGS) -o $@ $<

test-bridge-pci-testdev: test-bridge-pci-testdev.cpp
	$(CXX) $(CFLAGS) -o $@ $<

test-gpu-bridge-testdev: test-gpu-bridge-testdev.cpp
	$(HIPCC) $(CFLAGS) $(DRM_CFLAGS) $(DRM_LIBS) -o $@ $<

test-gpu-bar0-mmio: test-gpu-bar0-mmio.cpp
	$(HIPCC) $(CFLAGS) $(DRM_CFLAGS) $(DRM_LIBS) -o $@ $<

test-gpu-nvme-write: test-gpu-nvme-write.cpp
	$(HIPCC) $(CFLAGS) $(DRM_CFLAGS) $(DRM_LIBS) -o $@ $<

check-gpu-writes: check-gpu-writes.cpp
	$(HIPCC) $(CFLAGS) $(HSA_LIBS) -o $@ $<

find-gpu-physical-addr: find-gpu-physical-addr.cpp
	$(HIPCC) $(CFLAGS) -o $@ $<

find-hip-allocated-gpa: find-hip-allocated-gpa.cpp
	$(HIPCC) $(CFLAGS) -o $@ $<

test-amdgpu-userptr: test-amdgpu-userptr.cpp
	$(HIPCC) $(CFLAGS) $(DRM_CFLAGS) $(DRM_LIBS) -o $@ $<

simple-test: simple-test.cpp
	$(HIPCC) $(CFLAGS) -o $@ $<

simple-test-mem: simple-test-mem.cpp
	$(HIPCC) $(CFLAGS) -o $@ $<

diagnose-gpu-mapping: diagnose-gpu-mapping.cpp
	$(HIPCC) $(CFLAGS) $(DRM_CFLAGS) $(DRM_LIBS) -o $@ $<

dump-shadow: dump-shadow.cpp
	$(CXX) $(CFLAGS) -o $@ $<

check-sizes: check-sizes.cpp
	$(CXX) $(CFLAGS) -o $@ $<

test-gpu-pattern: test-gpu-pattern.cpp
	$(HIPCC) $(CFLAGS) $(DRM_CFLAGS) $(DRM_LIBS) -o $@ $<

test-bar-direct: test-bar-direct.cpp
	$(CXX) $(CFLAGS) -o $@ $<

nvme-create-queue: nvme-create-queue.cpp
	$(CXX) $(CFLAGS) -o $@ $<

clean:
	rm -f test-gpu-mmio-bridge test-bridge-pci-testdev test-gpu-bridge-testdev test-gpu-bar0-mmio test-gpu-nvme-write nvme-create-queue check-gpu-writes find-gpu-physical-addr find-hip-allocated-gpa test-amdgpu-userptr simple-test simple-test-mem diagnose-gpu-mapping dump-shadow check-sizes test-gpu-pattern test-bar-direct

.PHONY: all clean

