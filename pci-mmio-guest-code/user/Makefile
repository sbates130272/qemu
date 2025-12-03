# Makefile for PCI MMIO Bridge tests

HIPCC = /opt/rocm/bin/hipcc
CXX = g++
CFLAGS = -O2 -g -Wno-unused-result
DRM_CFLAGS = -I/usr/include/drm -I/usr/include/libdrm
HSA_LIBS = -lhsa-runtime64
DRM_LIBS = -ldrm -ldrm_amdgpu

all: test-gpu-nvme-write

test-gpu-nvme-write: test-gpu-nvme-write.cpp
	$(HIPCC) $(CFLAGS) $(DRM_CFLAGS) $(DRM_LIBS) $(HSA_LIBS) -o $@ $<

clean:
	rm -f test-gpu-nvme-write

.PHONY: all clean

