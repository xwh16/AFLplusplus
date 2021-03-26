#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <asm/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sysctl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <ctype.h>
#include <libxdc.h>

#define rmb() __asm__ __volatile__("" ::: "memory")

#ifndef BIT
  #define BIT(nr) (1UL << (nr))
#endif

#define RTIT_CTL_DISRETC BIT(11)

#define _HF_PERF_MAP_SZ (1024 * 512)
#define _HF_PERF_AUX_SZ (1024 * 1024)

uint8_t *bitmap;
int32_t perfIntelPtPerfType = -1;
int32_t cpuIptBtsFd = -1;
void *    perfMmapBuf = NULL;
void *    perfMmapAux = NULL;
void *    pt_trace_buffer[_HF_PERF_AUX_SZ] = {0};
libxdc_t *decoder = NULL;
char *mapsFilename;

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                     int group_fd, unsigned long flags) {

  return syscall(__NR_perf_event_open, hw_event, (uintptr_t)pid, (uintptr_t)cpu,
                 (uintptr_t)group_fd, (uintptr_t)flags);

}

bool files_exists(const char *fname) {

  return (access(fname, F_OK) != -1);

}

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
 
void hexdump(void *mem, unsigned int len){
  unsigned int i, j;
  for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++){
    /* print offset */
    if(i % HEXDUMP_COLS == 0){
      printf("0x%06x: ", i);
    }

    /* print hex data */
    if(i < len){
      printf("%02x ", 0xFF & ((char*)mem)[i]);
    }
    else {
      printf("   ");
    }
    /* print ASCII dump */
    if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)){
      for(j = i - (HEXDUMP_COLS - 1); j <= i; j++){
        if(j >= len){
          putchar(' ');
        } 
        else if(isprint(((char*)mem)[j])){
          putchar(0xFF & ((char*)mem)[j]);        
        }
        else {
          putchar('.');
        }
      }
      putchar('\n');
    }
  }
}


ssize_t files_readFromFd(int fd, uint8_t *buf, size_t fileSz) {

  size_t readSz = 0;
  while (readSz < fileSz) {

    ssize_t sz = read(fd, &buf[readSz], fileSz - readSz);
    if (sz == 0) { break; }
    if (sz < 0) { return -1; }
    readSz += sz;

  }

  return (ssize_t)readSz;

}

ssize_t files_readFileToBufMax(const char *fname, uint8_t *buf,
                               size_t fileMaxSz) {

  int fd = open(fname, O_RDONLY | O_CLOEXEC);
  if (fd == -1) {

    fprintf(stderr, "Couldn't open '%s' for R/O\n", fname);
    return -1;

  }

  ssize_t readSz = files_readFromFd(fd, buf, fileMaxSz);
  if (readSz < 0) {

    fprintf(stderr, "Couldn't read '%s' to a buf\n", fname);
    return -1;

  }

  close(fd);

  return readSz;

}

int local_init() {

  char const intel_pt_path[] = "/sys/bus/event_source/devices/intel_pt/type";

  if (files_exists(intel_pt_path)) {

    uint8_t buf[256];
    ssize_t sz = files_readFileToBufMax(intel_pt_path, buf, sizeof(buf) - 1);
    if (sz > 0) {

      buf[sz] = '\0';
      perfIntelPtPerfType = (int32_t)strtoul((char *)buf, NULL, 10);
       printf("perfIntelPtPerfType = %" PRIu32 "\n", perfIntelPtPerfType);
      return 0;

    }

  }

  return -1;

}

bool arch_perfCreate(pid_t pid, int *perfFd) {

   printf("Enabling PERF for pid=%d\n", pid);

/*
  if (*perfFd != -1) {

    fprintf(stderr,
            "The PERF FD is already initialized, possibly conflicting perf "
            "types enabled\n");
    return -1;

  }
*/

  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(struct perf_event_attr));
  pe.size = sizeof(struct perf_event_attr);
  pe.exclude_kernel = 1;
  pe.disabled = 1;
  pe.enable_on_exec = 1;
  pe.exclude_hv = 1;
  pe.type = PERF_TYPE_HARDWARE;

  pe.type = perfIntelPtPerfType;
  pe.config = RTIT_CTL_DISRETC;

#if !defined(PERF_FLAG_FD_CLOEXEC)
  #define PERF_FLAG_FD_CLOEXEC 0
#endif
  *perfFd = perf_event_open(&pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
  if (*perfFd == -1) {

    fprintf(stderr, "perf_event_open() failed\n");
    return false;

  }

#if defined(PERF_ATTR_SIZE_VER5)
  if ((perfMmapBuf = mmap(NULL, _HF_PERF_MAP_SZ + getpagesize(),
                          PROT_READ | PROT_WRITE, MAP_SHARED, *perfFd, 0)) ==
      MAP_FAILED) {

    perfMmapBuf = NULL;
    fprintf(stderr, "mmap(mmapBuf) failed, sz=%zu, try increasing the kernel.perf_event_mlock_kb sysctl (up to even 300000000)\n",
        (size_t)_HF_PERF_MAP_SZ + getpagesize());
    close(*perfFd);
    //*perfFd = -1;
    return false;

  }

  struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmapBuf;
  pem->aux_offset = pem->data_offset + pem->data_size;
  pem->aux_size = _HF_PERF_AUX_SZ;
  if ((perfMmapAux = mmap(NULL, pem->aux_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, *perfFd, pem->aux_offset)) ==
      MAP_FAILED) {

    munmap(perfMmapBuf, _HF_PERF_MAP_SZ + getpagesize());
    perfMmapBuf = NULL;
    perfMmapAux = NULL;
     fprintf(stderr, 
        "mmap(mmapAuxBuf) failed, try increasing the kernel.perf_event_mlock_kb sysctl (up to " "even 300000000)\n");
    close(*perfFd);
    //*perfFd = -1;
    return false;

  }

  return true;

#else                                       /* defined(PERF_ATTR_SIZE_VER5) */
  fprintf(stderr,
          "Your <linux/perf_event.h> includes are too old to support Intel "
          "PT/BTS\n");
  return false;
#endif                                      /* defined(PERF_ATTR_SIZE_VER5) */

}

void arch_ptAnalyze() {

  struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmapBuf;

  /* smp_rmb() required as per /usr/include/linux/perf_event.h */
  rmb();

  void *trace_buffer_start = perfMmapAux + pem->aux_tail;

   hexdump(trace_buffer_start, pem->aux_head-pem->aux_tail);

  /* zero copy does not work with perf */
  memcpy(pt_trace_buffer, trace_buffer_start, pem->aux_head - pem->aux_tail);
fprintf(stderr, "head: %llu   tail: %llu  = [%llu]=%02x\n", pem->aux_head, pem->aux_tail,pem->aux_head - pem->aux_tail, ((uint8_t *)pt_trace_buffer)[pem->aux_head - pem->aux_tail]);
  ((uint8_t *)pt_trace_buffer)[pem->aux_head - pem->aux_tail] = 0x55;

  decoder_result_t ret = libxdc_decode(decoder, (uint8_t *)pt_trace_buffer,
                                       pem->aux_head - pem->aux_tail);
  /**/
fprintf(stderr, "ret: %d\n", ret);
        switch(ret){
                case decoder_success:
                        fprintf(stderr, "[*] decoder returned: decoder_success\n");
                        break;
                case decoder_success_pt_overflow:
                        fprintf(stderr, "[*] decoder returned: decoder_success_pt_overflow\n");
                        break;
                case decoder_page_fault:
                        fprintf(stderr, "[*] decoder returned: decoder_page_fault\n");
                        break;
                case decoder_error:
                        fprintf(stderr, "[*] decoder returned: decoder_error\n");
                        break;
                case decoder_unkown_packet:
                        fprintf(stderr, "[*] decoder returned: decoder_unkown_packet\n");
                        break;
        }


  if (ret == decoder_success) {

      uint32_t i;
      fprintf(stderr, "Coverage map:\n");
      for (i = 0; i < 65536; ++i)
        if (bitmap[i]) fprintf(stderr, "%05u: %u\n", i, bitmap[i]);

  }
  /**/

}

void arch_perfMmapParse() {

#if defined(PERF_ATTR_SIZE_VER5)
  struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmapBuf;
  if (pem->aux_head == pem->aux_tail) { return; }
  if (pem->aux_head < pem->aux_tail) {

    fprintf(stderr,
            "The PERF AUX data has been overwritten. The AUX buffer is too "
            "small\n");
    return;

  }

  arch_ptAnalyze();
#endif                                      /* defined(PERF_ATTR_SIZE_VER5) */

}

void arch_perfAnalyze(int *perfFd) {

//  if (*perfFd != -1) {

    ioctl(*perfFd, PERF_EVENT_IOC_DISABLE, 0);
    arch_perfMmapParse();
    ioctl(*perfFd, PERF_EVENT_IOC_RESET, 0);

//  }

}

void arch_perfClose(int *perfFd) {

  if (perfMmapAux != NULL) {

    munmap(perfMmapAux, _HF_PERF_AUX_SZ);
    perfMmapAux = NULL;

  }

  if (perfMmapBuf != NULL) {

    munmap(perfMmapBuf, _HF_PERF_MAP_SZ + getpagesize());
    perfMmapBuf = NULL;

  }

  close(*perfFd);
  //*perfFd = -1;

}

typedef struct page_cache_s {

  void *page_buffer;
  int   fd;

} page_cache_t;

page_cache_t *page_cache_init() {

  page_cache_t *ret = malloc(sizeof(page_cache_t));
  ret->page_buffer = malloc(0x1000);

  asprintf(&mapsFilename, "/proc/%d/mem", getpid());
  int fd = open(mapsFilename, O_RDONLY);
  if (fd == -1) {

    fprintf(stderr, "proc_mem_fd: %d (%s) failed\n", fd, mapsFilename);
    return (void *)-1;

  }

  ret->fd = fd;
  return ret;

}

void *page_cache_fetch(void *self_ptr, uint64_t page, bool *success) {

  page_cache_t *self = (page_cache_t *)self_ptr;

  int ret = lseek(self->fd, (page & 0xFFFFFFFFFFFFF000ULL), SEEK_SET);
  ret = read(self->fd, self->page_buffer, 0x1000);
  if (ret != 0) {

    *success = true;
    return self->page_buffer;

  }

  fprintf(stderr, "%s: FAIL %lx\n", __func__, page);
  *success = false;
  return 0;

}

int perf_init_once(uint8_t *map, uint32_t map_size) {

  uint64_t filter[4][2] = {0};

  bitmap = map;
  filter[0][0] = 0x1000;
  filter[0][1] = 0x7FFFFFFFFFFF;
  page_cache_t *page_cache = page_cache_init();

  if (page_cache == (void *)-1) {

    fprintf(stderr, "page_cache alloc failed\n");
    return -1;

  }

  if (!(decoder = libxdc_init(filter, &page_cache_fetch, (void *)page_cache,
                              (void *)map, map_size))) {

    return -1;

  }
  
  if (local_init()) { return -1; }

  return 0;

}

int perf_init(pid_t pid) {

  if (arch_perfCreate(pid, &cpuIptBtsFd) == true) {

    return 0;

  } else {

    return 1;

  }

}

int perf_start() {

  return ioctl(cpuIptBtsFd, PERF_EVENT_IOC_ENABLE, 0);

}

void perf_analyze_and_close() {

  arch_perfAnalyze(&cpuIptBtsFd);
  arch_perfClose(&cpuIptBtsFd);

}

