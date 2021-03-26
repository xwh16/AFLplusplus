/*
   american fuzzy lop++ - afl-untracer skeleton example
   ---------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2021 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

   http://www.apache.org/licenses/LICENSE-2.0

*/

#define __USE_GNU
#define _GNU_SOURCE

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

#if defined(__linux__)
  #include <sys/personality.h>
  #include <sys/ucontext.h>
#elif defined(__APPLE__) && defined(__LP64__)
  #include <mach-o/dyld_images.h>
#elif defined(__FreeBSD__)
  #include <sys/sysctl.h>
  #include <sys/user.h>
#else
  #error "Unsupported platform"
#endif

#include "honeybee.h"

/* If you want to have debug output set this to 1, can also be set with
   AFL_DEBUG  */
u32   debug = 0;
u32   do_exit;
u32   __afl_map_size = MAP_SIZE;
u32   __afl_prev_loc;
u32   cpu;
pid_t child_pid = 65537;
u8 *  __afl_area_ptr;

/* Error reporting to forkserver controller */

void send_forkserver_error(int error) {

  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) return;

}

/* SHM setup. */

static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;
  /*
    if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {

      u32 val = atoi(ptr);
      if (val > 0) __afl_map_size = val;

    }

  */
  __afl_map_size = MAP_SIZE;
  if (__afl_map_size > MAP_SIZE) {

    if (__afl_map_size > FS_OPT_MAX_MAPSIZE) {

      fprintf(stderr,
              "Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
      if (id_str) {

        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);

      }

    } else {

      fprintf(stderr,
              "Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);

    }

  }

  if (id_str) {

#ifdef USEMMAP
    const char *   shm_file_path = id_str;
    int            shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {

      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    /* map the shared memory segment to the address space of the process */
    shm_base =
        mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    if (shm_base == MAP_FAILED) {

      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      send_forkserver_error(FS_ERROR_MMAP);
      exit(2);

    }

    __afl_area_ptr = shm_base;
#else
    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, 0, 0);

#endif

    if (__afl_area_ptr == (void *)-1) {

      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);

    }

    /* Write something into the bitmap so that the parent doesn't give up */

    __afl_area_ptr[0] = 1;

  }

}

/* Fork server logic. */
inline static void __afl_start_forkserver(void) {

  u8  tmp[4] = {0, 0, 0, 0};
  u32 status = 0;

  //  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
  //    status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  //  if (status) status |= (FS_OPT_ENABLED);
  memcpy(tmp, &status, 4);

  /* Phone home and tell the parent that we're OK. */
  if (write(FORKSRV_FD + 1, tmp, 4) != 4)
    FATAL("afl-fuzz forkserver not present");
  // fprintf(stderr, "write0 %d\n", do_exit);

}

/* the MAIN function */
int main(int argc, char *argv[]) {

  if (argc <= 1 || strcmp(argv[1], "-h") == 0) {

    FATAL(
        "Syntax: %s <target> <parameter ...>\nThe env var AFL_IPT_HIVE must "
        "point to the hive file of the target\n",
        argv[0]);

  }

#if defined(__linux__)
  (void)personality(ADDR_NO_RANDOMIZE);  // disable ASLR
#endif

  if (getenv("AFL_DEBUG")) debug = 1;
  --argc;
  ++argv;

  u32 status;
  u8 *cpuid = getenv("AFL_CPU");
  if (!cpuid) FATAL("AFL_CPU not set");
  cpu = atoi(cpuid);
  if (cpu < 0) FATAL("illegal cpu id: %d\n", cpu);
  if (debug) fprintf(stderr, "CPU: %d\n", cpu);
  u8 *hive_file = getenv("AFL_IPT_HIVE");
  if (!hive_file) { FATAL("environment AFL_IPT_HIVE not set"); }
  honeybeeInit(hive_file);

  /* by default we use stdin, but also a filename can be passed, in this
     case the input is argv[1] and we have to disable stdin */

  __afl_map_shm();
  __afl_start_forkserver();

  while (1) {

    // wait for afl-fuzz to have a testcase ready
    if (read(FORKSRV_FD, &status, 4) != 4) FATAL("afl-fuzz is gone (1)");

    // instead of fork() we could also use the snapshot lkm or do our own mini
    // snapshot feature like in https://github.com/marcinguy/fuzzer
    // -> snapshot.c
    if ((child_pid = fork()) == -1) PFATAL("fork failed");

    if (likely(child_pid)) {

      if (waitpid(child_pid, &status, WUNTRACED) < 0) exit(1);
      kill(child_pid, SIGCONT);
      honeybeeOpen();
      if (write(FORKSRV_FD + 1, &child_pid, 4) != 4)
        FATAL("afl-fuzz is gone (2)");
      kill(child_pid, SIGCONT);
      if (waitpid(child_pid, &status, 0) < 0) exit(1);
      honeybeeClose();
      honeybeeAnalyze();
      if (write(FORKSRV_FD + 1, &status, 4) != 4) FATAL("afl-fuzz is gone (3)");

    } else {

      __afl_prev_loc = 0;
      kill(getpid(), SIGSTOP);
      execv(argv[0], argv);

    }

  }

  return 0;

}

