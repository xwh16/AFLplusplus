//
// Created by Allison Husain on 1/12/21.
//

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <inttypes.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "afl-fuzz.h"

#include "honeybee.h"
#include "./Honeybee/honey_analyzer/honey_analyzer.h"

typedef struct {

  ha_capture_session_t capture_session;
  ha_session_t         analysis_session;

} honeybee_tracer;

struct {

  hb_hive *global_hive;

} honeybee_global;

struct {

  const char *hive_path;
  uint64_t    range_start;
  uint64_t    range_stop;

} honeybee_config;

static honeybee_tracer *tracer;

extern u8 *  __afl_area_ptr;
extern u32   __afl_prev_loc;
extern u32   cpu;
extern u32   debug;
extern pid_t child_pid;

/* this is called once */
void honeybeeInit(u8 *hive_file) {

  honeybee_config.range_start = 0x1;
  honeybee_config.range_stop = 0x6fffffffffff;

  // Init the global hive file
  if (!honeybee_global.global_hive) {

    if (!(honeybee_global.global_hive = hb_hive_alloc(hive_file))) {

      FATAL("Unable to load hive file! %s", hive_file);

    }

  }

  // Configure global buffers
  ha_capture_session_t temp_capture_session = NULL;
  if (ha_capture_session_alloc(&temp_capture_session, 0) < 0) {

    FATAL(
        "Failed to open honeybee capture session. Is the kernel module loaded "
        "and do you have appropriate "
        "permissions to access it?");

  }

  //    //Disable tracing on this core in case we're recovering
  //    ha_capture_session_set_trace_enable(temp_capture_session, 0x00);

  // 52MB
  if (ha_capture_session_set_global_buffer_size(temp_capture_session, 400, 5) <
      0) {

    FATAL(
        "Could not set global buffer size. This is not an allocation error but "
        "the driver refused to accept the "
        "the change.\n");

  }

  ha_capture_session_free(temp_capture_session);

}

void honeybeeOpen() {

  int result;

  if (!tracer) {

    tracer = calloc(1, sizeof(honeybee_tracer));
    if (!tracer) {

      FATAL("Could not allocate honeybee internal structure (out of memory)\n");

    }

    if ((result = ha_capture_session_alloc(&tracer->capture_session, cpu)) <
        0) {

      FATAL(
          "Failed to open honeybee capture session. Is the kernel module "
          "loaded and do you have appropriate "
          "permissions to access it? Error=%d\n",
          result);

    }

    if ((result = ha_session_alloc(&tracer->analysis_session,
                                   honeybee_global.global_hive)) < 0) {

      FATAL(
          "Could not allocate analysis session. This is likely an out of "
          "memory error. Error=%d\n",
          result);

    }

  }

  ha_capture_session_range_filter filters[4];
  memset(&filters, 0, sizeof(ha_capture_session_range_filter) * 4);

  uint64_t hive_filter_start = honeybee_config.range_start;
  uint64_t hive_filter_stop = honeybee_config.range_stop;
  if (hive_filter_start < hive_filter_stop) {

    filters[0].start = hive_filter_start;
    filters[0].stop = hive_filter_stop;
    filters[0].enabled = 0x1;

  } else {

    FATAL("Hive had invalid VIP range: %p -> %p", (void *)hive_filter_start,
          (void *)hive_filter_stop);

  }

  if ((result = ha_capture_session_configure_tracing(tracer->capture_session,
                                                     child_pid, filters)) < 0) {

    FATAL("Could not configure tracing on cpu=%d, pid=%d, error=%d\n", cpu, child_pid, result);

  }

  if ((result = ha_capture_session_set_trace_enable(tracer->capture_session,
                                                    0x1, 0x1)) < 0) {

    FATAL("Could not start tracing on cpu=%d, error=%d\n", cpu, result);

  }

}

void honeybeeClose() {

  if (!tracer) { return; }

  // disable tracing. This should already be done after analysis via reap but
  // just for safety?
  ha_capture_session_set_trace_enable(tracer->capture_session, 0x0, 0x1);

  return;

}

__attribute__((hot)) static void process_block(ha_session_t session,
                                               void *context, uint64_t ip) {

  (void)session;
  (void)context;

  u32 cur_loc = (ip >> 4) ^ (ip << 8);
  cur_loc &= MAP_SIZE - 1;

  u32 prev = __afl_prev_loc;
  __afl_prev_loc = (cur_loc >> 1);

  u8 *p = &__afl_area_ptr[prev ^ cur_loc];

#if 1                                      /* enable for neverZero feature. */
  #if __GNUC__
  u8 c = __builtin_add_overflow(*p, 1, p);
  *p += c;
  #else
  *p += 1 + ((u8)(1 + *p) == 0);
  #endif
#else
  ++*p;
#endif

}

/* this is called on each iteration */
void honeybeeAnalyze() {

  if (!tracer) { return; }

  int result;

  // Suspend tracing while we analyze
  if ((result = ha_capture_session_set_trace_enable(tracer->capture_session,
                                                    0x0, 0x0)) < 0) {

    FATAL("Could not start tracing on cpu=%d, error=%d\n", cpu, result);

  }

  uint8_t *trace_buffer;
  uint64_t trace_length;
  if ((result = ha_capture_get_trace(tracer->capture_session, &trace_buffer,
                                     &trace_length)) < 0) {

    FATAL("Could not get trace buffer on cpu=%d, error=%d\n", cpu, result);

  }

  // FIXME: Do not hardcode the slide address
  if ((result = ha_session_reconfigure_with_terminated_trace_buffer(
           tracer->analysis_session, trace_buffer, trace_length,
           honeybee_config.range_start)) >= 0) {

    /* We were able to sync */
    if ((result = ha_session_decode(tracer->analysis_session, process_block,
                                    NULL)) < 0 &&
        result != -HA_PT_DECODER_END_OF_STREAM) {

      //            FILE *f = fopen("/tmp/o.pt", "w+");
      //            fwrite(trace_buffer, trace_length, 1, f);
      //            fclose(f);

      if (debug) DEBUGF("ipt decode error on cpu=%d, error=%d\n", cpu, result);

    }

    //        DEBUGF("len = %llu\n", trace_length);

  }

  // Resume tracing
  if ((result = ha_capture_session_set_trace_enable(tracer->capture_session,
                                                    0x1, 0x1)) < 0) {

    FATAL("Could not resume tracing on cpu=%d, error=%d\n", cpu, result);

  }

}

