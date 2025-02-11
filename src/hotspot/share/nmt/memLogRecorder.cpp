/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

// record pattern of allocations of memory calls:
//
// NMTRecordMemoryAllocations=0x7FFFFFFF ./build/macosx-aarch64-server-release/xcode/build/jdk/bin/java -XX:+UnlockDiagnosticVMOptions -XX:NativeMemoryTracking=summary -jar build/macosx-aarch64-server-release/images/jdk/demo/jfc/J2Ddemo/J2Ddemo.jar
//
// OR record pattern of allocations of virtual memory calls:
//
// NMTRecordVirtualMemoryAllocations=0x7FFFFFFF ./build/macosx-aarch64-server-release/xcode/build/jdk/bin/java -XX:+UnlockDiagnosticVMOptions -XX:NativeMemoryTracking=summary -jar build/macosx-aarch64-server-release/images/jdk/demo/jfc/J2Ddemo/J2Ddemo.jar
//
// this will produce 3 files:
//
// #1 hs_nmt_pid22770_allocs_record.log (is the chronological record of the the desired operations)
// OR
// #1 hs_nmt_pid22918_virtual_allocs_record.log (is the chronological record of the desired operations)
// #2 hs_nmt_pid22770_info_record.log (is the record of default NMT memory overhead and the NMT state)
// #3 hs_nmt_pid22770_threads_record.log (is the record of thread names that can be retrieved later when processing)
//
// then to actually run the benchmark:
//
// NMTBenchmarkRecordedPID=22770 ./build/macosx-aarch64-server-release/xcode/build/jdk/bin/java -XX:+UnlockDiagnosticVMOptions -XX:NativeMemoryTracking=summary

#include "precompiled.hpp"
#include "jvm.h"
#include "nmt/nmtCommon.hpp"
#include "nmt/mallocHeader.hpp"
#include "nmt/mallocHeader.inline.hpp"
#include "nmt/memLogRecorder.hpp"
#include "nmt/memReporter.hpp"
#include "nmt/memTracker.hpp"
#include "nmt/memTracker.hpp"
#include "runtime/arguments.hpp"
#include "runtime/globals.hpp"
#include "runtime/os.hpp"
#include "runtime/thread.hpp"
#include "utilities/debug.hpp"
#include "utilities/nativeCallStack.hpp"
#include "utilities/permitForbiddenFunctions.hpp"
#include "utilities/vmError.hpp"

#include <locale.h>
#if defined(LINUX)
#include <malloc.h>
#elif defined(__APPLE__)
#include <malloc/malloc.h>
#endif

#if defined(LINUX) || defined(__APPLE__)
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#endif

#if defined(LINUX)
#define MAXTHREADNAMESIZE 256
#endif

NMT_MemoryLogRecorder NMT_MemoryLogRecorder::_recorder;
NMT_VirtualMemoryLogRecorder NMT_VirtualMemoryLogRecorder::_recorder;

void NMT_LogRecorder::initialize() {
  char* NMTRecordMemoryAllocations = getenv("NMTRecordMemoryAllocations");
  if (NMTRecordMemoryAllocations != nullptr) {
    long count = atol(NMTRecordMemoryAllocations);
    if (count == 0) {
      count = strtol(NMTRecordMemoryAllocations, NULL, 16);
    }
    NMT_MemoryLogRecorder::initialize(count);
  }
  char* NMTRecordVirtualMemoryAllocations = getenv("NMTRecordVirtualMemoryAllocations");
  if (NMTRecordVirtualMemoryAllocations != nullptr) {
    long count = atol(NMTRecordVirtualMemoryAllocations);
    if (count == 0) {
      count = strtol(NMTRecordVirtualMemoryAllocations, NULL, 16);
    }
    NMT_VirtualMemoryLogRecorder::initialize(count);
  }
}

void NMT_LogRecorder::finish() {
  if (!NMT_MemoryLogRecorder::instance()->done()) {
    NMT_MemoryLogRecorder::instance()->finish();
  }
  if (!NMT_VirtualMemoryLogRecorder::instance()->done()) {
    NMT_VirtualMemoryLogRecorder::instance()->finish();
  }
}

void NMT_LogRecorder::replay() {
  char* NMTBenchmarkRecordedPID = getenv("NMTBenchmarkRecordedPID");
  if (NMTBenchmarkRecordedPID != nullptr) {
    int pid = atoi(NMTBenchmarkRecordedPID);
    NMT_MemoryLogRecorder::instance()->replay(pid);
    NMT_VirtualMemoryLogRecorder::instance()->replay(pid);
  }
}

void NMT_LogRecorder::init() {
#if defined(LINUX) || defined(__APPLE__)
  pthread_mutex_t _mutex;
#elif defined(WINDOWS)
 // ???
#endif
  pthread_mutex_init(&_mutex, NULL);
  _threads_names_counter = 1;
  _threads_names = (thread_name_info*)permit_forbidden_function::calloc(_threads_names_counter, sizeof(thread_name_info));
  _done = true;
  _count = 0;
}

bool NMT_LogRecorder::lockIfNotDone() {
  if (!_done) {
    lock();
    return true;
  } else {
    return false;
  }
}

void NMT_LogRecorder::lock() {
#if defined(LINUX) || defined(__APPLE__)
  pthread_mutex_lock(&_mutex);
#elif defined(WINDOWS)
 // ???
#endif
}

void NMT_LogRecorder::unlock() {
#if defined(LINUX) || defined(__APPLE__)
  pthread_mutex_unlock(&_mutex);
#elif defined(WINDOWS)
 // ???
#endif
}

intx NMT_LogRecorder::thread_id() {
#if defined(LINUX) || defined(__APPLE__)
  return (intx)pthread_self();
#elif defined(WINDOWS)
  // TODO
  return 0;
#endif
}

void NMT_LogRecorder::thread_name(char* buf) {
#if defined(__APPLE__)
  if (pthread_main_np()) {
    strcpy(buf, "main");
  } else {
    pthread_getname_np(pthread_self(), buf, MAXTHREADNAMESIZE);
  }
#elif defined(LINUX)
  pthread_getname_np(pthread_self(), buf, MAXTHREADNAMESIZE);
#elif defined(WINDOWS)
  // TODO
#endif
}

void NMT_LogRecorder::logThreadName() {
  for (size_t i = 0; i < _threads_names_counter; i++) {
    if (_threads_names[i].thread == thread_id()) {
      return;
    }
  }
  static char name[MAXTHREADNAMESIZE];
  thread_name(name);
  if (strlen(name) > 0) {
    _threads_names_counter++;
    _threads_names = (thread_name_info*)permit_forbidden_function::realloc((void*)_threads_names, (_threads_names_counter+1)*sizeof(thread_name_info));
    _threads_names[_threads_names_counter-1].thread = thread_id();
    strncpy((char*)_threads_names[_threads_names_counter-1].name, name, MAXTHREADNAMESIZE-1);
  }
}

size_t NMT_LogRecorder::mallocSize(void* ptr)
{
#if defined(LINUX)
  return permit_forbidden_function::malloc_usable_size(ptr);
#elif defined(WINDOWS)
  return permit_forbidden_function::_msize(ptr);)
#elif defined(__APPLE__)
  return permit_forbidden_function::malloc_size(ptr);
#endif
}

#define IS_FREE(e)           ((e->requested == 0) && (e->old == nullptr))
#define IS_REALLOC(e)        ((e->requested  > 0) && (e->old != nullptr))
#define IS_MALLOC(e)         ((e->requested  > 0) && (e->old == nullptr))

#define ALLOCS_LOG_FILE "hs_nmt_pid%p_allocs_record.log"
#define THREADS_LOG_FILE "hs_nmt_pid%p_threads_record.log"
#define INFO_LOG_FILE "hs_nmt_pid%p_info_record.log"
#define BENCHMARK_LOG_FILE "hs_nmt_pid%p_benchmark.log"
#define VALLOCS_LOG_FILE "hs_nmt_pid%p_virtual_allocs_record.log"

static int _prepare_log_file(const char* pattern, const char* default_pattern) {
  int fd = -1;
  if (ErrorFileToStdout) {
    fd = STDOUT_FILENO;
  } else if (ErrorFileToStderr) {
    fd = STDERR_FILENO;
  } else {
    static char name_buffer[O_BUFLEN];
    fd = VMError::prepare_log_file(pattern, default_pattern, true, name_buffer, sizeof(name_buffer));
    if (fd == -1) {
      int e = errno;
      tty->print("Can't open memory [%s]. Error: ", pattern?pattern:"null");
      tty->print_raw_cr(os::strerror(e));
      tty->print_cr("NMT memory recorder report will be written to console.");
      // See notes in VMError::report_and_die about hard coding tty to 1
      fd = 1;
    }
  }
  return fd;
}

#define IS_VALID_FD(fd) (fd > STDERR_FILENO)

static void _write_and_check(int fd, const void *buf, size_t count) {
  if (!IS_VALID_FD(fd)) {
    fprintf(stderr, "write_and_check(%d) ERROR\n", fd);
    //assert(false, "fd: %d", fd);
  }
  errno = 0;
  ssize_t written = ::write(fd, buf, count);
  if ((long)written != (long)count) {
    int e = errno;
    fprintf(stderr, "write_and_check(%d) ERROR:[%s]\n", fd, os::strerror(e));
    //assert((long)written != (long)count, "written != count [%ld,%ld]", (long)written, (long)count);
  }
}

static int _close_and_check(int fd) {
  if (!IS_VALID_FD(fd)) {
    fprintf(stderr, "close_and_check(%d) ERROR\n", fd);
    return fd;
  }
  if (fd > STDERR_FILENO) {
    errno = 0;
    int status = close(fd);
    if (status != 0) {
      int e = errno;
      fprintf(stderr, "ERROR:[%s]\n", os::strerror(e));
      assert(status != 0, "close(%d) returned %d", fd, status);
      return fd;
    } else {
      return -1;
    }
  } else {
    return fd;
  }
}

static bool _create_file_path_with_pid(const char *path, const char *file, char* file_path, int pid) {
  char *tmp_path = NEW_C_HEAP_ARRAY(char, JVM_MAXPATHLEN, mtNMT);
  strcpy(tmp_path, path);
  strcat(tmp_path, os::file_separator());
  strcat(tmp_path, file);
  if (!Arguments::copy_expand_pid(tmp_path, strlen(tmp_path), file_path, JVM_MAXPATHLEN, pid)) {
    FREE_C_HEAP_ARRAY(char, tmp_path);
    return false;
  } else {
    FREE_C_HEAP_ARRAY(char, tmp_path);
    return true;
  }
}

typedef struct file_info {
  void*   ptr;
  size_t  size;
  int     fd;
} file_info;

static file_info _open_file_and_read(const char* pattern, const char* path, int pid) {
  file_info info = { nullptr, 0, -1 };

  char *file_path = NEW_C_HEAP_ARRAY(char, JVM_MAXPATHLEN, mtNMT);
  if (!_create_file_path_with_pid(path, pattern, file_path, pid)) {
    tty->print("Can't construct path [%s:%s:%d].", pattern, path, pid);
    return info;
  }

  info.fd = os::open(file_path, O_RDONLY, 0);
  if (info.fd == -1) {
    int e = errno;
    tty->print("Can't open file [%s].", file_path);
    tty->print_raw_cr(os::strerror(e));
    return info;
  }

  struct stat file_info;
  ::fstat(info.fd, &file_info);
  info.size = file_info.st_size;
  ::lseek(info.fd, 0, SEEK_SET);

  info.ptr = ::mmap(NULL, info.size, PROT_READ, MAP_PRIVATE, info.fd, 0);
  assert(info.ptr != MAP_FAILED, "info.ptr != MAP_FAILED");

  FREE_C_HEAP_ARRAY(char, file_path);

  return info;
}

void NMT_MemoryLogRecorder::initialize(intx limit) {
  //fprintf(stderr, "> NMT_MemoryLogRecorder::initialize(%ld, %zu)\n", limit, sizeof(Entry));
  NMT_MemoryLogRecorder *recorder = NMT_MemoryLogRecorder::instance();
  recorder->init();
  recorder->lock();
  {
    recorder->_limit = limit;
    if (recorder->_limit > 0) {
      recorder->_log_fd = _prepare_log_file(nullptr, ALLOCS_LOG_FILE);
      //fprintf(stderr, ">> _memLogRecorder._log_fd:%d\n", recorder->_log_fd);
      recorder->_done = false;
    } else {
      recorder->_done = true;
    }
  }
  recorder->unlock();
}

void NMT_MemoryLogRecorder::finish(void) {
  NMT_MemoryLogRecorder *recorder = NMT_MemoryLogRecorder::instance();
  //fprintf(stderr, "NMT_MemoryLogRecorder::finish() %p\n", NMT_MemoryLogRecorder::instance());
  if (recorder->lockIfNotDone()) {
    volatile int log_fd = recorder->_log_fd;
    recorder->_log_fd = -1;
    //fprintf(stderr, " log_fd:%d\n", log_fd);
    log_fd = _close_and_check(log_fd);
    //fprintf(stderr, " log_fd:%d\n", log_fd);

    int threads_fd = _prepare_log_file(nullptr, THREADS_LOG_FILE);
    //fprintf(stderr, " threads_fd:%d\n", threads_fd);
    if (threads_fd != -1) {
      _write_and_check(threads_fd, recorder->_threads_names, recorder->_threads_names_counter*sizeof(thread_name_info));
      threads_fd = _close_and_check(threads_fd);
      //fprintf(stderr, " threads_fd:%d\n", threads_fd);
    }

    int info_fd = _prepare_log_file(nullptr, INFO_LOG_FILE);
    //fprintf(stderr, " info_fd:%d\n", info_fd);
    if (info_fd != -1) {
      size_t level = NMTUtil::parse_tracking_level(NativeMemoryTracking);
      _write_and_check(info_fd, &level, sizeof(level));
      size_t overhead = MemTracker::overhead_per_malloc();
      _write_and_check(info_fd, &overhead, sizeof(overhead));
      info_fd = _close_and_check(info_fd);
      //fprintf(stderr, " info_fd:%d\n", info_fd);
    }

    recorder->_done = true;
    recorder->unlock();
  }
}

jlong histogramLimits[] = {32, 64, 128, 256, 512, 1024, 4096, 8192, 16896};
//jlong histogramLimits[] = {16, 32, 48, 64, 80, 96, 112, 128, 256, 512, 1024, 4096, 8192, 16896, 65536};
const jlong histogramLimitsSize = sizeof(histogramLimits)/sizeof(jlong);
const char *histogramChars[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
typedef struct HistogramBuckets {
  jlong buckets[histogramLimitsSize+1];
} HistogramBuckets;

void NMT_MemoryLogRecorder::replay(const int pid) {
  //fprintf(stderr, "NMT_MemoryLogRecorder::replay(\"%s\", %d)\n", path, pid);
  static const char *path = ".";
  setlocale(LC_NUMERIC, "");
  NMT_MemoryLogRecorder *recorder = NMT_MemoryLogRecorder::instance();
  recorder->lock();

  // compare the recorded and current levels of NMT and exit if different
  file_info log_fi = _open_file_and_read(INFO_LOG_FILE, path, pid);
  if (log_fi.fd == -1) {
    return;
  }
  size_t* status_file_bytes = (size_t*)log_fi.ptr;
  NMT_TrackingLevel recorded_nmt_level = (NMT_TrackingLevel)status_file_bytes[0];
  if (NMTUtil::parse_tracking_level(NativeMemoryTracking) != recorded_nmt_level) {
    tty->print("NativeMemoryTracking mismatch [%u != %u].\n", recorded_nmt_level, NMTUtil::parse_tracking_level(NativeMemoryTracking));
    tty->print("Re-run with \"-XX:NativeMemoryTracking=%s\"\n", NMTUtil::tracking_level_to_string(recorded_nmt_level));
    os::exit(-1);
  }

  // open records file for reading the memory allocations to "play back"
  file_info records_fi = _open_file_and_read(ALLOCS_LOG_FILE, path, pid);
  if (records_fi.fd == -1) {
    return;
  }
  Entry* records_file_entries = (Entry*)records_fi.ptr;
  long int count = (records_fi.size / sizeof(Entry));
  size_t size_pointers = count * sizeof(address);
  address *pointers = (address*)::mmap(NULL, size_pointers, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_NORESERVE|MAP_ANONYMOUS, -1, 0);
  assert(pointers != MAP_FAILED, "pointers != MAP_FAILED");

  // open benchmark file for writing the final results
  char *benchmark_file_path = NEW_C_HEAP_ARRAY(char, JVM_MAXPATHLEN, mtNMT);
  if (!_create_file_path_with_pid(path, BENCHMARK_LOG_FILE, benchmark_file_path, pid)) {
    tty->print("Can't construct benchmark_file_path [%s].", benchmark_file_path);
    os::exit(-1);
  }
  int benchmark_fd = _prepare_log_file(benchmark_file_path, nullptr);
  if (benchmark_fd == -1) {
    tty->print("Can't open [%s].", benchmark_file_path);
    os::exit(-1);
  }
  jlong requestedByCategory[mt_number_of_tags] = {0};
  jlong allocatedByCategory[mt_number_of_tags] = {0};
  jlong nmtObjectsByCategory[mt_number_of_tags] = {0};
  jlong timeByCategory[mt_number_of_tags] = {0};
  HistogramBuckets histogramByCategory[mt_number_of_tags] = {0};
  
  jlong nanoseconds = 0;
  jlong requestedTotal = 0;
  jlong actualTotal = 0;
  for (off_t i = 0; i < count; i++) {
    Entry *e = &records_file_entries[i];
    MemTag mem_tag = NMTUtil::index_to_tag((int)e->mem_tag);
    int frameCount;
    for (frameCount = 0; frameCount < NMT_TrackingStackDepth; frameCount++) {
      if (e->stack[frameCount] == 0) {
        break;
      }
    }
    NativeCallStack stack = NativeCallStack::empty_stack();
    if (frameCount > 0) {
      stack = NativeCallStack(e->stack, frameCount);
    }
    jlong requested = 0;
    jlong actual = 0;
    pointers[i] = nullptr;
    jlong start = 0;
    jlong end = 0;
    {
      if (IS_MALLOC(e)) {
        address client_ptr = nullptr;
        start = os::javaTimeNanos();
        {
          client_ptr = (address)os::malloc(e->requested, mem_tag, stack);
        }
        end = os::javaTimeNanos();
        requested = e->requested;
        actual = e->actual;
        pointers[i] = client_ptr;
        if (mem_tag == mtNone) {
          fprintf(stderr, "MALLOC?\n");
        }
      } else if (IS_REALLOC(e)) {
        // the recorded "realloc" was captured in a different process,
        // so find the corresponding "malloc" or "realloc" in this process
        for (off_t j = i-1; j >= 0; j--) {
          Entry *p = &records_file_entries[j];
          if (e->old == p->ptr) {
            address ptr = pointers[j];
            requested -= p->requested;
            actual -= p->actual;
            start = os::javaTimeNanos();
            {
              ptr = (address)os::realloc(ptr, e->requested, mem_tag, stack);
            }
            end = os::javaTimeNanos();
            requested += e->requested;
            actual += e->actual;
            pointers[i] = ptr;
            pointers[j] = nullptr;
            break;
          }
          if (mem_tag == mtNone) {
            fprintf(stderr, "REALLOC?\n");
          }
        }
      } else if (IS_FREE(e)) {
        // the recorded "free" was captured in a different process,
        // so find the corresponding "malloc" or "realloc" in this process
        for (off_t j = i-1; j >= 0; j--) {
          Entry *p = &records_file_entries[j];
          if ((e->old == p->ptr) || (e->ptr == p->ptr)) {
            mem_tag = NMTUtil::index_to_tag((int)p->mem_tag);
            void* ptr = pointers[j];
            requested -= p->requested;
            actual -= p->actual;
            start = os::javaTimeNanos();
            {
              os::free(ptr);
            }
            end = os::javaTimeNanos();
            pointers[i] = nullptr;
            pointers[j] = nullptr;
            break;
          }
        }
        if (mem_tag == mtNone) {
          fprintf(stderr, "FREE?\n");
        }
      } else {
        fprintf(stderr, "HUH?\n");
        os::exit(-1);
      }
      requestedTotal += requested;
      actualTotal += actual;
      
      requestedByCategory[NMTUtil::tag_to_index(mem_tag)] += requested;
      allocatedByCategory[NMTUtil::tag_to_index(mem_tag)] += actual;
      if (IS_FREE(e)) {
        nmtObjectsByCategory[NMTUtil::tag_to_index(mem_tag)]--;
      } else {
        nmtObjectsByCategory[NMTUtil::tag_to_index(mem_tag)]++;
      }
    }
    jlong duration = (start > 0) ? (end - start) : 0;
    timeByCategory[NMTUtil::tag_to_index(mem_tag)] += duration;
    nanoseconds += duration;

    _write_and_check(benchmark_fd, &duration, sizeof(duration));
    _write_and_check(benchmark_fd, &requested, sizeof(requested));
    _write_and_check(benchmark_fd, &actual, sizeof(actual));
    char type = (IS_MALLOC(e) * 1) | (IS_REALLOC(e) * 2) | (IS_FREE(e) * 4);
    _write_and_check(benchmark_fd, &type, sizeof(type));
    //fprintf(stderr, " %9ld:%9ld:%9ld %d:%d:%d\n", requested, actual, duration, IS_MALLOC(e), IS_REALLOC(e), IS_FREE(e));

    HistogramBuckets* histogram = &histogramByCategory[NMTUtil::tag_to_index(mem_tag)];
    for (int s = histogramLimitsSize; s >= 0; s--) {
      if (actual >= histogramLimits[s]) {
        histogram->buckets[s]++;
        break;
      }
    }
  }

  setlocale(LC_ALL, "");
  size_t overhead_NMT = count * MemTracker::overhead_per_malloc();
  jlong overhead_malloc = actualTotal - requestedTotal - overhead_NMT;
  double overheadPercentage_malloc = 100.0 * (double)overhead_malloc / (double)requestedTotal;
  fprintf(stderr, "\n\n\nmalloc summary:\n\n");
  fprintf(stderr, "time:%'ld[ns] [samples:%'ld]\n", nanoseconds, count);
  fprintf(stderr, "memory requested:%'zu bytes, allocated:%'zu bytes, \n", requestedTotal, actualTotal);
  double overheadPercentage_NMT = 100.0 * (double)overhead_NMT / (double)requestedTotal;
  fprintf(stderr, "malloc overhead=%'zu bytes [%2.2f%%], NMT headers overhead=%'zu bytes [%2.2f%%]\n", overhead_malloc, overheadPercentage_malloc, overhead_NMT, overheadPercentage_NMT);
  fprintf(stderr, "\n");

  fprintf(stderr, "%22s: %12s: %12s: %12s: %12s: %12s: %12s: %12s:\n", "NMT type", "objects", "bytes", "time", "count%", "bytes%", "time%", "overhead%");
  fprintf(stderr, "-------------------------------------------------------------------------------------------------------------------------\n");
  for (int i = 0; i < mt_number_of_tags; i++) {
    double overhead = 0.0;
    if (requestedByCategory[i] > 0) {
      overhead = 100.0 * ((double)allocatedByCategory[i] - (double)requestedByCategory[i]) / (double)requestedByCategory[i];
    }
    fprintf(stderr, "%22s: %'12ld  %'12ld   %'12ld", NMTUtil::tag_to_name(NMTUtil::index_to_tag(i)), nmtObjectsByCategory[i], allocatedByCategory[i], timeByCategory[i]);
    double countPercentage = 100.0 * ((double)nmtObjectsByCategory[i] / (double)count);
    if (countPercentage > 10.0) {
      fprintf(stderr, "        %.1f%%", countPercentage);
    } else {
      fprintf(stderr, "         %.1f%%", countPercentage);
    }
    double bytesPercentage = 100.0 * ((double)allocatedByCategory[i] / (double)actualTotal);
    if (bytesPercentage > 10.0) {
      fprintf(stderr, "         %.1f%%", bytesPercentage);
    } else {
      fprintf(stderr, "          %.1f%%", bytesPercentage);
    }
    double timePercentage = 100.0 * ((double)timeByCategory[i] / (double)nanoseconds);
    if (timePercentage > 10.0) {
      fprintf(stderr, "         %.1f%%", timePercentage);
    } else {
      fprintf(stderr, "          %.1f%%", timePercentage);
    }
    if (overhead > 100.0) {
      fprintf(stderr, "        %.1f%%", overhead);
    } else if (overhead > 10.0) {
      fprintf(stderr, "         %.1f%%", overhead);
    } else {
      fprintf(stderr, "          %.1f%%", overhead);
    }
    fprintf(stderr, "    ");
    
    HistogramBuckets* histogram = &histogramByCategory[i];
    jlong max = 0;
    for (int s = histogramLimitsSize; s >= 0; s--) {
      if (histogram->buckets[s] > max) {
        max = histogram->buckets[s];
      }
    }
    for (int s = 0; s < histogramLimitsSize; s++) {
      int index = (int)(100.0 * ((double)histogram->buckets[s] / (double)max)) % 8;
      fprintf(stderr, "%s", histogramChars[index]);
    }
    fprintf(stderr, "\n");
  }

  _close_and_check(log_fi.fd);
  _close_and_check(records_fi.fd);
  _close_and_check(benchmark_fd);
  FREE_C_HEAP_ARRAY(char, benchmark_file_path);

  for (off_t i = 0; i < count; i++) {
    if (pointers[i] != nullptr) {
      os::free(pointers[i]);
      pointers[i] = nullptr;
    }
  }
  munmap((void*)pointers, size_pointers);

  recorder->unlock();

  os::exit(0);
}

void NMT_MemoryLogRecorder::_log(MemTag mem_tag, size_t requested, address ptr, address old, const NativeCallStack *stack){
  NMT_MemoryLogRecorder *recorder = NMT_MemoryLogRecorder::instance();
  //fprintf(stderr, "NMT_MemoryLogRecorder::log(%16s, %6ld, %12p, %12p)\n", NMTUtil::tag_to_name(mem_tag), requested, ptr, old);
  if (recorder->lockIfNotDone()) {
    volatile intx count = recorder->_count++;
    if (count < recorder->_limit) {
      Entry entry;
      entry.time = count;
      if (MemTracker::is_initialized()) {
        entry.time = os::javaTimeNanos();
      }
      entry.thread = os::current_thread_id();
      entry.ptr = ptr;
      entry.old = old;
      entry.requested = requested;
      if (entry.requested > 0) {
        //entry.requested += MemTracker::overhead_per_malloc();
      }
      entry.actual = 0;
      if (entry.requested > 0) {
        entry.actual = NMT_LogRecorder::mallocSize(ptr);
      }

      entry.mem_tag = (jlong)mem_tag;
      if ((MemTracker::is_initialized()) && (stack != nullptr)) {
        // recording stack frames will make sure that the hashtables
        // are used, so they get benchmarked
        for (int i = 0; i < NMT_TrackingStackDepth; i++) {
          entry.stack[i] = stack->get_frame(i);
        }
      }

      if (recorder->_log_fd != -1) {
        _write_and_check(recorder->_log_fd, &entry, sizeof(Entry));
      }

      recorder->logThreadName();
    } else {
      recorder->finish();
    }

    recorder->unlock();
  }
}

void NMT_MemoryLogRecorder::log_free(void *ptr) {
  //fprintf(stderr, "NMT_MemoryLogRecorder::log(%16p)\n", ptr);
  NMT_MemoryLogRecorder::_log(mtNone, 0, (address)ptr, nullptr, nullptr);
}

void NMT_MemoryLogRecorder::log_malloc(MemTag mem_tag, size_t requested, void* ptr, const NativeCallStack *stack, void* old) {
  NMT_MemoryLogRecorder::_log(mem_tag, requested, (address)ptr, (address)old, stack);
}

void NMT_MemoryLogRecorder::print(Entry *e) {
  if (e == nullptr) {
    fprintf(stderr, "nullptr\n");
  } else {
    if (IS_FREE(e)) {
      fprintf(stderr, "           FREE: ");
    } else if (IS_REALLOC(e)) {
      fprintf(stderr, "        REALLOC: ");
    } else if (IS_MALLOC(e)) {
      fprintf(stderr, "         MALLOC: ");
    }
    fprintf(stderr, "time:%15ld, thread:%6ld, ptr:%14p, old:%14p, requested:%8ld, actual:%8ld, mem_tag:%s\n", e->time, e->thread, e->ptr, e->old, e->requested, e->actual, NMTUtil::tag_to_name(NMTUtil::index_to_tag((int)e->mem_tag)));
  }
}

static inline const char* type_to_name(NMT_VirtualMemoryLogRecorder::Type type) {
  switch (type) {
    case NMT_VirtualMemoryLogRecorder::Type::RESERVE: return "RESERVE"; break;
    case NMT_VirtualMemoryLogRecorder::Type::RELEASE: return "RELEASE"; break;
    case NMT_VirtualMemoryLogRecorder::Type::UNCOMMIT: return "UNCOMMIT"; break;
    case NMT_VirtualMemoryLogRecorder::Type::RESERVE_AND_COMMIT: return "RESERVE_AND_COMMIT"; break;
    case NMT_VirtualMemoryLogRecorder::Type::COMMIT: return "COMMIT"; break;
    case NMT_VirtualMemoryLogRecorder::Type::SPLIT_RESERVED: return "SPLIT_RESERVED"; break;
    case NMT_VirtualMemoryLogRecorder::Type::TAG: return "TAG"; break;
    default: break;
  }
}

void NMT_VirtualMemoryLogRecorder::initialize(intx limit) {
  //fprintf(stderr, "> NMT_VirtualMemoryLogRecorder::initialize(%ld, %zu)\n", limit, sizeof(Entry));
  NMT_VirtualMemoryLogRecorder *recorder = NMT_VirtualMemoryLogRecorder::instance();
  recorder->init();
  recorder->lock();
  {
    recorder->_limit = limit;
    if (recorder->_limit > 0) {
      recorder->_log_fd = _prepare_log_file(nullptr, VALLOCS_LOG_FILE);
      recorder->_done = false;
    } else {
      recorder->_done = true;
    }
  }
  recorder->unlock();
}

void NMT_VirtualMemoryLogRecorder::finish(void) {
  NMT_VirtualMemoryLogRecorder *recorder = NMT_VirtualMemoryLogRecorder::instance();
  if (recorder->lockIfNotDone()) {
      volatile int log_fd = recorder->_log_fd;
    recorder->_log_fd = -1;
      //fprintf(stderr, " log_fd:%d\n", log_fd);
      log_fd = _close_and_check(log_fd);
  }

  int info_fd = _prepare_log_file(nullptr, INFO_LOG_FILE);
  if (info_fd != -1) {
    size_t level = NMTUtil::parse_tracking_level(NativeMemoryTracking);
    _write_and_check(info_fd, &level, sizeof(level));
    size_t overhead = MemTracker::overhead_per_malloc();
    _write_and_check(info_fd, &overhead, sizeof(overhead));
    info_fd = _close_and_check(info_fd);
  }

  recorder->_done = true;
  recorder->unlock();
}

void NMT_VirtualMemoryLogRecorder::replay(const int pid) {
  //fprintf(stderr, "NMT_VirtualMemoryLogRecorder::replay(\"%s\", %d)\n", path, pid);
  static const char *path = ".";
  // compare the recorded and current levels of NMT and exit if different
  //    file_info log_fi = _open_file_and_read(INFO_LOG_FILE, path, pid);
  //    size_t* status_file_bytes = (size_t*)log_fi.ptr;
  //    NMT_TrackingLevel recorded_nmt_level = (NMT_TrackingLevel)status_file_bytes[0];
  //    if (NMTUtil::parse_tracking_level(NativeMemoryTracking) != recorded_nmt_level) {
  //      tty->print("NativeMemoryTracking mismatch [%u != %u].\n", recorded_nmt_level, NMTUtil::parse_tracking_level(NativeMemoryTracking));
  //      tty->print("Re-run with \"-XX:NativeMemoryTracking=%s\"\n", NMTUtil::tracking_level_to_string(recorded_nmt_level));
  //      os::exit(-1);
  //    }

  // open records file for reading the virtual memory allocations to "play back"
  file_info records_fi = _open_file_and_read(VALLOCS_LOG_FILE, path, pid);
  if (records_fi.fd == -1) {
    return;
  }
  Entry* records_file_entries = (Entry*)records_fi.ptr;
  long int count = (records_fi.size / sizeof(Entry));

  jlong total = 0;
  //VirtualMemoryTracker::Instance::initialize(NMTUtil::parse_tracking_level(NativeMemoryTracking));
  for (off_t i = 0; i < count; i++) {
    Entry *e = &records_file_entries[i];

    MemTag mem_tag = NMTUtil::index_to_tag((int)e->mem_tag);
    int frameCount;
    for (frameCount = 0; frameCount < NMT_TrackingStackDepth; frameCount++) {
      if (e->stack[frameCount] == 0) {
        break;
      }
    }
    NativeCallStack stack = NativeCallStack::empty_stack();
    if (frameCount > 0) {
      stack = NativeCallStack(e->stack, frameCount);
    }

    jlong start = os::javaTimeNanos();
    {
      switch (e->type) {
        case NMT_VirtualMemoryLogRecorder::Type::RESERVE:
          //fprintf(stderr, "[record_virtual_memory_reserve(%p, %zu, %p, %hhu)\n", e->ptr, e->size, &stack, mem_tag);fflush(stderr);
          MemTracker::record_virtual_memory_reserve(e->ptr, e->size, stack, mem_tag);
          //fprintf(stderr, "]\n");fflush(stderr);
          break;
        case NMT_VirtualMemoryLogRecorder::Type::RELEASE:
          //fprintf(stderr, "[record_virtual_memory_release(%p, %zu)\n", e->ptr, e->size);fflush(stderr);
          MemTracker::record_virtual_memory_release(e->ptr, e->size);
          //fprintf(stderr, "]\n");fflush(stderr);
          break;
        case NMT_VirtualMemoryLogRecorder::Type::UNCOMMIT:
          //fprintf(stderr, "<record_virtual_memory_uncommit(%p, %zu)\n", e->ptr, e->size);fflush(stderr);
          MemTracker::record_virtual_memory_uncommit(e->ptr, e->size);
          //fprintf(stderr, ">\n");fflush(stderr);
          break;
        case NMT_VirtualMemoryLogRecorder::Type::RESERVE_AND_COMMIT:
          //fprintf(stderr, "[MemTracker::record_virtual_memory_reserve_and_commit\n");
          MemTracker::record_virtual_memory_reserve_and_commit(e->ptr, e->size, stack, mem_tag);
          //fprintf(stderr, "]\n");fflush(stderr);
          break;
        case NMT_VirtualMemoryLogRecorder::Type::COMMIT:
          //fprintf(stderr, "[record_virtual_memory_commit(%p, %zu, %p)\n", e->ptr, e->size, &stack);fflush(stderr);
          MemTracker::record_virtual_memory_commit(e->ptr, e->size, stack);
          //fprintf(stderr, "]\n");fflush(stderr);
          break;
        case NMT_VirtualMemoryLogRecorder::Type::SPLIT_RESERVED:
          //fprintf(stderr, "[MemTracker::record_virtual_memory_split_reserved\n");
          MemTracker::record_virtual_memory_split_reserved(e->ptr, e->size, e->size_split, mem_tag, NMTUtil::index_to_tag((int)e->mem_tag_split));
          //fprintf(stderr, "]\n");fflush(stderr);
          break;
        case NMT_VirtualMemoryLogRecorder::Type::TAG:
          //fprintf(stderr, "[record_virtual_memory_type(%p, %zu, %p)\n", e->ptr, e->size, &stack);fflush(stderr);
          MemTracker::record_virtual_memory_tag(e->ptr, mem_tag);
          //fprintf(stderr, "]\n");fflush(stderr);
          break;
        default:
          fprintf(stderr, "HUH?\n");
          os::exit(-1);
          break;
      }
    }
    jlong end = os::javaTimeNanos();
    jlong duration = (start > 0) ? (end - start) : 0;
    total += duration;
  }
  fprintf(stderr, "\n\n\nVirtualMemoryTracker summary:\n\n\n");
  fprintf(stderr, "time:%'ld[ns] [samples:%'ld]\n", total, count);

//    if (count > 0) {
//      nullStream bench_null;
//      total = 0;
//      for (off_t l = 0; l < 1; l++) {
//        jlong start = os::javaTimeNanos();
//        VirtualMemoryTracker::Instance::print_self(tty);
//        jlong end = os::javaTimeNanos();
//        jlong duration = (start > 0) ? (end - start) : 0;
//        total += duration;
//      }
//    }

  _close_and_check(records_fi.fd);
}

void NMT_VirtualMemoryLogRecorder::_log(NMT_VirtualMemoryLogRecorder::Type type, MemTag mem_tag, MemTag mem_tag_split, size_t size, size_t size_split, address ptr, const NativeCallStack *stack) {
  //fprintf(stderr, "NMT_VirtualMemoryLogRecorder::log (%s, %hhu, %hhu, %zu, %zu, %p, %p)\n",
  //        type_to_name(type), mem_tag, mem_tag_split, size, size_split, ptr, stack);fflush(stderr);
  NMT_VirtualMemoryLogRecorder *recorder = NMT_VirtualMemoryLogRecorder::instance();
  if (recorder->lockIfNotDone()) {
    volatile intx count = recorder->_count++;
    if (count < recorder->_limit) {
      Entry entry;
      entry.type = type;
      entry.time = count;
      if (MemTracker::is_initialized())
      {
        entry.time = os::javaTimeNanos();
      }
      entry.thread = os::current_thread_id();
      entry.ptr = ptr;
      entry.mem_tag = (jlong)mem_tag;
      entry.mem_tag_split = (jlong)mem_tag_split;
      entry.size = size;
      entry.size_split = size_split;
      if ((MemTracker::is_initialized()) && (stack != nullptr)) {
        // the only use of frames is for benchmarking -
        // the NMT code uses a hashtable to store these values,
        // so preserving these will make sure that the hashtables
        // are used when ran with this data
        for (int i = 0; i < NMT_TrackingStackDepth; i++) {
          entry.stack[i] = stack->get_frame(i);
        }
      }
      //fprintf(stderr, "recorder->_log_fd: %d\n", recorder->_log_fd);
      if (recorder->_log_fd != -1) {
        _write_and_check(recorder->_log_fd, &entry, sizeof(Entry));
      }
    } else {
      recorder->finish();
    }

    recorder->unlock();
  }
}

void NMT_VirtualMemoryLogRecorder::log_virtual_memory_reserve(void* addr, size_t size, const NativeCallStack& stack, MemTag mem_tag) {
  NMT_VirtualMemoryLogRecorder::_log(Type::RESERVE, mem_tag, mtNone, size, 0, (address)addr, &stack);
}

void NMT_VirtualMemoryLogRecorder::log_virtual_memory_release(address addr, size_t size) {
  NMT_VirtualMemoryLogRecorder::_log(Type::RELEASE, mtNone, mtNone, size, 0, (address)addr, nullptr);
}

void NMT_VirtualMemoryLogRecorder::log_virtual_memory_uncommit(address addr, size_t size) {
  NMT_VirtualMemoryLogRecorder::_log(Type::UNCOMMIT, mtNone, mtNone, size, 0, (address)addr, nullptr);
}

void NMT_VirtualMemoryLogRecorder::log_virtual_memory_reserve_and_commit(void* addr, size_t size, const NativeCallStack& stack, MemTag mem_tag) {
  NMT_VirtualMemoryLogRecorder::_log(Type::RESERVE_AND_COMMIT, mem_tag, mtNone, size, 0, (address)addr, &stack);
}

void NMT_VirtualMemoryLogRecorder::log_virtual_memory_commit(void* addr, size_t size, const NativeCallStack& stack) {
  NMT_VirtualMemoryLogRecorder::_log(Type::COMMIT, mtNone, mtNone, size, 0, (address)addr, &stack);
}

void NMT_VirtualMemoryLogRecorder::log_virtual_memory_split_reserved(void* addr, size_t size, size_t split, MemTag mem_tag, MemTag split_mem_tag) {
  NMT_VirtualMemoryLogRecorder::_log(Type::SPLIT_RESERVED, mem_tag, split_mem_tag, size, split, (address)addr, nullptr);
}

void NMT_VirtualMemoryLogRecorder::log_virtual_memory_tag(void* addr, MemTag mem_tag) {
  NMT_VirtualMemoryLogRecorder::_log(Type::TAG, mem_tag, mtNone, 0, 0, (address)addr, nullptr);
}
