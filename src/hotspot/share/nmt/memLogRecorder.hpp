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

#ifndef SHARE_NMT_MEMLOGRECORDER_HPP
#define SHARE_NMT_MEMLOGRECORDER_HPP

#include "memory/allocation.hpp"
#include "nmt/nmtCommon.hpp"
#include "runtime/globals.hpp"

class NMT_LogRecorder : public StackObj {
#if defined(LINUX) || defined(__APPLE__)
  pthread_mutex_t _mutex;
#elif defined(WINDOWS)
 // ???
#endif
protected:
  intx _limit  = 0;
  intx _count  = 0;
  int _log_fd;
  volatile bool _done = true;
  static constexpr size_t _threads_name_length = 32;
  volatile size_t _threads_names_capacity = 128;
  volatile size_t _threads_names_counter = 0;
  typedef struct thread_name_info {
    char name[_threads_name_length];
    intx thread;
  } thread_name_info;
  thread_name_info *_threads_names = nullptr;

public:
  static void initialize(intx memoryCount, intx virtualMemoryCount);
  static void finish();
  static void replay(const int pid);
  static void logThreadName(const char* name);
  static size_t mallocSize(void* ptr);

public:
  void init();
  bool lockIfNotDone();
  void lock();
  void unlock();
  bool done() {
    return _done;
  }

private:
  void _logThreadName(const char* name);
};

class NMT_MemoryLogRecorder : public NMT_LogRecorder {

private:
  static NMT_MemoryLogRecorder _recorder;

private:
    struct Entry {
    jlong time;
    intx thread;
    address ptr;
    address old;
    address stack[NMT_TrackingStackDepth];
    size_t requested;
    size_t actual;
    jlong mem_tag;
  };

public:
  static NMT_MemoryLogRecorder* instance() {
    return &_recorder;
  };
  static void initialize(intx count);
  static bool initialized() {
    return false;
  }
  static void print(Entry *e);
  static void finish(void);
  static void replay(const int pid);
  static void log_free(void *ptr);
  static void log_malloc(MemTag mem_tag, size_t requested, void* ptr, const NativeCallStack *stack, void* old = nullptr);
  static void printActualSizesFor(const char* list);

private:
  static void _log(MemTag mem_tag, size_t requested, address ptr, address old, const NativeCallStack *stack);
};

class NMT_VirtualMemoryLogRecorder : public NMT_LogRecorder {

private:
  static NMT_VirtualMemoryLogRecorder _recorder;

private:
  struct Entry {
    jlong time;
    intx thread;
    address ptr;
    address stack[NMT_TrackingStackDepth];
    jlong mem_tag;
    jlong mem_tag_split;
    size_t size;
    size_t size_split;
    int type;
  };

public:
  enum Type {
    RESERVE,
    RELEASE,
    UNCOMMIT,
    RESERVE_AND_COMMIT,
    COMMIT,
    SPLIT_RESERVED,
    TAG
  };

public:
  static NMT_VirtualMemoryLogRecorder* instance() {
    return &_recorder;
  };
  static void initialize(intx count);
  static void finish(void);
  static void replay(const int pid);
  static void log_virtual_memory_reserve(void* addr, size_t size, const NativeCallStack& stack, MemTag mem_tag = mtNone);
  static void log_virtual_memory_release(address addr, size_t size);
  static void log_virtual_memory_uncommit(address addr, size_t size);
  static void log_virtual_memory_reserve_and_commit(void* addr, size_t size, const NativeCallStack& stack, MemTag mem_tag = mtNone);
  static void log_virtual_memory_commit(void* addr, size_t size, const NativeCallStack& stack);
  static void log_virtual_memory_split_reserved(void* addr, size_t size, size_t split, MemTag flag, MemTag mem_tag_split);
  static void log_virtual_memory_tag(void* addr, MemTag mem_tag);

private:
  static void _log(NMT_VirtualMemoryLogRecorder::Type type, MemTag mem_tag, MemTag mem_tag_split, size_t size, size_t size_split, address ptr, const NativeCallStack *stack);
};

#endif // SHARE_NMT_MEMLOGRECORDER_HPP
