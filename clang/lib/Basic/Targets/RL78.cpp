//===--- RL78.cpp - Implement RL78 target feature support ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements RL78 TargetInfo objects.
//
//===----------------------------------------------------------------------===//

#include "RL78.h"
#include "clang/Basic/TargetBuiltins.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang;
using namespace clang::targets;

const Builtin::Info RL78TargetInfo::BuiltinInfo[] = {
#define BUILTIN(ID, TYPE, ATTRS)                                               \
  {#ID, TYPE, ATTRS, nullptr, ALL_LANGUAGES, nullptr},
#define TARGET_BUILTIN(ID, TYPE, ATTRS, FEATURE)                               \
  {#ID, TYPE, ATTRS, nullptr, ALL_LANGUAGES, FEATURE},
#include "clang/Basic/BuiltinsRL78.def"
};

ArrayRef<Builtin::Info> RL78TargetInfo::getTargetBuiltins() const {
  return llvm::makeArrayRef(BuiltinInfo, clang::RL78::LastTSBuiltin -
                                             Builtin::FirstTSBuiltin);
}

const char *const RL78TargetInfo::GCCRegNames[] = {
    "x",   "a",   "c",   "b",   "e",   "d",   "l",   "h",   "r8",  "r9",
    "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19",
    "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29",
    "r30", "r31", "sp",  "ap",  "psw", "es",  "cs"};

const LangASMap RL78TargetInfo::RL78AddrSpaceMap = {
    0, // Default
    0, // opencl_global
    0, // opencl_local
    0, // opencl_constant
    0, // opencl_private
    0, // opencl_generic
    0, // cuda_device
    0, // cuda_constant
    0, // cuda_shared
    0, // ptr32_sptr
    0, // ptr32_uptr
    0, // ptr64
    1, // __near
    2  // __far
};

ArrayRef<const char *> RL78TargetInfo::getGCCRegNames() const {
  return llvm::makeArrayRef(GCCRegNames);
}

const TargetInfo::GCCRegAlias RL78TargetInfo::GCCRegAliases[] = {
    {{"ax"}, "x"},  {{"bc"}, "c"},  {{"de"}, "e"},  {{"hl"}, "l"},
    {{"rp0"}, "x"}, {{"rp1"}, "c"}, {{"rp2"}, "e"}, {{"rp3"}, "l"},
    {{"r0"}, "x"},  {{"r1"}, "a"},  {{"r2"}, "c"},  {{"r3"}, "b"},
    {{"r4"}, "e"},  {{"r5"}, "d"},  {{"r6"}, "l"},  {{"r7"}, "h"},
};

ArrayRef<TargetInfo::GCCRegAlias> RL78TargetInfo::getGCCRegAliases() const {
  return llvm::makeArrayRef(GCCRegAliases);
}

RL78TargetInfo::RL78TargetInfo(const llvm::Triple &Triple,
                               const TargetOptions &Opts)
    : TargetInfo(Triple) {

  has64BitDoubles = false;
  farCodeModel = false;
  isMDADisabled = false;
  for (auto &I : Opts.FeaturesAsWritten) {
    if (I == "+64bit-doubles")
      has64BitDoubles = true;
    if (I == "+disable-mda")
      isMDADisabled = true;
    if (I == "+far-code")
      farCodeModel = true;
    if (I == "+near-code")
      farCodeModel = false;
  }

  IntWidth = 16;
  IntAlign = 16;
  LongWidth = 32;
  LongLongWidth = 64;
  LongAlign = LongLongAlign = 16;
  if (!has64BitDoubles) {
    DoubleWidth = 32;
    DoubleFormat = &llvm::APFloat::IEEEsingle();
    LongDoubleWidth = 32;
    LongDoubleFormat = &llvm::APFloat::IEEEsingle();
  } else {
    DoubleWidth = 64;
    DoubleFormat = &llvm::APFloat::IEEEdouble();
    LongDoubleWidth = 64;
    LongDoubleFormat = &llvm::APFloat::IEEEdouble();
  }
  Char32Type = UnsignedLong;
  WCharType = UnsignedInt;
  WIntType = UnsignedInt;
  FloatAlign = 16;
  DoubleAlign = 16;
  LongDoubleAlign = 16;
  PointerWidth = 16;
  PointerAlign = 16;
  SuitableAlign = 16;
  SizeType = UnsignedInt;
  IntMaxType = SignedLongLong;
  IntPtrType = SignedInt;
  PtrDiffType = SignedInt;
  SigAtomicType = SignedLong;
  // TODO: see https://llvm.org/docs/LangRef.html#data-layout
  if (farCodeModel) {
    resetDataLayout(
        "e"            // little endian
        "-m:o"         // Mach-O mangling: Private symbols get L prefix. Other
                       // symbols get a _ prefix.
        "-p0:16:16:16" // default: 16 bit width, 16 bit aligned
        "-p1:16:16:16" // near pointers: 16 bit width, 16 bit aligned
        "-p2:32:16:16" // far pointers: 32 bit width, 16 bit aligned
        "-i32:16-i64:16-f32:16-f64:16-a:8" // TODO: explain
        "-n8:8"                            // 8 bit native integer width
        "-n16:16"                          // 16 bit native integer width
        "-S16"                             // 16 bit natural stack alignment
        "-P2"                              // use far pointers for functions
    );
  } else {
    resetDataLayout(
        "e"            // little endian
        "-m:o"         // Mach-O mangling: Private symbols get L prefix. Other
                       // symbols get a _ prefix.
        "-p0:16:16:16" // default: 16 bit width, 16 bit aligned
        "-p1:16:16:16" // near pointers: 16 bit width, 16 bit aligned
        "-p2:32:16:16" // far pointers: 32 bit width, 16 bit aligned
        "-i32:16-i64:16-f32:16-f64:16-a:8" // TODO: explain
        "-n8:8"                            // 8 bit native integer width
        "-n16:16"                          // 16 bit native integer width
        "-S16"                             // 16 bit natural stack alignment
    );
  }
  AddrSpaceMap = &RL78AddrSpaceMap;
}
