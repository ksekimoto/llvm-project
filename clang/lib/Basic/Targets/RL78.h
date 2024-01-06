//===--- RL78.h - Declare RL78 target feature support ---------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file declares RL78 TargetInfo objects.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_BASIC_TARGETS_RL78_H
#define LLVM_CLANG_LIB_BASIC_TARGETS_RL78_H
#include "clang/Basic/MacroBuilder.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/TargetOptions.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Support/Compiler.h"

namespace clang {
namespace targets {
class RL78TargetInfo : public TargetInfo {

  static const TargetInfo::GCCRegAlias GCCRegAliases[];
  static const char *const GCCRegNames[];
  static const Builtin::Info BuiltinInfo[];
  static const LangASMap RL78AddrSpaceMap;
  // TODO: optimize this we are comparing the string twice
  std::string CPUName;
  bool has64BitDoubles;
  bool farCodeModel;
  bool isMDADisabled;

public:
  RL78TargetInfo(const llvm::Triple &Triple, const TargetOptions &Opts);

  void getTargetDefines(const LangOptions &Opts,
                        MacroBuilder &Builder) const override {
    
	Builder.defineMacro("__ELF__");

    // Define RL78 specific macros.
    Builder.defineMacro("__RL78__");
    // OBS. We have kept the CCRL naming here which is the correct one (matches
    // the hardware) GCC defines __RL78_G10__, __RL78_G13, __RL78_G14__ which is
    // wrong.
    if (CPUName.compare("RL78_S1") == 0) {
      Builder.defineMacro("__RL78_S1__");
    } else if (CPUName.compare("RL78_S2") == 0) {
      Builder.defineMacro("__RL78_S2__");
      if (isMDADisabled) {
        Builder.defineMacro("__MDA_DISABLED__");
      } else {
        Builder.defineMacro("__MDA_ENABLED__");
      }
    } else if (CPUName.compare("RL78_S3") == 0) {
      Builder.defineMacro("__RL78_S3__");
    }

    if (has64BitDoubles)
      Builder.defineMacro("__RL78_64BIT_DOUBLES__");
    else
      Builder.defineMacro("__RL78_32BIT_DOUBLES__");

    if(Opts.getRenesasRL78RomModel() == LangOptions::RL78RomModelKind::Far)
      Builder.defineMacro("__FAR_ROM__");
    else if(Opts.getRenesasRL78RomModel() == LangOptions::RL78RomModelKind::Common)
      Builder.defineMacro("__COMMON_ROM__");
    
    if(Opts.RenesasRL78CodeModel)
      Builder.defineMacro("__RL78_MEDIUM__");
    else 
      Builder.defineMacro("__RL78_SMALL__");

    // CCRL specific macros enabled only when using -frenesas-extensions.
    if(Opts.RenesasExt) {
      // Pretend we are CCRL.
      Builder.defineMacro("__CCRL__");
      Builder.defineMacro("__CCRL");
      // TODO: define when newlib/compiler-rt multilib expects near to far
      // pointer promotion in va_arg Builder.defineMacro("__RENESAS__"); 
      
      if (has64BitDoubles)
        Builder.defineMacro("__DBL8");
      else
        Builder.defineMacro("__DBL4");
      
      if (Opts.CharIsSigned)
        Builder.defineMacro("__SCHAR");
      else 
         Builder.defineMacro("__UCHAR");

      //TODO: signed/unsigned bitfields __SBIT / __UBIT
      // -fsigned-bitfields is default, and clang doesn't yet support
      // -funsigned-bitfields.
      Builder.defineMacro("__SBIT");
    }

  }

  uint64_t getPointerWidthV(unsigned AddrSpace) const override {
    // The options is 1 - __near, 2 - __far.
    return (AddrSpace == 1)? 16 : 32;
  }

  bool setCPU(const std::string &Name) override {
    if ((Name.compare("RL78_S1") == 0) || (Name.compare("RL78_S2") == 0) ||
        (Name.compare("RL78_S3") == 0)) {
      CPUName = Name;
      return true;
    }
    return false;
  }

  bool validateAsmConstraint(const char *&Name,
                             TargetInfo::ConstraintInfo &info) const override {
    return true;
  }

  ArrayRef<const char *> getGCCRegNames() const override;

  ArrayRef<TargetInfo::GCCRegAlias> getGCCRegAliases() const override;

  ArrayRef<Builtin::Info> getTargetBuiltins() const override;

  bool allowsLargerPreferedTypeAlignment() const override { return false; }

  BuiltinVaListKind getBuiltinVaListKind() const override {
    return TargetInfo::VoidPtrBuiltinVaList;
  }

  // Returns a string of target-specific clobbers, in LLVM format.
  const char *getClobbers() const override { return ""; }
};

} // namespace targets
} // namespace clang

#endif // LLVM_CLANG_LIB_BASIC_TARGETS_RL78_H