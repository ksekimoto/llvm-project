//===------- RL78TargetObjectFile.cpp - RL78 Object Info Impl -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RL78TargetObjectFile.h"
#include "RL78.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Mangler.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCSectionELF.h"

using namespace llvm;

void RL78TargetObjectFile::Initialize(MCContext &Ctx,
                                         const TargetMachine &TM) {
  TargetLoweringObjectFileELF::Initialize(Ctx, TM);
  InitializeELF(TM.Options.UseInitArray);
}

std::string RL78TargetObjectFile::getSectionPrefixForGlobal(
    SectionKind Kind, const GlobalObject *GO) const {
  bool isFar = false;
  bool useRenesasNaming = false;
  bool isSaddr = false;
  if (GO) {
    const GlobalVariable *GV = dyn_cast<GlobalVariable>(GO);
    const Function *GF = dyn_cast<Function>(GO);
    if (GV) {
      useRenesasNaming = GV->getAttributes().hasAttribute("use-renesas-naming");
      isSaddr = GV->getAttributes().hasAttribute("saddr");
      isFar = GV->getAddressSpace() == RL78AS::Far;
    } else if (GF) {
      isFar = GF->getAddressSpace() == RL78AS::Far;
    }
  }

  if (Kind.isText())
    return isFar ? ".textf" : ".text";
  if (Kind.isReadOnly()) {
    if (useRenesasNaming) {
      return isFar ? ".constf" : ".const";
    } else {
      return isFar ? ".frodata" : ".rodata";
    }
  }

  if (isSaddr) {
    return Kind.isData() ? ".sdata" : ".sbss";
  }

  if (Kind.isBSS()) {
    return isFar ? ".bssf" : ".bss";
}

  if (Kind.isData())
    return isFar ? ".dataf" : ".data";
  assert(Kind.isReadOnlyWithRel() && "Unknown section kind");
  return ".data.rel.ro";
}
