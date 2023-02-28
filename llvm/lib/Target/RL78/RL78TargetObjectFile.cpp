//===------- RL78TargetObjectFile.cpp - RL78 Object Info Impl -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RL78TargetObjectFile.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Mangler.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCSectionELF.h"

using namespace llvm;

void
RL78TargetObjectFile::
Initialize(MCContext &Ctx, const TargetMachine &TM) {
  TargetLoweringObjectFileELF::Initialize(Ctx, TM);
}

MCSection *RL78TargetObjectFile::SelectSectionForGlobal(
    const GlobalObject *GO, SectionKind Kind, const TargetMachine &TM) const {
  // Here override ReadOnlySection to DataRelROSection for PPC64 SVR4 ABI
  // when we have a constant that contains global relocations.  This is
  // necessary because of this ABI's handling of pointers to functions in
  // a shared library.  The address of a function is actually the address
  // of a function descriptor, which resides in the .opd section.  Generated
  // code uses the descriptor directly rather than going via the GOT as some
  // other ABIs do, which means that initialized function pointers must
  // reference the descriptor.  The linker must convert copy relocs of
  // pointers to functions in shared libraries into dynamic relocations,
  // because of an ordering problem with initialization of copy relocs and
  // PLT entries.  The dynamic relocation will be initialized by the dynamic
  // linker, so we must use DataRelROSection instead of ReadOnlySection.
  // For more information, see the description of ELIMINATE_COPY_RELOCS in
  // GNU ld.
  if (Kind.isReadOnly()) {
    const auto *GVar = dyn_cast<GlobalVariable>(GO);

    if (GVar && GVar->isConstant() &&
        GVar->getInitializer()->needsDynamicRelocation())
      Kind = SectionKind::getReadOnlyWithRel();
  }

  return TargetLoweringObjectFileELF::SelectSectionForGlobal(GO, Kind, TM);
}

const MCExpr *RL78TargetObjectFile::
getDebugThreadLocalSymbol(const MCSymbol *Sym) const {
  const MCExpr *Expr =
    MCSymbolRefExpr::create(Sym, MCSymbolRefExpr::VK_DTPREL, getContext());
  return MCBinaryExpr::createAdd(Expr,
                                 MCConstantExpr::create(0x8000, getContext()),
                                 getContext());
}
