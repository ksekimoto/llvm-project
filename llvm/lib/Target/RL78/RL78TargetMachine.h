//===-- RL78TargetMachine.h - Define TargetMachine for RL78 ---*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file declares the RL78 specific subclass of TargetMachine.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RL78_RL78TARGETMACHINE_H
#define LLVM_LIB_TARGET_RL78_RL78TARGETMACHINE_H

#include "RL78Subtarget.h"

namespace llvm {

class RL78TargetMachine : public LLVMTargetMachine {
  std::unique_ptr<TargetLoweringObjectFile> TLOF;
  RL78Subtarget Subtarget;
  bool is64Bit;
  mutable StringMap<std::unique_ptr<RL78Subtarget>> SubtargetMap;

public:
  RL78TargetMachine(const Target &T, const Triple &TT, StringRef CPU,
                    StringRef FS, const TargetOptions &Options,
                    Optional<Reloc::Model> RM, Optional<CodeModel::Model> CM,
                    CodeGenOpt::Level OL, bool JIT);
  ~RL78TargetMachine() override;

  const RL78Subtarget *getSubtargetImpl() const { return &Subtarget; }
  const RL78Subtarget *getSubtargetImpl(const Function &) const override;

  // Pass Pipeline Configuration
  TargetPassConfig *createPassConfig(PassManagerBase &PM) override;
  TargetLoweringObjectFile *getObjFileLowering() const override {
    return TLOF.get();
  }

  bool isMachineVerifierClean() const override { return false; }

  // FIXME: currently we are using substitutePass(&PostRASchedulerID,
  // &PostMachineSchedulerID)
  // we might come back to this at some point maybe on -O3.
  // Temporary option to allow experimenting with MachineScheduler as a post-RA
  // scheduler. Targets can "properly" enable this with
  // substitutePass(&PostRASchedulerID, &PostMachineSchedulerID).
  // Targets can return true in targetSchedulesPostRAScheduling() and
  // insert a PostRA scheduling pass wherever it wants.
  bool targetSchedulesPostRAScheduling() const override { return false; }

  bool useIPRA() const override { return true; }
};

} // end namespace llvm

#endif
