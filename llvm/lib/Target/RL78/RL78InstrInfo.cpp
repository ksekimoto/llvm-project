//===-- RL78InstrInfo.cpp - RL78 Instruction Information ----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the RL78 implementation of the TargetInstrInfo class.
//
//===----------------------------------------------------------------------===//

#include "RL78Subtarget.h"
#include "llvm/CodeGen/ScheduleDAG.h"
#include "llvm/CodeGen/ScheduleHazardRecognizer.h"

using namespace llvm;

#define GET_INSTRINFO_CTOR_DTOR
#include "RL78GenInstrInfo.inc"

// Pin the vtable to this file.
void RL78InstrInfo::anchor() {}

RL78InstrInfo::RL78InstrInfo(RL78Subtarget &ST)
    : RL78GenInstrInfo(RL78::ADJCALLSTACKDOWN, RL78::ADJCALLSTACKUP), RI(),
      Subtarget(ST) {}

/// isLoadFromStackSlot - If the specified machine instruction is a direct
/// load from a stack slot, return the virtual or physical register number of
/// the destination along with the FrameIndex of the loaded stack slot.  If
/// not, return 0.  This predicate must return 0 if the instruction has
/// any side effects other than loading from the stack slot.
unsigned RL78InstrInfo::isLoadFromStackSlot(const MachineInstr &MI,
                                            int &FrameIndex) const {
  // MI.dump();
  if ((MI.getOpcode() == RL78::LOAD8_r_stack_slot) ||
      (MI.getOpcode() == RL78::LOAD16_rp_stack_slot)) {
    if (MI.getOperand(1).isFI() && MI.getOperand(2).isImm() &&
        MI.getOperand(2).getImm() == 0) {
      FrameIndex = MI.getOperand(1).getIndex();
      return MI.getOperand(0).getReg();
    }
  }
  return 0;
}

/// isStoreToStackSlot - If the specified machine instruction is a direct
/// store to a stack slot, return the virtual or physical register number of
/// the source reg along with the FrameIndex of the loaded stack slot.  If
/// not, return 0.  This predicate must return 0 if the instruction has
/// any side effects other than storing to the stack slot.
unsigned RL78InstrInfo::isStoreToStackSlot(const MachineInstr &MI,
                                           int &FrameIndex) const {
  if ((MI.getOpcode() == RL78::STORE8_stack_slot_r) ||
      (MI.getOpcode() == RL78::STORE16_stack_slot_rp)) {
    if (MI.getOperand(0).isFI() && MI.getOperand(1).isImm() &&
        MI.getOperand(1).getImm() == 0) {
      FrameIndex = MI.getOperand(0).getIndex();
      return MI.getOperand(2).getReg();
    }
  }
  return 0;
}

void RL78InstrInfo::storeRegToStackSlot(MachineBasicBlock &MBB,
                                        MachineBasicBlock::iterator I,
                                        unsigned SrcReg, bool isKill, int FI,
                                        const TargetRegisterClass *RC,
                                        const TargetRegisterInfo *TRI) const {
  DebugLoc DL;
  // dbgs() << "storeRegToStackSlot\n";
  if (I != MBB.end())
    DL = I->getDebugLoc();
  if ((TRI->getRegSizeInBits(*RC) == 8)) {
    BuildMI(MBB, I, DL, get(RL78::STORE8_stack_slot_r))
        .addFrameIndex(FI)
        .addImm(0)
        .addReg(SrcReg, getKillRegState(isKill));
  } else {
    BuildMI(MBB, I, DL, get(RL78::STORE16_stack_slot_rp))
        .addFrameIndex(FI)
        .addImm(0)
        .addReg(SrcReg, getKillRegState(isKill));
  }
  // MBB.dump();
}

void RL78InstrInfo::loadRegFromStackSlot(MachineBasicBlock &MBB,
                                         MachineBasicBlock::iterator I,
                                         unsigned DestReg, int FI,
                                         const TargetRegisterClass *RC,
                                         const TargetRegisterInfo *TRI) const {
  DebugLoc DL;
  if (I != MBB.end())
    DL = I->getDebugLoc();
  // dbgs() << "loadRegFromStackSlot\n";
  if (TRI->getRegSizeInBits(*RC) == 8) {
    BuildMI(MBB, I, DL, get(RL78::LOAD8_r_stack_slot), DestReg)
        .addFrameIndex(FI)
        .addImm(0);
  } else {
    BuildMI(MBB, I, DL, get(RL78::LOAD16_rp_stack_slot), DestReg)
        .addFrameIndex(FI)
        .addImm(0);
    // We can't do this here becuase it's done during reg alloc.
    // BuildMI(MBB, I, DL, get(RL78::LOAD16_rp_stack_slot),
    // RL78::RP0).addFrameIndex(FI).addImm(0); BuildMI(MBB, I, DL,
    // get(RL78::COPY)).addReg(DestReg).addReg(RL78::RP0, RegState::Kill);
  }
  // MBB.dump();
}

static RL78CC::CondCodes GetOppositeBranchCondition(RL78CC::CondCodes CC) {
  switch (CC) {
  case RL78CC::RL78CC_C:
    return RL78CC::RL78CC_NC;
  case RL78CC::RL78CC_NC:
    return RL78CC::RL78CC_C;
  case RL78CC::RL78CC_Z:
    return RL78CC::RL78CC_NZ;
  case RL78CC::RL78CC_NZ:
    return RL78CC::RL78CC_Z;
  case RL78CC::RL78CC_H:
    return RL78CC::RL78CC_NH;
  case RL78CC::RL78CC_NH:
    return RL78CC::RL78CC_H;
  }
  llvm_unreachable("Invalid condition code!");
}

static bool isUncondBranchOpcode(int Opc) { return Opc == RL78::BR; }

static bool isCondBranchOpcode(int Opc) {
  return (Opc == RL78::BRCC) || (Opc == RL78::BTBF) || (Opc == RL78::BTBF_mem);
}

static bool isIndirectBranchOpcode(int Opc) { return Opc == RL78::BR_AX; }

static void parseCondBranch(MachineInstr *LastInst, MachineBasicBlock *&Target,
                            SmallVectorImpl<MachineOperand> &Cond) {
  Cond.push_back(MachineOperand::CreateImm(LastInst->getOperand(1).getImm()));
  Target = LastInst->getOperand(0).getMBB();
  // if BT/BF/BTCLR instruction add the remaining 2 operands (reg and bit)
  // LastInst->dump();
  if (LastInst->getNumOperands() > 3) {
    Cond.push_back(MachineOperand::CreateImm(LastInst->getOpcode()));
    Cond.push_back(LastInst->getOperand(2));
    Cond.push_back(LastInst->getOperand(3));
  }
}

bool RL78InstrInfo::analyzeBranch(MachineBasicBlock &MBB,
                                  MachineBasicBlock *&TBB,
                                  MachineBasicBlock *&FBB,
                                  SmallVectorImpl<MachineOperand> &Cond,
                                  bool AllowModify) const {
  MachineBasicBlock::iterator I = MBB.getLastNonDebugInstr();
  // empty BB? fall-through
  if (I == MBB.end())
    return false;

  // not a branch instruction? fall-through
  if (!isUnpredicatedTerminator(*I))
    return false;

  // Get the last instruction in the block.
  MachineInstr *LastInst = &*I;
  unsigned LastOpc = LastInst->getOpcode();

  // If there is only one terminator instruction, process it.
  if (I == MBB.begin() || (!(--I)->isBranch())) {
    if (isUncondBranchOpcode(LastOpc)) {
      TBB = LastInst->getOperand(0).getMBB();
      return false;
    }
    if (isCondBranchOpcode(LastOpc)) {
      // Block ends with fall-through condbranch.
      parseCondBranch(LastInst, TBB, Cond);
      return false;
    }
    return true; // Can't handle indirect branch.
  }
  // MBB.dump();
  // Get the instruction before it if it is a terminator.
  MachineInstr *SecondLastInst = &*I;
  unsigned SecondLastOpc = SecondLastInst->getOpcode();

  // If AllowModify is true and the block ends with two or more unconditional
  // branches, delete all but the first unconditional branch.
  if (AllowModify && isUncondBranchOpcode(LastOpc)) {
    while (isUncondBranchOpcode(SecondLastOpc)) {
      LastInst->eraseFromParent();
      LastInst = SecondLastInst;
      LastOpc = LastInst->getOpcode();
      if (I == MBB.begin() || (!(--I)->isBranch())) {
        // Return now the only terminator is an unconditional branch.
        TBB = LastInst->getOperand(0).getMBB();
        return false;
      } else {
        SecondLastInst = &*I;
        SecondLastOpc = SecondLastInst->getOpcode();
      }
    }
  }

  // If there are three terminators, we don't know what sort of block this is.
  if (SecondLastInst && I != MBB.begin() && isUnpredicatedTerminator(*--I))
    return true;

  // If the block ends with a B and a Bcc, handle it.
  if (isCondBranchOpcode(SecondLastOpc) && isUncondBranchOpcode(LastOpc)) {
    parseCondBranch(SecondLastInst, TBB, Cond);
    FBB = LastInst->getOperand(0).getMBB();
    return false;
  }

  // If the block ends with two unconditional branches, handle it.  The second
  // one is not executed.
  if (isUncondBranchOpcode(SecondLastOpc) && isUncondBranchOpcode(LastOpc)) {
    TBB = SecondLastInst->getOperand(0).getMBB();
    return false;
  }

  // ...likewise if it ends with an indirect branch followed by an unconditional
  // branch.
  if (isIndirectBranchOpcode(SecondLastOpc) && isUncondBranchOpcode(LastOpc)) {
    I = LastInst;
    if (AllowModify)
      I->eraseFromParent();
    return true;
  }

  // Otherwise, can't handle this.
  return true;
}

unsigned RL78InstrInfo::insertBranch(
    MachineBasicBlock &MBB, MachineBasicBlock *TBB, MachineBasicBlock *FBB,
    ArrayRef<MachineOperand> Cond, const DebugLoc &DL, int *BytesAdded) const {
  assert(TBB && "insertBranch must not be told to insert a fallthrough");
  assert(!BytesAdded && "code size not handled");
  // MBB.dump();
  // MBB.getParent()->dump();
  if (Cond.empty()) {
    assert(!FBB && "Unconditional branch with multiple successors!");
    BuildMI(&MBB, DL, get(RL78::BR)).addMBB(TBB);
    return 1;
  }

  // Conditional branch
  unsigned CC = Cond[0].getImm();

  // is this a BT/BF/BTCLR
  if (Cond.size() > 1) {
    // Cond[1].dump();
    BuildMI(&MBB, DL, get(Cond[1].getImm()))
        .addMBB(TBB)
        .addImm(CC)
        .add(Cond[2])
        .add(Cond[3]);
    // MBB.dump();
  } else {
    BuildMI(&MBB, DL, get(RL78::BRCC)).addMBB(TBB).addImm(CC);
  }
  // do we need to insert a branch for the FBB as well?
  if (!FBB)
    return 1;

  BuildMI(&MBB, DL, get(RL78::BR)).addMBB(FBB);
  return 2;
}

unsigned RL78InstrInfo::removeBranch(MachineBasicBlock &MBB,
                                     int *BytesRemoved) const {
  // FIXME: we currently have our own 'branchexpand' pass
  // Try and use BranchRelaxation at some point.
  assert(!BytesRemoved && "code size not handled");
  // MBB.dump();
  // MBB.getParent()->dump();
  MachineBasicBlock::iterator I = MBB.end();
  unsigned Count = 0;
  while (I != MBB.begin()) {
    --I;

    if (I->isDebugValue())
      continue;

    if ((I->getOpcode() != RL78::BR) && (I->getOpcode() != RL78::BR_AX) &&
        (I->getOpcode() != RL78::BTBF) && (I->getOpcode() != RL78::BTBF_mem) &&
        (I->getOpcode() != RL78::BRCC))
      break; // Not a branch.

    I->eraseFromParent();
    I = MBB.end();
    ++Count;
  }
  return Count;
}

bool RL78InstrInfo::reverseBranchCondition(
    SmallVectorImpl<MachineOperand> &Cond) const {
  RL78CC::CondCodes CC = static_cast<RL78CC::CondCodes>(Cond[0].getImm());
  Cond[0].setImm(GetOppositeBranchCondition(CC));
  return false;
}

void RL78InstrInfo::copyPhysReg(MachineBasicBlock &MBB,
                                MachineBasicBlock::iterator I,
                                const DebugLoc &DL, MCRegister DestReg,
                                MCRegister SrcReg, bool KillSrc) const {
  // 8 bit copy:
  if (RL78::RL78RegRegClass.contains(DestReg, SrcReg)) {
    // mov A, <...>
    if (RL78::RL78ARegRegClass.contains(DestReg)) {
      // mov A, r
      BuildMI(MBB, I, DL, get(RL78::MOV_A_r), DestReg)
          .addReg(SrcReg, getKillRegState(KillSrc));
    }
    // mov <..>, A
    else if (RL78::RL78ARegRegClass.contains(SrcReg)) {
      // mov r, A
      BuildMI(MBB, I, DL, get(RL78::MOV_r_A), DestReg)
          .addReg(SrcReg, getKillRegState(KillSrc));
    } else {
      // FIXME: revisit this.
      // last solution for 8 bit copy:
      // using xch: 3 - 8 bytes and 3-5 clocks
      // xch A, dst -> 1,2,3 bytes and clocks 1,2
      // mov A, src -> 1,2 bytes and clocks 1
      // xch A, dst -> 1,2,3 bytes and clocks 1,2
      // or using push,pop: 4-6 bytes and 4 clocks
      // push AX -> 1 byte and clocks 1
      // mov A, src -> 1,2 bytes and clocks 1
      // mov dst, A -> 1,2 bytes and clocks 1
      // pop AX -> 1 byte and clocks 1
      if (MBB.getParent()->getFunction().hasMinSize() &&
          (DestReg != RL78::R0)) {
        BuildMI(MBB, I, DL, get(RL78::PUSH_rp))
            .addReg(RL78::RP0, RegState::Kill);
        // mov A, r
        BuildMI(MBB, I, DL, get(RL78::MOV_A_r), RL78::R1)
            .addReg(SrcReg, getKillRegState(KillSrc));
        // mov r, A
        BuildMI(MBB, I, DL, get(RL78::MOV_r_A), DestReg)
            .addReg(RL78::R1, RegState::Kill);
        //
        BuildMI(MBB, I, DL, get(RL78::POP_rp), RL78::RP0);
      } else {
        BuildMI(MBB, I, DL, get(RL78::XCH_A_r), RL78::R1)
            .addReg(DestReg, RegState::Define)
            .addReg(RL78::R1, RegState::Kill)
            .addReg(DestReg, RegState::Kill);
        // mov A, r
        BuildMI(MBB, I, DL, get(RL78::MOV_A_r), RL78::R1)
            .addReg(SrcReg, getKillRegState(KillSrc));
        //
        BuildMI(MBB, I, DL, get(RL78::XCH_A_r), RL78::R1)
            .addReg(DestReg, RegState::Define)
            .addReg(RL78::R1, RegState::Kill)
            .addReg(DestReg, RegState::Kill);
      }
    }
  }
  // moving on to 16 bit copy:
  else if (RL78::RL78RPRegsRegClass.contains(DestReg, SrcReg)) {
    // movw AX, <...>
    if (RL78::RL78AXRPRegClass.contains(DestReg)) {
      // movw AX, rp
      BuildMI(MBB, I, DL, get(RL78::MOVW_AX_rp), DestReg)
          .addReg(SrcReg, getKillRegState(KillSrc));
    }
    // movw <..>, AX
    else if (RL78::RL78AXRPRegClass.contains(SrcReg)) {
      // movw rp, AX
      BuildMI(MBB, I, DL, get(RL78::MOVW_rp_AX), DestReg)
          .addReg(SrcReg, getKillRegState(KillSrc));
    }
    // movw BC/DE/HL, BC/DE/HL using push/pop 2 bytes and 2 cycles.
    else {
      BuildMI(MBB, I, DL, get(RL78::PUSH_rp))
          .addReg(SrcReg, getKillRegState(KillSrc));
      BuildMI(MBB, I, DL, get(RL78::POP_rp), DestReg);
    }
  }
  // 16 to 8 bit copy:
  else if (RL78::RL78RegRegClass.contains(DestReg) &&
           RL78::RL78RPRegsRegClass.contains(SrcReg)) {
    llvm_unreachable("Don't know how to copy from 16 to 8 bit reg!");
    // if the 8 bit reg is part of the 16 bit reg don't do anything
    // else do a a bit copy of the low part
    // const TargetRegisterInfo *TRI = &getRegisterInfo();
    // unsigned int source = TRI->getSubReg(SrcReg, RL78::sub_lo);
    // assert(DestReg != TRI->getSubReg(SrcReg, RL78::sub_hi) && "Unhandled copy
    // form hi part!"); if(source != DestReg)
    //  copyPhysReg(MBB, I, DL, DestReg, source, KillSrc);
  }
  // 8 to 16 bit copy:
  else if (RL78::RL78RPRegsRegClass.contains(DestReg) &&
           RL78::RL78RegRegClass.contains(SrcReg)) {
    // const TargetRegisterInfo *TRI = &getRegisterInfo();
    // unsigned int dstlo = TRI->getSubReg(SrcReg, RL78::sub_lo);
    // BuildMI(MBB, I, DL, get(RL78::MOV_A_r), DestReg).addReg(SrcReg,
    // getKillRegState(KillSrc));
    llvm_unreachable("Don't know how to copy from 8 to 16 bit reg!");
  }
  // SP reg to 16 bit reg
  else if (RL78::RL78RPRegsRegClass.contains(DestReg) &&
           RL78::RL78SPRegRegClass.contains(SrcReg)) {
    BuildMI(MBB, I, DL, get(RL78::MOVW_rp_sp), DestReg)
        .addReg(SrcReg, getKillRegState(KillSrc));
  }
  // 16 bit reg to SP reg
  else if (RL78::RL78SPRegRegClass.contains(DestReg) &&
           RL78::RL78RPRegsRegClass.contains(SrcReg)) {
    //
    if (SrcReg == RL78::RP0)
      BuildMI(MBB, I, DL, get(RL78::MOVW_sp_rp), DestReg)
          .addReg(SrcReg, getKillRegState(KillSrc));
    else {
      BuildMI(MBB, I, DL, get(RL78::XCHW_AX_rp), RL78::RP0)
          .addReg(SrcReg, RegState::Define)
          .addReg(RL78::RP0, RegState::Kill)
          .addReg(SrcReg, RegState::Kill);
      BuildMI(MBB, I, DL, get(RL78::MOVW_sp_rp), DestReg).addReg(RL78::RP0);
      BuildMI(MBB, I, DL, get(RL78::XCHW_AX_rp), RL78::RP0)
          .addReg(SrcReg, RegState::Define)
          .addReg(RL78::RP0, RegState::Kill)
          .addReg(SrcReg, RegState::Kill);
    }
  } else if (RL78::RL78Bank0RegRegClass.contains(DestReg) &&
             RL78::RL78CCRegRegClass.contains(SrcReg)) {

    BuildMI(MBB, I, DL, get(RL78::MOV1_r_cy), DestReg)
        .addReg(SrcReg, getKillRegState(KillSrc))
        .addImm(0);
  } else if (RL78::RL78CCRegRegClass.contains(DestReg) &&
             RL78::RL78Bank0RegRegClass.contains(SrcReg)) {

    BuildMI(MBB, I, DL, get(RL78::MOV1_cy_r))
        .addReg(SrcReg, getKillRegState(KillSrc))
        .addImm(0);
  }
  // 8 bit reg to CS
  else if (RL78::CS == DestReg && RL78::RL78Bank0RegRegClass.contains(SrcReg)) {
    if (RL78::R1 == SrcReg) {
      BuildMI(MBB, I, DL, get(RL78::MOV_cs_A), RL78::CS)
          .addReg(RL78::R1, RegState::Kill);
    } else {
      BuildMI(MBB, I, DL, get(RL78::XCH_A_r), RL78::R1)
          .addReg(SrcReg, RegState::Define)
          .addReg(RL78::R1, RegState::Kill)
          .addReg(SrcReg, RegState::Kill);
      BuildMI(MBB, I, DL, get(RL78::MOV_cs_A), RL78::CS)
          .addReg(RL78::R1, RegState::Kill);
      BuildMI(MBB, I, DL, get(RL78::XCH_A_r), RL78::R1)
          .addReg(SrcReg, RegState::Define)
          .addReg(RL78::R1, RegState::Kill)
          .addReg(SrcReg, RegState::Kill);
    }
  } else
    llvm_unreachable("Unknown copy!");
  // MovMI->addRegisterDefined(DestReg, TRI);
}

unsigned RL78InstrInfo::getInstSizeInBytes(const MachineInstr &MI) const {
  return MI.getDesc().getSize();
}

/// Constants defining how certain sequences should be outlined.
///
/// \p MachineOutlinerDefault implies that the function is called with a call
/// instruction, and a return must be emitted for the outlined function frame.
///
/// That is,
///
/// I1                                 OUTLINED_FUNCTION:
/// I2 --> call OUTLINED_FUNCTION       I1
/// I3                                  I2
///                                     I3
///                                     ret
///
/// * Call construction overhead: 1 (call instruction)
/// * Frame construction overhead: 1 (return instruction)
///
/// \p MachineOutlinerTailCall implies that the function is being tail called.
/// A jump is emitted instead of a call, and the return is already present in
/// the outlined sequence. That is,
///
/// I1                                 OUTLINED_FUNCTION:
/// I2 --> jmp OUTLINED_FUNCTION       I1
/// ret                                I2
///                                    ret
///
/// * Call construction overhead: 1 (jump instruction)
/// * Frame construction overhead: 0 (don't need to return)
///
enum MachineOutlinerClass { MachineOutlinerDefault, MachineOutlinerTailCall };

/// Returns a \p outliner::OutlinedFunction struct containing target-specific
/// information for a set of outlining candidates.
outliner::OutlinedFunction RL78InstrInfo::getOutliningCandidateInfo(
    std::vector<outliner::Candidate> &RepeatedSequenceLocs) const {
  //
  unsigned SequenceSize =
      std::accumulate(RepeatedSequenceLocs[0].front(),
                      std::next(RepeatedSequenceLocs[0].back()), 0,
                      [this](unsigned Sum, const MachineInstr &MI) {
                        return Sum + getInstSizeInBytes(MI);
                      });

  if (RepeatedSequenceLocs[0].back()->isTerminator()) {
    unsigned CO = Subtarget.HasFarCodeModel() ? get(RL78::BR_addr20).getSize()
                                              : get(RL78::BR_addr16).getSize();

    for (outliner::Candidate &C : RepeatedSequenceLocs)
      C.setCallInfo(MachineOutlinerTailCall, CO);

    return outliner::OutlinedFunction(RepeatedSequenceLocs, SequenceSize,
                                      0, // Number of bytes to emit frame.
                                      MachineOutlinerTailCall // Type of frame.
    );
  }
  unsigned CO = Subtarget.HasFarCodeModel() ? get(RL78::CALL_addr20).getSize()
                                            : get(RL78::CALL_addr16).getSize();
  for (outliner::Candidate &C : RepeatedSequenceLocs)
    C.setCallInfo(MachineOutlinerDefault, CO);
  return outliner::OutlinedFunction(RepeatedSequenceLocs, SequenceSize, 0,
                                    MachineOutlinerDefault);
}

/// Returns how or if \p MI should be outlined.
outliner::InstrType
RL78InstrInfo::getOutliningType(MachineBasicBlock::iterator &MIT,
                                unsigned Flags) const {
  MachineInstr &MI = *MIT;
  // Don't allow debug values to impact outlining type.
  if (MI.isDebugInstr() || MI.isIndirectDebugValue())
    return outliner::InstrType::Invisible;

  // At this point, KILL instructions don't really tell us much so we can go
  // ahead and skip over them.
  if (MI.isKill())
    return outliner::InstrType::Invisible;

  // Is this a tail call? If yes, we can outline as a tail call.
  if (isTailCall(MI))
    return outliner::InstrType::Legal;

  // Is this the terminator of a basic block?
  if (MI.isTerminator() || MI.isReturn()) {

    // Does its parent have any successors in its MachineFunction?
    if (MI.getParent()->succ_empty())
      return outliner::InstrType::Legal;

    // It does, so we can't tail call it.
    return outliner::InstrType::Illegal;
  }
  // Positions can't safely be outlined.
  if (MI.isPosition())
    return outliner::InstrType::Illegal;
  // Make sure none of the operands of this instruction do anything tricky.
  for (const MachineOperand &MOP : MI.operands())
    if (MOP.isCPI() || MOP.isJTI() || MOP.isCFIIndex() || MOP.isFI() ||
        MOP.isTargetIndex() || (MOP.isReg() && MOP.getReg() == RL78::SPreg))
      return outliner::InstrType::Illegal;

  return outliner::InstrType::Legal;
}

/// Insert a custom frame for outlined functions.
void RL78InstrInfo::buildOutlinedFrame(
    MachineBasicBlock &MBB, MachineFunction &MF,
    const outliner::OutlinedFunction &OF) const {
  // If we're a tail call, we already have a return, so don't do anything.
  if (OF.FrameConstructionID == MachineOutlinerTailCall)
    return;

  // We're a normal call, so our sequence doesn't have a return instruction.
  // Add it in.
  MachineInstr *retq = BuildMI(MF, DebugLoc(), get(RL78::RET));
  MBB.insert(MBB.end(), retq);
}

/// Insert a call to an outlined function into the program.
/// Returns an iterator to the spot where we inserted the call. This must be
/// implemented by the target.
MachineBasicBlock::iterator RL78InstrInfo::insertOutlinedCall(
    Module &M, MachineBasicBlock &MBB, MachineBasicBlock::iterator &It,
    MachineFunction &MF, const outliner::Candidate &C) const {
  // Is it a tail call?
  unsigned Opcode;
  if (C.CallConstructionID == MachineOutlinerTailCall) {
    // Yes, just insert a JMP.
    Opcode = Subtarget.HasFarCodeModel() ? RL78::BR_addr20 : RL78::BR_addr16;
  } else {
    // No, insert a call.
    Opcode =
        Subtarget.HasFarCodeModel() ? RL78::CALL_addr20 : RL78::CALL_addr16;
  }
  It = MBB.insert(It, BuildMI(MF, DebugLoc(), get(Opcode))
                          .addGlobalAddress(M.getNamedValue(MF.getName())));
  return It;
}

/// Return true if the function can safely be outlined from.
/// A function \p MF is considered safe for outlining if an outlined function
/// produced from instructions in F will produce a program which produces the
/// same output for any set of given inputs.
bool RL78InstrInfo::isFunctionSafeToOutlineFrom(
    MachineFunction &MF, bool OutlineFromLinkOnceODRs) const {
  const Function &F = MF.getFunction();
  // If we *don't* want to outline from things that could potentially be deduped
  // then return false.
  if (!OutlineFromLinkOnceODRs && F.hasLinkOnceODRLinkage())
    return false;

  // It's safe to outline from MF.
  return true;
}

/// Return true if the function should be outlined from by default.
bool RL78InstrInfo::shouldOutlineFromFunctionByDefault(
    MachineFunction &MF) const {
  return MF.getFunction().hasOptSize();
}

ArrayRef<std::pair<unsigned, const char *>>
RL78InstrInfo::getSerializableDirectMachineOperandTargetFlags() const {

  static const std::pair<unsigned, const char *> Flags[] = {
      {SPII::MO_LOW8, "rl78_low8"},
      {SPII::MO_LOW16, "rl78_low16"},
      {SPII::MO_HI16, "rl78_hi16"}};
  return makeArrayRef(Flags);
}

MachineInstr *RL78InstrInfo::foldMemoryOperandImpl(
    MachineFunction &MF, MachineInstr &MI, ArrayRef<unsigned> Ops,
    MachineBasicBlock::iterator InsertPt, int FrameIndex, LiveIntervals *LIS,
    VirtRegMap *VRM) const {
  if ((MI.getOpcode() != RL78::MOV_r_imm) && (MI.getOpcode() != RL78::ONEB_r) &&
      (MI.getOpcode() != RL78::CLRB_r))
    return nullptr;

  int64_t Imm;
  switch (MI.getOpcode()) {
  case RL78::MOV_r_imm:
    Imm = MI.getOperand(1).getImm();
    break;
  case RL78::ONEB_r:
    Imm = 1;
    break;
  case RL78::CLRB_r:
    Imm = 0;
    break;
  }
  return BuildMI(*MI.getParent(), InsertPt, MI.getDebugLoc(),
                 get(RL78::STORE8_stack_slot_imm))
      .addFrameIndex(FrameIndex)
      .addImm(0)
      .addImm(Imm);
}

// See 7.2.3 Hazards related to combined instructions
// in the RL78 Software Manual.
class RL78HazardRecognizer : public ScheduleHazardRecognizer {
  const unsigned SP = 8;
  const unsigned CS = 9;
  // 0-7 Bak 0 regs, 8 - SP reg, 9 - CS reg.
  BitVector RegMask;
  // Is the issued instruction an SEL instruction?
  bool SelI;
  // Is an instruction issues in this cycle?
  bool Issue;

public:
  RL78HazardRecognizer() : RegMask(10){};

  /// atIssueLimit - Return true if no more instructions may be issued in this
  /// cycle.
  ///
  /// FIXME: remove this once MachineScheduler is the only client.
  bool atIssueLimit() const override { return Issue; }

  /// Reset - This callback is invoked when a new block of
  /// instructions is about to be schedule. The hazard state should be
  /// set to an initialized state.
  void Reset() override {
    RegMask.reset();
    SelI = false;
    Issue = false;
  }

  /// EmitInstruction - This callback is invoked when an instruction is
  /// emitted, to advance the hazard state.
  void EmitInstruction(SUnit *SU) override {
    RegMask.reset();
    Issue = true;
    SelI = SU->getInstr()->getOpcode() == RL78::SEL;
    // SU->getInstr()->dump();
    for (unsigned i = 0; i < SU->getInstr()->getNumOperands(); ++i) {
      if (SU->getInstr()->getOperand(i).isReg() &&
          SU->getInstr()->getOperand(i).isDef()) {
        switch (SU->getInstr()->getOperand(i).getReg().id()) {
        case RL78::R0:
        case RL78::R1:
        case RL78::R2:
        case RL78::R3:
        case RL78::R4:
        case RL78::R5:
        case RL78::R6:
        case RL78::R7:
          RegMask.set(SU->getInstr()->getOperand(i).getReg().id() - RL78::R0);
          break;
        case RL78::RP0:
        case RL78::RP2:
        case RL78::RP4:
        case RL78::RP6:
          RegMask.set(SU->getInstr()->getOperand(i).getReg().id() - RL78::RP0);
          RegMask.set(SU->getInstr()->getOperand(i).getReg().id() - RL78::RP0 +
                      1);
          break;
        case RL78::SPreg:
          RegMask.set(SP);
          break;
        case RL78::CS:
          RegMask.set(CS);
          break;
        }
      }
    }
  }

  /// AdvanceCycle - This callback is invoked whenever the next top-down
  /// instruction to be scheduled cannot issue in the current cycle, either
  /// because of latency or resource conflicts.  This should increment the
  /// internal state of the hazard recognizer so that previously "Hazard"
  /// instructions will now not be hazards.
  void AdvanceCycle() override {
    RegMask.reset();
    SelI = false;
    Issue = false;
  }

  /// getHazardType - Return the hazard type of emitting this node.  There are
  /// three possible results.  Either:
  ///  * NoHazard: it is legal to issue this instruction on this cycle.
  ///  * Hazard: issuing this instruction would stall the machine.  If some
  ///     other instruction is available, issue it first.
  ///  * NoopHazard: issuing this instruction would break the program.  If
  ///     some other instruction can be issued, do so, otherwise issue a noop.
  HazardType getHazardType(SUnit *m, int Stalls = 0) {
    switch (m->getInstr()->getOpcode()) {
    case RL78::BR_AX: {
      BitVector AX(2, true);
      if (SelI || RegMask.anyCommon(AX) || RegMask.test(CS))
        return Hazard;
      return NoHazard;
    }
    case RL78::CALL_rp:
    case RL78::CALL_cs_rp:
    case RL78::CALL_rp_fp: {
      BitVector Bank0(8, true);
      if (SelI || RegMask.anyCommon(Bank0) || RegMask.test(CS) ||
          RegMask.test(SP))
        return Hazard;
      return NoHazard;
    }
    case RL78::PUSH_cc:
    case RL78::PUSH_rp:
    case RL78::POP_cc:
    case RL78::POP_rp:
    case RL78::BRK:
    case RL78::LOAD8_r_stack_slot:
    case RL78::LOAD16_rp_stack_slot:
    case RL78::STORE8_stack_slot_r:
    case RL78::STORE16_stack_slot_rp:
      if (RegMask.test(SP))
        return Hazard;
      return NoHazard;
    }
    if (m->getInstr()->isCall() || m->getInstr()->isReturn()) {
      if (RegMask.test(SP))
        return Hazard;
    }
    if (m->getInstr()->mayLoad() && (m->getInstr()->getNumOperands() >= 2) &&
        m->getInstr()->getOperand(1).isReg()) {
      switch (m->getInstr()->getOperand(1).getReg().id()) {
      case RL78::R2:
      case RL78::R3:
      case RL78::R4:
      case RL78::R5:
      case RL78::R6:
      case RL78::R7:
        if (SelI ||
            RegMask.test(m->getInstr()->getOperand(1).getReg().id() - RL78::R0))
          return Hazard;
        return NoHazard;
      case RL78::RP2:
      case RL78::RP4:
      case RL78::RP6:
        if (SelI ||
            RegMask.test(m->getInstr()->getOperand(1).getReg().id() -
                         RL78::RP0) ||
            RegMask.test(m->getInstr()->getOperand(1).getReg().id() -
                         RL78::RP0 + 1))
          return Hazard;
        return NoHazard;
      }
    }
    if (m->getInstr()->mayStore() && (m->getInstr()->getNumOperands() >= 1) &&
        m->getInstr()->getOperand(0).isReg()) {
      switch (m->getInstr()->getOperand(0).getReg().id()) {
      case RL78::R2:
      case RL78::R3:
      case RL78::R4:
      case RL78::R5:
      case RL78::R6:
      case RL78::R7:
        if (SelI ||
            RegMask.test(m->getInstr()->getOperand(0).getReg().id() - RL78::R0))
          return Hazard;
        return NoHazard;
      case RL78::RP2:
      case RL78::RP4:
      case RL78::RP6:
        if (SelI ||
            RegMask.test(m->getInstr()->getOperand(0).getReg().id() -
                         RL78::RP0) ||
            RegMask.test(m->getInstr()->getOperand(0).getReg().id() -
                         RL78::RP0 + 1))
          return Hazard;
        return NoHazard;
      }
    }
    return NoHazard;
  }

  /// ShouldPreferAnother - This callback may be invoked if getHazardType
  /// returns NoHazard. If, even though there is no hazard, it would be better
  /// to schedule another available instruction, this callback should return
  /// true.
  bool ShouldPreferAnother(SUnit *SU) override {
    for (unsigned i = 0; i < SU->getInstr()->getNumOperands(); ++i) {
      // Current Post RA scheduler is top down, If the instruction defines
      // A/AX schedule it as late as possible, this means fewer exchange
      // instructions as we can use A/AX without storing/restoring it.
      // FIXME: expand for the reverse case when A/AX is kill:
      /// schedule it first.
      if (SU->getInstr()->getOperand(i).isReg() &&
          ((SU->getInstr()->getOperand(i).getReg() == RL78::R1) ||
           (SU->getInstr()->getOperand(i).getReg() == RL78::RP0)) &&
          SU->getInstr()->getOperand(i).isDef())
        return true;
    }
    return false;
  }
};

ScheduleHazardRecognizer *RL78InstrInfo::CreateTargetPostRAHazardRecognizer(
    const InstrItineraryData *, const ScheduleDAG *DAG) const {
  return new RL78HazardRecognizer();
}