//==- llvm/lib/Target/RL78/RL78SelectionDAGTargetInfo.h - RL78 SelectionDAG Info
//--*- C++ -*-==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------------------------===//
//
// This file implements the RL78 specific subclass of SelectionDAGTargetInfo.
//
//===---------------------------------------------------------------------------------------===//

#include "RL78SelectionDAGTargetInfo.h"
#include "RL78.h"
#include "llvm/CodeGen/TargetLowering.h"

using namespace llvm;

RL78SelectionDAGTargetInfo::~RL78SelectionDAGTargetInfo() = default;

SDValue RL78SelectionDAGTargetInfo::EmitTargetCodeForMemcpy(
    SelectionDAG &DAG, const SDLoc &dl, SDValue Chain, SDValue Op1, SDValue Op2,
    SDValue Op3, unsigned Align, bool isVolatile, bool AlwaysInline,
    MachinePointerInfo DstPtrInfo, MachinePointerInfo SrcPtrInfo) const {
  if (AlwaysInline)
    return SDValue();

  // FIXME: If the memcpy is volatile (isVol), lowering it to a plain libc
  // memcpy is not guaranteed to be safe. libc memcpys aren't required to
  // respect volatile, so they may do things like read or write memory
  // beyond the given memory regions. But fixing this isn't easy, and most
  // people don't care.

  // Emit a library call.
  TargetLowering::ArgListTy Args;
  TargetLowering::ArgListEntry Entry;
  Entry.Ty = Type::getInt8PtrTy(*DAG.getContext(), DstPtrInfo.getAddrSpace());
  Entry.Node = Op1;
  Args.push_back(Entry);
  Entry.Node = Op2;
  Args.push_back(Entry);

  Entry.Ty = DAG.getDataLayout().getIntPtrType(*DAG.getContext());
  Entry.Node = Op3;
  Args.push_back(Entry);
  const char *libcallName =
      DstPtrInfo.getAddrSpace() == RL78AS::Far
          ? "_COM_memcpy_ff"
          : DAG.getTargetLoweringInfo().getLibcallName(RTLIB::MEMCPY);
  // FIXME: pass in SDLoc
  TargetLowering::CallLoweringInfo CLI(DAG);
  CLI.setDebugLoc(dl)
      .setChain(Chain)
      .setLibCallee(
          DAG.getTargetLoweringInfo().getLibcallCallingConv(RTLIB::MEMCPY),
          Op1.getValueType().getTypeForEVT(*DAG.getContext()),
          DAG.getExternalSymbol(
              libcallName, DAG.getTargetLoweringInfo().getPointerTy(
                               DAG.getDataLayout(),
                               DAG.getDataLayout().getProgramAddressSpace())),
          std::move(Args))
      .setDiscardResult();

  std::pair<SDValue, SDValue> CallResult =
      DAG.getTargetLoweringInfo().LowerCallTo(CLI);
  return CallResult.second;
}

SDValue RL78SelectionDAGTargetInfo::EmitTargetCodeForMemmove(
    SelectionDAG &DAG, const SDLoc &dl, SDValue Chain, SDValue Op1, SDValue Op2,
    SDValue Op3, unsigned Align, bool isVolatile, MachinePointerInfo DstPtrInfo,
    MachinePointerInfo SrcPtrInfo) const {

  // FIXME: If the memmove is volatile, lowering it to plain libc memmove may
  // not be safe.  See memcpy above for more details.

  // Emit a library call.
  TargetLowering::ArgListTy Args;
  TargetLowering::ArgListEntry Entry;
  Entry.Ty = Type::getInt8PtrTy(*DAG.getContext(), DstPtrInfo.getAddrSpace());
  Entry.Node = Op1;
  Args.push_back(Entry);
  Entry.Node = Op2;
  Args.push_back(Entry);

  Entry.Ty = DAG.getDataLayout().getIntPtrType(*DAG.getContext());
  Entry.Node = Op3;
  Args.push_back(Entry);
  const char *libcallName =
      DstPtrInfo.getAddrSpace() == RL78AS::Far
          ? "_COM_memmove_ff"
          : DAG.getTargetLoweringInfo().getLibcallName(RTLIB::MEMMOVE);
  // FIXME:  pass in SDLoc
  TargetLowering::CallLoweringInfo CLI(DAG);
  CLI.setDebugLoc(dl)
      .setChain(Chain)
      .setLibCallee(
          DAG.getTargetLoweringInfo().getLibcallCallingConv(RTLIB::MEMMOVE),
          Op1.getValueType().getTypeForEVT(*DAG.getContext()),
          DAG.getExternalSymbol(
              libcallName, DAG.getTargetLoweringInfo().getPointerTy(
                               DAG.getDataLayout(),
                               DAG.getDataLayout().getProgramAddressSpace())),
          std::move(Args))
      .setDiscardResult();

  std::pair<SDValue, SDValue> CallResult =
      DAG.getTargetLoweringInfo().LowerCallTo(CLI);
  return CallResult.second;
}

SDValue RL78SelectionDAGTargetInfo::EmitTargetCodeForMemset(
    SelectionDAG &DAG, const SDLoc &dl, SDValue Chain, SDValue Op1, SDValue Op2,
    SDValue Op3, unsigned Align, bool isVolatile,
    MachinePointerInfo DstPtrInfo) const {

  // Emit a library call.
  TargetLowering::ArgListTy Args;
  TargetLowering::ArgListEntry Entry;
  Entry.Node = Op1;
  Entry.Ty = Type::getInt8PtrTy(*DAG.getContext(), DstPtrInfo.getAddrSpace());
  Args.push_back(Entry);
  Entry.Node = Op2;
  // Here we pass it as i16, despite only the low i8 part being used
  Entry.Ty =
      EVT::getIntegerVT(*DAG.getContext(), 16).getTypeForEVT(*DAG.getContext());
  Args.push_back(Entry);
  Entry.Node = Op3;
  Entry.Ty = DAG.getDataLayout().getIntPtrType(*DAG.getContext());
  Args.push_back(Entry);
  const char *libcallName =
      DstPtrInfo.getAddrSpace() == RL78AS::Far
          ? "_COM_memset_f"
          : DAG.getTargetLoweringInfo().getLibcallName(RTLIB::MEMSET);
  // FIXME: pass in SDLoc
  TargetLowering::CallLoweringInfo CLI(DAG);
  CLI.setDebugLoc(dl)
      .setChain(Chain)
      .setLibCallee(
          DAG.getTargetLoweringInfo().getLibcallCallingConv(RTLIB::MEMSET),
          Op1.getValueType().getTypeForEVT(*DAG.getContext()),
          DAG.getExternalSymbol(
              libcallName, DAG.getTargetLoweringInfo().getPointerTy(
                               DAG.getDataLayout(),
                               DAG.getDataLayout().getProgramAddressSpace())),
          std::move(Args))
      .setDiscardResult();

  std::pair<SDValue, SDValue> CallResult =
      DAG.getTargetLoweringInfo().LowerCallTo(CLI);
  return CallResult.second;
}