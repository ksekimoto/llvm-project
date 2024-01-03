//===- RL78.cpp
//------------------------------------------------------------===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "InputFiles.h"
#include "Symbols.h"
#include "SymbolTable.h"
#include "Target.h"
#include "lld/Common/ErrorHandler.h"
#include "llvm/Object/ELF.h"
#include "llvm/Support/Endian.h"

using namespace llvm;
using namespace llvm::ELF;
using namespace llvm::object;
using namespace llvm::support::endian;
using namespace lld;
using namespace lld::elf;

namespace {
class RL78 final : public TargetInfo {
public:
  RL78();
  void relocateOne(uint8_t *Loc, RelType Type, uint64_t Val) const override;
  uint32_t calcEFlags() const override;
  RelExpr getRelExpr(RelType Type, const Symbol &S,
                     const uint8_t *Loc) const override;
  void writePlt(uint8_t *buf, const Symbol &sym,
                uint64_t pltEntryAddr) const override;

private:
  std::stack<uint64_t> relocationStack;
  uint64_t checkAndPop(uint8_t *Loc, RelType Type,  char bitSize = 0, bool isSigned = false, uint64_t adj = 0) const;
  void push(uint8_t *Loc, RelType Type, uint64_t Value) const;
  uint16_t checkAndConvertRAM(uint8_t *Loc, RelType Type, uint64_t Val) const;
};
} // namespace

RL78::RL78() {
  pltEntrySize = 4;
}

static uint32_t getEFlags(InputFile *file) {
  return cast<ObjFile<ELF32LE>>(file)->getObj().getHeader()->e_flags;
}

static bool mergeFlags(uint32_t &mergedFlags, uint32_t newFlags, unsigned flag,
                       const Twine &msg, InputFile *f) {
  if ((mergedFlags & flag) == 0) { // if the merged flag is set to common
    mergedFlags |= (newFlags & flag);
    return true;
  } else if ((newFlags & flag) == 0) { // if the new flag is set to common
    return true;
  } else if ((mergedFlags & flag) !=
             (newFlags & flag)) { // if both are non-common and non-matching
    error(msg + toString(f));
    return false;
  } else {

    return true;
  }
}

uint32_t RL78::calcEFlags() const {
  assert(!objectFiles.empty());
  uint32_t mergedFlags = getEFlags(objectFiles[0]);
  bool mergeSucceeded = true;
  // Verify that all input files have compatible flags
  for (InputFile *f : makeArrayRef(objectFiles).slice(1)) {
    uint32_t newFlags = getEFlags(f);
    if (mergedFlags == newFlags)
      continue;

    mergedFlags |= (newFlags & ELF::EF_RL78_FU_EXIST);
    mergedFlags |= (newFlags & ELF::EF_RL78_EI_EXIST);

    mergeSucceeded &= mergeFlags(mergedFlags, newFlags, ELF::EF_RL78_MAA_1,
                                 "incompatible MAA flags: ", f);

    if ((mergedFlags & ELF::EF_RL78_CPU_16BIT) == 0) {
      if ((newFlags & ELF::EF_RL78_CPU_16BIT) == 0) {
        error("CPU flag can't be set to common for both input files: " +
              toString(f));
        mergeSucceeded = false;
      } else {
        mergedFlags |= (newFlags & ELF::EF_RL78_CPU_16BIT);
      }
    } else if ((newFlags & ELF::EF_RL78_CPU_16BIT) != 0 &&
               (mergedFlags & ELF::EF_RL78_CPU_16BIT) !=
                   (newFlags & ELF::EF_RL78_CPU_16BIT)) {
      error("incompatible CPU flags: " + toString(f));
      mergeSucceeded = false;
    }

    // TODO change to size 8 if force option is specified
    mergeSucceeded &= mergeFlags(mergedFlags, newFlags, ELF::EF_RL78_DOUBLE_8,
                                 "incompatible double type size flags: ", f);

    // TODO change to far if force option is specified
    mergeSucceeded &= mergeFlags(mergedFlags, newFlags, ELF::EF_RL78_TEXT_FAR,
                                 "incompatible text area flags: ", f);

    // TODO change to far if force option is specified
    mergeSucceeded &= mergeFlags(mergedFlags, newFlags, ELF::EF_RL78_DATA_FAR,
                                 "incompatible data area flags: ", f);

    if ((mergedFlags & ELF::EF_RL78_RODATA_FAR) == 0) {
      mergedFlags |= (newFlags & ELF::EF_RL78_RODATA_FAR);
    } else if ((newFlags & ELF::EF_RL78_RODATA_FAR) != 0 &&
               (mergedFlags & ELF::EF_RL78_RODATA_FAR) !=
                   (newFlags & ELF::EF_RL78_RODATA_FAR)) {
      warn("incompatible rodata area flags, changed to far:  " + toString(f));
      mergedFlags |= (newFlags & ELF::EF_RL78_RODATA_FAR);
    }
  }
  return mergeSucceeded ? mergedFlags : 0;
}

RelExpr RL78::getRelExpr(RelType Type, const Symbol &S,
                         const uint8_t *Loc) const {
  switch (Type) {
  case R_RL78_DIR8S_PCREL:
  case R_RL78_DIR16S_PCREL:
  case R_RL78_ABS8S_PCREL:
  case R_RL78_ABS16S_PCREL:
    return R_PC;
  default:
    return R_ABS;
  }
}

void RL78::writePlt(uint8_t *buf, const Symbol &sym,
                uint64_t pltEntryAddr) const {
  write32le(buf, 0x000000EC | ((sym.getVA() & 0xFFFFF) << 8));
}

inline void write3le(void *P, uint8_t V) {
  write<uint8_t, llvm::support::little>(
      P, (read<uint8_t, llvm::support::little>(P) & 0x8f) | ((V & 0x7) << 4));
}

inline void write8le(void *P, uint8_t V) {
  write<uint8_t, llvm::support::little>(P, V);
}

inline void write24le(void *P, uint64_t V) {
  write32le(P, (read32le(P) & 0xff00'0000) | (V & ~0xff00'0000));
}

static uint64_t checkAndConvertMirrorAddr(uint8_t *Loc, RelType Type,
                                          uint64_t Val, bool AllowOutOfRange = false) {
  // clang-format off
  /*
  RL78-S1 core
    MAA = 0: Mirror data in addresses 00000H to 05EFFH to addresses F8000H to FDEFFH.
    MAA = 1: Setting prohibited. 
  RL78-S2 core 
    MAA = 0: Mirror data in addresses 00000H to 0FFFFH to addresses F0000H to FFFFFH. 
    MAA = 1: Mirror data in addresses 10000H to 1FFFFH to addresses F0000H to FFFFFH. 
  RL78-S3 core 
    MAA = 0: Mirror data in addresses 00000H to 0FFFFH to addresses F0000H to FFFFFH.
    MAA = 1: Mirror data in addresses 10000H to 1FFFFH to addresses F0000H to FFFFFH.
  */
  // clang-format on

  ErrorPlace errPlace = getErrorPlace(Loc);
  uint32_t maaFlag = config->eflags & ELF::EF_RL78_MAA_1;
  uint32_t cpuType = config->eflags & ELF::EF_RL78_CPU_16BIT;

  uint32_t max;
  uint32_t min;
  uint32_t correction;

  if (maaFlag == 0) {
    // code should not depend on MAA mode, yet it does
    error(errPlace.loc + "relocation " + lld::toString(Type) +
          " is invalid when MAA mode flag in ELF is set to common!");
    return 0;
  }
  if (cpuType == 0) {
    // need to know CPU bitness, cause there are different mirror regions for S1
    // and S2/S3
    error(errPlace.loc + "relocation " + lld::toString(Type) +
          " is invalid when CPU bit flag in ELF is set to common!");
    return 0;
  }
  if (cpuType == ELF::EF_RL78_CPU_8BIT && maaFlag == ELF::EF_RL78_MAA_1) {
    // RL78-S1 core   MAA = 1: Setting prohibited.
    error(errPlace.loc + "relocation " + lld::toString(Type) +
          "error: S1 cores can't have MAA set to 1!");
    return 0;
  }

  switch (maaFlag) {
  case EF_RL78_MAA_0: // MAA = 0
    min = 0;
    max = cpuType == ELF::EF_RL78_CPU_8BIT ? 0x5EFF : 0xFFFF;
    correction = cpuType == 1 ? 0xF8000 : 0xF0000;
    break;
  case EF_RL78_MAA_1: // MAA = 1
    min = 0x10000;
    max = 0x1FFFF;
    correction = 0xE0000;
    break;
  default:
    error(errPlace.loc + "relocation " + lld::toString(Type) +
          " invalid MAA flag value!");
    return 0;
    break;
  }

  if (Val >= min && Val <= max) {
    return Val + correction;
  } else if(AllowOutOfRange){
	// return it unchanged, used for R_RL78_OPmir
    return Val;
  } else {
    errorOrWarn(errPlace.loc + "relocation " + lld::toString(Type) +
                " out of MIRROR range: " + Twine::utohexstr(Val).str() + " is not in [" +
                Twine::utohexstr(min).str() + ", " + Twine::utohexstr(max).str() + "]");
    return 0;
  }
}

static uint8_t checkAndConvertSAddr(uint8_t *Loc, RelType Type, uint64_t Val) {
  ErrorPlace errPlace = getErrorPlace(Loc);
  uint32_t max1 = 0xff1f;
  uint32_t min1 = 0xfe20;
  uint32_t max2 = 0xfff1f;
  uint32_t min2 = 0xffe20;
  if (Val >= min1 && Val <= max1 || Val >= min2 && Val <= max2) {
    return Val;
  } else {
    error(errPlace.loc + "relocation " + lld::toString(Type) +
          " out of SADDR(P) range: " + Twine(Val).str() + " is not in [" +
          Twine::utohexstr(min1).str() + ", " + Twine::utohexstr(max1).str() + "] or [" +
          Twine::utohexstr(min2).str() + ", " + Twine::utohexstr(max2).str() + "]");
    return 0;
  }
}

uint16_t RL78::checkAndConvertRAM(uint8_t *Loc, RelType Type, uint64_t Val) const {
  ErrorPlace errPlace = getErrorPlace(Loc);
  uint32_t max = 0xffeff;
  uint32_t min = 0xfef00;

  Symbol *minRamAddrSym = symtab->find("__data");
  if (minRamAddrSym != nullptr) {
    min = minRamAddrSym->getVA(0);
  }

  if (Val >= min && Val <= max) {
    return Val;
  } else {
    error(errPlace.loc + "relocation " + lld::toString(Type) +
          " out of RAM range: " + Twine::utohexstr(Val).str() + " is not in [" +
          Twine::utohexstr(min).str() + ", " + Twine::utohexstr(max).str() + "]");
    return 0;
  }
}

uint64_t RL78::checkAndPop(uint8_t *Loc, RelType Type, char bitSize, bool isSigned, uint64_t adj) const {
  if (relocationStack.empty()) {
    error(getErrorPlace(Loc).loc + "relocation " + lld::toString(Type) +
          " is invalid: linker relocation stack is empty, nothing to pop!");
    return 0;
  } else {
    uint64_t t = relocationStack.top() - adj;

    if(bitSize > 0) {
      if(isSigned) {
        checkInt(Loc,t,bitSize,Type);
      } else {
        checkUInt(Loc,t,bitSize,Type);
      }
    }
    
    const_cast<RL78 *>(this)->relocationStack.pop();
    return t;
  }
}

void RL78::push(uint8_t *Loc, RelType Type, uint64_t Value) const {
  const_cast<RL78 *>(this)->relocationStack.push(Value);
}

void RL78::relocateOne(uint8_t *Loc, RelType Type, uint64_t Val) const {
  // TODO Not sure if zero refers to boot cluster 0?
  // also if these addresses are target specific?
  uint32_t zeroCALLTST = 0x00080;
  uint32_t CALLTST = 0x01080;

  switch (Type) {
  case R_RL78_DIR3U:
    checkUInt(Loc, Val, 3, Type);
    write3le(Loc, Val);
    break;
  case R_RL78_DIR8U:
    checkUInt(Loc, Val, 8, Type);
    write8le(Loc, Val);
    break;
  case R_RL78_DIR16U:
    //checkUInt(Loc, Val, 16, Type); - temporary revert
    write16le(Loc, Val);
    break;
  case R_RL78_DIR20U:
    checkUInt(Loc, Val, 20, Type);
    write24le(Loc, Val);
    break;
  case R_RL78_DIR20U_16:
    checkUInt(Loc, Val, 20, Type);
    write16le(Loc, Val);
    break;
  case R_RL78_DIR20UW_16:
    checkUInt(Loc, Val, 20, Type);
    write16le(Loc, Val & 0xfffe);
    break;
  case R_RL78_DIR32U:
    checkUInt(Loc, Val, 32, Type);
    write32le(Loc, Val);
    break;
  case R_RL78_DIR8U_MIR:
    write8le(Loc, checkAndConvertMirrorAddr(Loc, Type, Val));
    break;
  case R_RL78_DIR16U_MIR:
    write16le(Loc, checkAndConvertMirrorAddr(Loc, Type, Val));
    break;
  case R_RL78_DIR16UW_MIR:
    write16le(Loc, checkAndConvertMirrorAddr(Loc, Type, Val) & 0xfffe);
    break;
  case R_RL78_DIR8U_SAD:
    write8le(Loc, checkAndConvertSAddr(Loc, Type, Val) & 0xff);
    break;
  case R_RL78_DIR8UW_SAD:
    write8le(Loc, checkAndConvertSAddr(Loc, Type, Val) & 0xfe);
    break;
  case R_RL78_DIR16U_RAM:
    write16le(Loc, checkAndConvertRAM(Loc, Type, Val) & 0xffff);
    break;
  case R_RL78_DIR16UW_RAM:
    write16le(Loc, checkAndConvertRAM(Loc, Type, Val) & 0xfffe);
    break;
  case R_RL78_DIR8S_PCREL:
    checkInt(Loc, Val - 1, 8, Type);
    write8le(Loc, Val - 1);
    break;
  case R_RL78_DIR16S_PCREL:
    checkInt(Loc, Val - 2, 16, Type);
    write16le(Loc, Val - 2);
    break;
  case R_RL78_DIR_CALLT:
    write8le(Loc, ((((Val - zeroCALLTST) & 0x30) >> 4) +
                   (((Val - CALLTST) & 0x0e) << 3)) |
                      0x84);
    break;
  case R_RL78_ABS3U:    
    write3le(Loc, checkAndPop(Loc, Type,3));
    break;
  case R_RL78_ABS8U:    
    write8le(Loc, checkAndPop(Loc, Type,8));
    break;
  case R_RL78_ABS8UW:
    write8le(Loc, checkAndPop(Loc, Type,8) & 0xfe);
    break;
  case R_RL78_ABS16U:
    write16le(Loc, checkAndPop(Loc, Type,16));
    break;
  case R_RL78_ABS16UW:
    write16le(Loc, checkAndPop(Loc, Type,16) & 0xfffe);
    break;
  case R_RL78_ABS20U:
    write24le(Loc, checkAndPop(Loc, Type,20));
    break;
  case R_RL78_ABS20U_16:
    write16le(Loc, checkAndPop(Loc, Type,20));
    break;
  case R_RL78_ABS20UW_16:
    write16le(Loc, checkAndPop(Loc, Type,20) & 0xfffe);
    break;
  case R_RL78_ABS32U:
    write32le(Loc, checkAndPop(Loc, Type,32));
    break;
  case R_RL78_ABS8S_PCREL:
    write8le(Loc, (checkAndPop(Loc, Type,8,true, Val) - 1)& 0xff);
    break;
  case R_RL78_ABS16S_PCREL:
    write16le(Loc, (checkAndPop(Loc, Type,16,true, Val) - 2) & 0xffff);
    break;
  case R_RL78_ABS_CALLT: {
    uint64_t savedVal = checkAndPop(Loc, Type);
    write8le(Loc, ((((savedVal - zeroCALLTST) & 0x30) >> 4) +
                   (((savedVal - CALLTST) & 0x0e) << 3)) |
                      0x84);
  } break;
  case R_RL78_REF:
    break;
  case R_RL78_SYM:
    push(Loc, Type, Val);
    break;
  case R_RL78_SYM_MIR:
    push(Loc, Type, checkAndConvertMirrorAddr(Loc, Type, Val));
    break;
  case R_RL78_OPadd: {
    uint64_t a = checkAndPop(Loc, Type);
    uint64_t b = checkAndPop(Loc, Type);
    push(Loc, Type, a + b);
  } break;
  case R_RL78_OPsub: {
    uint64_t a = checkAndPop(Loc, Type);
    uint64_t b = checkAndPop(Loc, Type);
    push(Loc, Type, b - a);
  } break;
  case R_RL78_OPsctsize:
  case R_RL78_OPscttop:
    push(Loc, Type, Val);
    break;
  case R_RL78_OPlowH:
    push(Loc, Type, (Val & 0xFF00) >> 8);
    break;
  case R_RL78_OPlowL:
    push(Loc, Type, Val & 0xff);
    break;
  case R_RL78_OPhighW:
    push(Loc, Type, (Val & 0xFFFF0000) >> 16);
    break;
  case R_RL78_OPlowW:
    //TODO currently we incorrectly use this for constant references too, it should be R_RL78_OPlowW_MIR
    //one possible solution to this might be at ISelLowering::makeaddress, where we would insert a different node to signal that 
    //it should be a constant access from the rom/mirror area
    push(Loc, Type, Val & 0xFFFF);
    break;
  case R_RL78_OPhighW_MIR:
    push(Loc, Type, (checkAndConvertMirrorAddr(Loc, Type, Val) & 0xFFFF0000) >> 16);
    break;
  case R_RL78_OPlowW_MIR:
  case R_RL78_OPlowW_SMIR://TODO this might be wrong PUSH (MIR(S)+ A) & 0xFFFF
    push(Loc, Type, checkAndConvertMirrorAddr(Loc, Type, Val) & 0xFFFF);
    break;   
  case R_RL78_OPmir: {
    uint64_t T = checkAndPop(Loc, Type);
    push(Loc, Type, checkAndConvertMirrorAddr(Loc, Type, T, true));
  } break;   
  case R_RL78_OPABSlowH:
    push(Loc, Type, (checkAndPop(Loc, Type) & 0xFF00) >> 8);
    break;
  case R_RL78_OPABSlowL:
    push(Loc, Type, checkAndPop(Loc, Type) & 0xFF);
    break;
  case R_RL78_OPABShighW:
    push(Loc, Type, (checkAndPop(Loc, Type) & 0xFFFF0000) >> 16);
    break;
  case R_RL78_OPABSlowW:
    push(Loc, Type, checkAndPop(Loc, Type) & 0xFFFF);
    break;
  default:
    error(getErrorLocation(Loc) + "unrecognized relocation " + Twine(Type));
  }
}

TargetInfo *elf::getRL78TargetInfo() {
  static RL78 Target;
  return &Target;
}
