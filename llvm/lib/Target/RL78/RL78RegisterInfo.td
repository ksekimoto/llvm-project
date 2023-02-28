//===-- RL78RegisterInfo.td - RL78 Register defs ---------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//  Declarations that describe the RL78 register file
//===----------------------------------------------------------------------===//

class RL78Register<string n, bits<6> num, list<string> altNames = []> : Register<n, altNames> {
  field bits<6> Num = num;
  let Namespace = "RL78";
}

let Namespace = "RL78" in {
  def BankRegAltName : RegAltNameIndex;
}

def R0 : RL78Register<"X", 0, []>, DwarfRegNum<[0]>;
def R1 : RL78Register<"A", 1, []>, DwarfRegNum<[1]>;
def R2 : RL78Register<"C", 2, []>, DwarfRegNum<[2]>;
def R3 : RL78Register<"B", 3, []>, DwarfRegNum<[3]>;
def R4 : RL78Register<"E", 4, []>, DwarfRegNum<[4]>;
def R5 : RL78Register<"D", 5, []>, DwarfRegNum<[5]>;
def R6 : RL78Register<"L", 6, []>, DwarfRegNum<[6]>;
def R7 : RL78Register<"H", 7, []>, DwarfRegNum<[7]>;

let RegAltNameIndices = [BankRegAltName] in {
def R8 : RL78Register<"R8", 8, ["X"]>, DwarfRegNum<[8]>;
def R9 : RL78Register<"R9", 9, ["A"]>, DwarfRegNum<[9]>;
def R10 : RL78Register<"R10", 10, ["C"]>, DwarfRegNum<[10]>;
def R11 : RL78Register<"R11", 11, ["B"]>, DwarfRegNum<[11]>;
def R12 : RL78Register<"R12", 12, ["E"]>, DwarfRegNum<[12]>;
def R13 : RL78Register<"R13", 13, ["D"]>, DwarfRegNum<[13]>;
def R14 : RL78Register<"R14", 14, ["L"]>, DwarfRegNum<[14]>;
def R15 : RL78Register<"R15", 15, ["H"]>, DwarfRegNum<[15]>;
def R16 : RL78Register<"R16", 16, ["X"]>, DwarfRegNum<[16]>;
def R17 : RL78Register<"R17", 17, ["A"]>, DwarfRegNum<[17]>;
def R18 : RL78Register<"R18", 18, ["C"]>, DwarfRegNum<[18]>;
def R19 : RL78Register<"R19", 19, ["B"]>, DwarfRegNum<[19]>;
def R20 : RL78Register<"R20", 20, ["E"]>, DwarfRegNum<[20]>;
def R21 : RL78Register<"R21", 21, ["D"]>, DwarfRegNum<[21]>;
def R22 : RL78Register<"R22", 22, ["L"]>, DwarfRegNum<[22]>;
def R23 : RL78Register<"R23", 23, ["H"]>, DwarfRegNum<[23]>;
def R24 : RL78Register<"R24", 24, ["X"]>, DwarfRegNum<[24]>;
def R25 : RL78Register<"R25", 25, ["A"]>, DwarfRegNum<[25]>;
def R26 : RL78Register<"R26", 26, ["C"]>, DwarfRegNum<[26]>;
def R27 : RL78Register<"R27", 27, ["B"]>, DwarfRegNum<[27]>;
def R28 : RL78Register<"R28", 28, ["E"]>, DwarfRegNum<[28]>;
def R29 : RL78Register<"R29", 29, ["D"]>, DwarfRegNum<[29]>;
def R30 : RL78Register<"R30", 30, ["L"]>, DwarfRegNum<[30]>;
def R31 : RL78Register<"R31", 31, ["H"]>, DwarfRegNum<[31]>;
}
let Namespace = "RL78" in {
def ES : Register<"es">;
def CS : Register<"cs">;
def CY : Register<"cy">;
def PSW : Register<"psw">;
def PMC : Register<"pmc">;
def MEM : Register<"mem">;
def SPL : Register<"spl">;
def SPH : Register<"sph">;
}

def RL78RegES : RegisterClass<"RL78", [i8], 8, (add ES)>;
def RL78RegCS : RegisterClass<"RL78", [i8], 8, (add CS)>;
def RL78RegCY : RegisterClass<"RL78", [i8], 8, (add CY)>; 

def RL78RegPSW : RegisterClass<"RL78", [i8], 8, (add PSW)>; 
def RL78RegPMC : RegisterClass<"RL78", [i8], 8, (add PMC)>; 
def RL78RegMEM : RegisterClass<"RL78", [i8], 8, (add MEM)>; 
def RL78RegSPL : RegisterClass<"RL78", [i8], 8, (add SPL)>; 
def RL78RegSPH : RegisterClass<"RL78", [i8], 8, (add SPH)>; 

def RL78SfrReg : RegisterClass<"RL78", [i8], 16, (add SPL, SPH, PSW, CS, ES, PMC, MEM)>;

def RL78Reg : RegisterClass<"RL78", [i8], 8, (add R1, R0, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15, 
  R16, R17, R18, R19, R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30, R31)>;

def RL78RExceptBank0 : RegisterClass<"RL78", [i8], 8, (add R8, R9, R10, R11, R12, R13, R14, R15, 
  R16, R17, R18, R19, R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30, R31)>;

def RL78OddReg : RegisterClass<"RL78", [i8], 8, (add R1, R3, R5, R7, R9, R11, R13, R15, 
  R17, R19, R21, R23, R25, R27, R29, R31)>;

def RL78AReg : RegisterClass<"RL78", [i8], 8, (add R1)>;
//used for MULU
def RL78XReg : RegisterClass<"RL78", [i8], 8, (add R0)>;

//used of SHL
def RL78ABCReg : RegisterClass<"RL78", [i8], 8, (add R1, R2, R3)>;

def RL78BCEDHLReg : RegisterClass<"RL78", [i8], 8, (add R2, R3, R4, R5, R6, R7)>;

def RL78XBCEDHLReg : RegisterClass<"RL78", [i8], 8, (add R0, R2, R3, R4, R5, R6, R7)>;

//this is for ADDrr
def RL78BCReg : RegisterClass<"RL78", [i8], 8, (add R2, R3)>;

def RL78BCXReg : RegisterClass<"RL78", [i8], 8, (add R0, R2, R3)>;


def RL78Bank0Reg : RegisterClass<"RL78", [i8], 8, (add R0, R1, R2, R3, R4, R5, R6, R7)>;

def RL78Bank0Lo : RegisterClass<"RL78", [i8], 8, (add R1, R0, R2, R3)>;

def RL78Bank0Hi : RegisterClass<"RL78", [i8], 8, (add R4, R5, R6, R7)>;

let Namespace = "RL78" in
{
  def sub_lo : SubRegIndex<8>;
  def sub_hi : SubRegIndex<8, 8>;
}

class RL78RPReg<string n, bits<6> num, list<Register> subregs, list<string> altNames = []> : RL78Register<n, num, altNames> {
  let SubRegs = subregs;
  let SubRegIndices = [sub_lo, sub_hi];
}

def RP0 : RL78RPReg<"AX", 0, [R0, R1], []>, DwarfRegNum<[0]>;
def RP2 : RL78RPReg<"BC", 2, [R2, R3], []>, DwarfRegNum<[2]>;
def RP4 : RL78RPReg<"DE", 4, [R4, R5], []>, DwarfRegNum<[4]>;
def RP6 : RL78RPReg<"HL", 6, [R6, R7], []>, DwarfRegNum<[6]>;

let RegAltNameIndices = [BankRegAltName] in {
def RP8 : RL78RPReg<"R8", 8, [R8, R9], ["AX"]>, DwarfRegNum<[8]>;
def RP10 : RL78RPReg<"R10", 10, [R10, R11], ["BC"]>, DwarfRegNum<[10]>;
def RP12 : RL78RPReg<"R12", 12, [R12, R13], ["DE"]>, DwarfRegNum<[12]>;
def RP14 : RL78RPReg<"R14", 14, [R14, R15], ["HL"]>, DwarfRegNum<[14]>;

def RP16 : RL78RPReg<"R16", 16, [R16, R17], ["AX"]>, DwarfRegNum<[16]>;
def RP18 : RL78RPReg<"R18", 18, [R18, R19], ["BC"]>, DwarfRegNum<[18]>;
def RP20 : RL78RPReg<"R20", 20, [R20, R21], ["DE"]>, DwarfRegNum<[20]>;
def RP22 : RL78RPReg<"R22", 22, [R22, R23], ["HL"]>, DwarfRegNum<[22]>;

def RP24 : RL78RPReg<"R24", 24, [R24, R25], ["AX"]>, DwarfRegNum<[24]>;
def RP26 : RL78RPReg<"R26", 26, [R26, R27], ["BC"]>, DwarfRegNum<[26]>;
def RP28 : RL78RPReg<"R28", 28, [R28, R29], ["DE"]>, DwarfRegNum<[28]>;
def RP30 : RL78RPReg<"R30", 30, [R30, R31], ["HL"]>, DwarfRegNum<[30]>;
}

def RL78RPRegs : RegisterClass<"RL78", [i16], 16, (add RP0, RP2, RP4, RP6, RP8, RP10, RP12, RP14, RP16, RP18, RP20, RP22, RP24, RP26, RP28, RP30)>;

def RL78AXRP : RegisterClass<"RL78", [i16], 16, (add RP0)>;

def RL78AXBCRP : RegisterClass<"RL78", [i16], 16, (add RP0, RP2)>;

//this is for ADDRri and ADDrr
def RL78BCDEHL : RegisterClass<"RL78", [i16], 16, (add RP6, RP4, RP2)>;
def RL78HL : RegisterClass<"RL78", [i16], 16, (add RP6)>;

def SPreg : RL78Register<"SP", 32>, DwarfRegNum<[32]>;
def CCreg : RL78Register<"CC", 34>;
def Zflag : RL78Register<"Z", 35>;

def RL78SPReg : RegisterClass<"RL78", [i16], 16, (add SPreg)>;
def RL78CCReg : RegisterClass<"RL78", [i8], 8, (add CCreg)>;

def PCreg : RL78Register<"PC", 37>, DwarfRegNum<[37]>;
