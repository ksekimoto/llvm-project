; RUN: llc < %s -march=RL78 | FileCheck %s

define i8 @add8_reg_imm(i8 %a) {
; CHECK-LABEL: add8_reg_imm:
; CHECK: add a, #5
    %result = add i8 %a, 5
    ret i8 %result
}

define i8 @add8_reg_reg(i8 %a, i8 %b) {
; CHECK-LABEL: add8_reg_reg:
; CHECK: add a, x
    %result = add i8 %a, %b
    ret i8 %result
}
