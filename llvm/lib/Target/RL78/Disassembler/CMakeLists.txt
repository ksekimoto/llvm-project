add_llvm_component_library(LLVMRL78Disassembler
  RL78Disassembler.cpp

  LINK_COMPONENTS
  MC
  MCDisassembler
  RL78Info
  RL78Desc
  Support
  
  ADD_TO_COMPONENT
  RL78

  )
