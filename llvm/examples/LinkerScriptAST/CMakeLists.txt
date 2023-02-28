set(LLVM_LINK_COMPONENTS
  Support
  )

add_llvm_example(LinkerScriptAST
  LinkerScriptParser.cpp
  )

if(LLVM_COMPILER_IS_GCC_COMPATIBLE)
  target_compile_options(LinkerScriptAST PRIVATE
    -Wno-unused-private-field
    )
endif()

if(MSVC)
  # ignore "warning LNK4199: /DELAYLOAD:shell32.dll ignored; no imports found from shell32.dll"
  target_link_libraries(LinkerScriptAST PRIVATE "-ignore:4199")
endif()
