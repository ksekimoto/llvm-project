//===--- RL78.cpp - RL78 ToolChain Implementations ------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RL78.h"
#include "CommonArgs.h"
#include "InputInfo.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Options.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang::driver;
using namespace clang::driver::toolchains;
using namespace clang::driver::tools;
using namespace clang;
using namespace llvm::opt;

static Multilib makeMultilib(StringRef commonSuffix) {
  return Multilib(commonSuffix, commonSuffix, commonSuffix);
}

// RL78 Toolchain
RL78ToolChain::RL78ToolChain(const Driver &D, const llvm::Triple &Triple,
                             const ArgList &Args)
    : BareMetal(D, Triple, Args) {

  // Adding multilibs
  Multilibs.push_back(makeMultilib("s1").flag("+mcpu=s1").flag("+O2").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s1/far-code").flag("+mcpu=s1").flag("+O2").flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s2").flag("+mcpu=s2").flag("+O2").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s2/far-code").flag("+mcpu=s2").flag("+O2").flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s3").flag("+mcpu=s3").flag("+O2").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s3/far-code").flag("+mcpu=s3").flag("+O2").flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s1/Oz").flag("+mcpu=s1").flag("+Oz").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s1/Oz/far-code").flag("+mcpu=s1").flag("+Oz").flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s2/Oz").flag("+mcpu=s2").flag("+Oz").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s2/Oz/far-code").flag("+mcpu=s2").flag("+Oz").flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s3/Oz").flag("+mcpu=s3").flag("+Oz").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s3/Oz/far-code").flag("+mcpu=s3").flag("+Oz").flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s1/64-bit-doubles")
                          .flag("+mcpu=s1")
                          .flag("+m64bit-doubles")
                          .flag("+O2").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s1/64-bit-doubles/far-code")
                          .flag("+mcpu=s1")
                          .flag("+m64bit-doubles")
                          .flag("+O2")
                          .flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s2/64-bit-doubles")
                          .flag("+mcpu=s2")
                          .flag("+m64bit-doubles")
                          .flag("+O2").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s2/64-bit-doubles/far-code")
                          .flag("+mcpu=s2")
                          .flag("+m64bit-doubles")
                          .flag("+O2")
                          .flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s3/64-bit-doubles")
                          .flag("+mcpu=s3")
                          .flag("+m64bit-doubles")
                          .flag("+O2").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s3/64-bit-doubles/far-code")
                          .flag("+mcpu=s3")
                          .flag("+m64bit-doubles")
                          .flag("+O2")
                          .flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s2/disable-mda")
                        .flag("+mcpu=s2")
                        .flag("+mdisable-mda")
                        .flag("+O2").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s2/disable-mda/far-code")
                        .flag("+mcpu=s2")
                        .flag("+mdisable-mda")
                        .flag("+O2")
                        .flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s2/64-bit-doubles/disable-mda")
                          .flag("+mcpu=s2")
                          .flag("+mdisable-mda")
                          .flag("+m64bit-doubles")
                          .flag("+O2").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s2/64-bit-doubles/disable-mda/far-code")
                          .flag("+mcpu=s2")
                          .flag("+mdisable-mda")
                          .flag("+m64bit-doubles")
                          .flag("+O2")
                          .flag("+mfar-code"));


  Multilibs.push_back(makeMultilib("s1/64-bit-doubles/Oz")
                          .flag("+mcpu=s1")
                          .flag("+m64bit-doubles")
                          .flag("+Oz").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s1/64-bit-doubles/Oz/far-code")
                          .flag("+mcpu=s1")
                          .flag("+m64bit-doubles")
                          .flag("+Oz")
                          .flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s2/64-bit-doubles/Oz")
                          .flag("+mcpu=s2")
                          .flag("+m64bit-doubles")
                          .flag("+Oz").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s2/64-bit-doubles/Oz/far-code")
                          .flag("+mcpu=s2")
                          .flag("+m64bit-doubles")
                          .flag("+Oz")
                          .flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s3/64-bit-doubles/Oz")
                          .flag("+mcpu=s3")
                          .flag("+m64bit-doubles")
                          .flag("+Oz").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s3/64-bit-doubles/Oz/far-code")
                          .flag("+mcpu=s3")
                          .flag("+m64bit-doubles")
                          .flag("+Oz")
                          .flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s2/disable-mda/Oz")
                          .flag("+mcpu=s2")
                          .flag("+mdisable-mda")
                          .flag("+Oz").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s2/disable-mda/Oz/far-code")
                          .flag("+mcpu=s2")
                          .flag("+mdisable-mda")
                          .flag("+Oz")
                          .flag("+mfar-code"));

  Multilibs.push_back(makeMultilib("s2/64-bit-doubles/disable-mda/Oz")
                          .flag("+mcpu=s2")
                          .flag("+mdisable-mda")
                          .flag("+m64bit-doubles")
                          .flag("+Oz").flag("+mnear-code"));
  Multilibs.push_back(makeMultilib("s2/64-bit-doubles/disable-mda/Oz/far-code")
                          .flag("+mcpu=s2")
                          .flag("+mdisable-mda")
                          .flag("+m64bit-doubles")
                          .flag("+Oz")
                          .flag("+mfar-code"));
}

// Returns the include path for compiler-rt and clang_rt.crtbegin-rl78.obj
std::string RL78ToolChain::getRuntimesDir(const ArgList &Args) const {
  SmallString<256> Dir(getDriver().ResourceDir);
  llvm::sys::path::append(Dir, "rl78");
  Dir = getSelectedMultilibPath(Dir, Args, true);
  llvm::sys::path::append(Dir, "lib", "baremetal");
  return Dir.str();
}

// Returns path specific for cpu and m64bit_doubles
std::string RL78ToolChain::getSelectedMultilibPath(SmallString<256> Dir,
                                                   const ArgList &Args,
                                                   bool forRT) const {

  // Add specific cpu of the toolchain
  StringRef CPU;
  if (const Arg *A = Args.getLastArg(clang::driver::options::OPT_mcpu_EQ)) {
    CPU = A->getValue();
  } else {
    CPU = "s3";
  }
  llvm::sys::path::append(Dir, CPU.lower());
  // Add m64bit_doubles
  if (const Arg *BitDoubles = Args.getLastArg(options::OPT_m64bit_doubles)) {
    StringRef BitDoublesValue = BitDoubles->getOption().getName();
    llvm::sys::path::append(Dir, "64-bit-doubles");
  }

  // Add mdisable_mda for compiler-rt only
  const Arg *disableMDA = Args.getLastArg(options::OPT_mdisable_mda);
  if (disableMDA) {
    llvm::sys::path::append(Dir, "disable-mda");
  }

  if (const Arg *optimizeOpt = Args.getLastArg(options::OPT_O)) {
    StringRef Opt = optimizeOpt->getValue();
    if (Opt == "s" || Opt == "z") {
      llvm::sys::path::append(Dir, "Oz");
    }
  }

  // Add mfar-code
  const Arg *mCode =
      Args.getLastArg(options::OPT_mnear_code, options::OPT_mfar_code);
  if (/*(mCode == nullptr && CPU.lower() != "s1" &&  !getDriver().CCCIsCXX()) ||*/
      (mCode && mCode->getOption().getID() == options::OPT_mfar_code)) {
    llvm::sys::path::append(Dir, "far-code");
  }

  return Dir.str();
}

// Returns the include path for newlib libraries, libunwind libcxx and libcxxabi
std::string RL78ToolChain::getNewlibPath(const ArgList &Args) const {

  SmallString<256> Dir(getDriver().ResourceDir);
  llvm::sys::path::append(Dir, "..", "..");
  llvm::sys::path::append(Dir, "..", getDriver().getTargetTriple());
  llvm::sys::path::append(Dir, "lib");
  Dir = getSelectedMultilibPath(Dir, Args, false);
  return Dir.str();
}

void RL78ToolChain::AddClangSystemIncludeArgs(const ArgList &DriverArgs,
                                              ArgStringList &CC1Args) const {
  if (DriverArgs.hasArg(options::OPT_nostdinc))
    return;

  // Do not search the standard system directories for include cxx files
  if (!DriverArgs.hasArg(options::OPT_nostdlibinc, options::OPT_nostdincxx) &&
      getDriver().CCCIsCXX()) {
    SmallString<256> Dir(getDriver().ResourceDir);
    llvm::sys::path::append(Dir, "..", "..");
    llvm::sys::path::append(Dir, "..", getDriver().getTargetTriple());
    llvm::sys::path::append(Dir, "include");
    llvm::sys::path::append(Dir, "c++", "v1");
    addSystemInclude(DriverArgs, CC1Args, Dir.str());
  }

  // Disable builtin #include directories
  if (!DriverArgs.hasArg(options::OPT_nobuiltininc)) {
    SmallString<256> Dir(getDriver().ResourceDir);
    llvm::sys::path::append(Dir, "include");
    addSystemInclude(DriverArgs, CC1Args, Dir.str());
  }
  // Do not search the standard system directories for include files,
  // but do search compiler builtin include directories
  if (!DriverArgs.hasArg(options::OPT_nostdlibinc)) {
    SmallString<256> Dir(getDriver().ResourceDir);
    llvm::sys::path::append(Dir, "..", "..");
    llvm::sys::path::append(Dir, "..", getDriver().getTargetTriple());
    llvm::sys::path::append(Dir, "include");
    addSystemInclude(DriverArgs, CC1Args, Dir.str());
  }

}
void RL78ToolChain::AddCXXStdlibLibArgs(const ArgList &Args,
                                    ArgStringList &CmdArgs) const {
    CmdArgs.push_back("-lc++");
    CmdArgs.push_back("-lc++abi");
}

void RL78ToolChain::AddLinkRuntimeLib(const ArgList &Args,
                                      ArgStringList &CmdArgs) const {
  CmdArgs.push_back(
      Args.MakeArgString("-lclang_rt.builtins-" + getTriple().getArchName()));
}

auto RL78ToolChain::buildLinker() const -> Tool * {
  return new rl78::Linker(*this);
}

void rl78::Linker::ConstructJob(Compilation &C, const JobAction &JA,
                                const InputInfo &Output,
                                const InputInfoList &Inputs,
                                const ArgList &Args,
                                const char *LinkingOutput) const {

  const ToolChain &ToolChain = getToolChain();
  std::string Linker = ToolChain.GetProgramPath(getShortName());
  ArgStringList CmdArgs;

  auto &TC = static_cast<const toolchains::RL78ToolChain &>(getToolChain());

  AddLinkerInputs(TC, Inputs, Args, CmdArgs, JA);

  CmdArgs.push_back("-Bstatic");

  // For debug purposes
  // printf("Runtime Directory %s \n", TC.getRuntimesDir(Args).c_str());
  // printf("CMCxxLibs Directory %s \n", TC.getNewlibPath(Args).c_str());

  // Adding all paths pecified with -L
  Args.AddAllArgs(CmdArgs, options::OPT_L);

  ToolChain.AddFilePathLibArgs(Args, CmdArgs);

  // Adding default linker script if -T option not specified
  if (!Args.hasArg(options::OPT_T)) {

    SmallString<256> Dir(TC.getNewlibPath(Args));

    // Handling -frenesas-extensions anf -fsim options for
    // default linker script ussage.
    if (const Arg *Msim = Args.getLastArg(options::OPT_frenesas_extensions)) {

      llvm::sys::path::append(Dir, "rl78-frenesas-extensions.ld");
      CmdArgs.push_back(Args.MakeArgString("-T" + Dir.str()));

    } else if (const Arg *Msim = Args.getLastArg(options::OPT_fsim)) {

      llvm::sys::path::append(Dir, "rl78-sim.ld");
      CmdArgs.push_back(Args.MakeArgString("-T" + Dir.str()));

    } else {

      llvm::sys::path::append(Dir, "rl78.ld");
      CmdArgs.push_back(Args.MakeArgString("-T" + Dir.str()));
    }

  } else {
    Args.AddAllArgs(CmdArgs, options::OPT_T);
  }

  // Do not add if nostdlib or nostartfiles options present
  if (!Args.hasArg(options::OPT_nostdlib, options::OPT_nostartfiles)) {
    SmallString<256> Dir(TC.getNewlibPath(Args));
    llvm::sys::path::append(Dir, "crt0.o");
    CmdArgs.push_back(Args.MakeArgString(Dir.str()));
    Dir = TC.getRuntimesDir(Args);
    llvm::sys::path::append(Dir, "clang_rt.crtbegin-rl78.obj");
    CmdArgs.push_back(Args.MakeArgString(Dir.str()));
  }

  // Do not add if nostdlib or nodefaultlibs options present
  if (!Args.hasArg(options::OPT_nostdlib, options::OPT_nodefaultlibs)) {

	// C++ libraries will use symbols from C libraries so they have to apear before the C ones.
	// C++ also uses symbols from C++ABI.
	// Both C and C++ libraries will use compiler-rt functions
	// AddCXXStdlibLibArgs adds -lc++ and -lc++abi in this order. 
	// e.g. for c++, the order would be -lc++ -lc++abi -lsim -lc -lm -lclang_rt.builtins-rl78

    // Adding cxx libraries if cxx and no nostdlib or nodefaultlibs or nostdlibxx
    // options specified
    if (TC.ShouldLinkCXXStdlib(Args))
      TC.AddCXXStdlibLibArgs(Args, CmdArgs);

    if (const Arg *Msim = Args.getLastArg(options::OPT_fsim)) {
      CmdArgs.push_back("-lsim");
    } else {
      CmdArgs.push_back("-lnosys");
    }
	if (const Arg *Mnano = Args.getLastArg(options::OPT_fnewlib_nano)) {
		CmdArgs.push_back("-lc_nano");
	}
	else {
		CmdArgs.push_back("-lc");
		//libg.a is a debugging enabled version of libc.a 
	}
	//libm.a and libm_nano.a are similar and there is not code size difference
    CmdArgs.push_back("-lm");
    
	TC.AddLinkRuntimeLib(Args, CmdArgs);

  }

  // Do not add if nostdlib or nostartfiles options present
  if (!Args.hasArg(options::OPT_nostdlib, options::OPT_nostartfiles)) {
    SmallString<256> Dir(TC.getRuntimesDir(Args));
    llvm::sys::path::append(Dir, "clang_rt.crtend-rl78.obj");
    CmdArgs.push_back(Args.MakeArgString(Dir.str()));
    Dir = TC.getNewlibPath(Args);
    llvm::sys::path::append(Dir, "crtn.o");
    CmdArgs.push_back(Args.MakeArgString(Dir.str()));
  }

  // Adding paths to the default libraries
  CmdArgs.push_back(Args.MakeArgString("-L" + TC.getRuntimesDir(Args)));
  CmdArgs.push_back(Args.MakeArgString("-L" + TC.getNewlibPath(Args)));

  CmdArgs.push_back("-o");
  CmdArgs.push_back(Output.getFilename());

  //Disable multiple threads to avoid race when using the relocation "stack".
  //See ELF\Arch\RL78.cpp
  CmdArgs.push_back("-no-threads");

  StringRef CPU;
  if (const Arg *A = Args.getLastArg(clang::driver::options::OPT_mcpu_EQ)) {
    CPU = A->getValue();
  } else {
    CPU = "s3";
  }

  const Arg *mCode =
      Args.getLastArg(options::OPT_mnear_code, options::OPT_mfar_code);
  if (/*(mCode == nullptr && CPU.lower() != "s1" && !TC.getDriver().CCCIsCXX()) ||*/
      (mCode && mCode->getOption().getID() == options::OPT_mfar_code))
    CmdArgs.push_back("-mfar-code");

  C.addCommand(std::make_unique<Command>(
      JA, *this, Args.MakeArgString(TC.GetLinkerPath()), CmdArgs, Inputs));
}
// RL78 tools end.