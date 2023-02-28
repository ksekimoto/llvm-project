//===--- RL78.cpp - RL78 Helpers for Tools --------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RL78.h"
#include "clang/Basic/CharInfo.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/DriverDiagnostic.h"
#include "clang/Driver/Options.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Support/TargetParser.h"
#include "llvm/Support/raw_ostream.h"
#include "ToolChains/CommonArgs.h"

using namespace clang::driver;
using namespace clang::driver::tools;
using namespace clang;
using namespace llvm::opt;


void rl78::getRL78TargetFeatures(const Driver &D, const ArgList &Args,
                                   std::vector<StringRef> &Features) {

  const Arg *cpu = Args.getLastArg(options::OPT_mcpu_EQ);
  const Arg *disableMDA = Args.getLastArg(options::OPT_mdisable_mda);
  const Arg *mCode = Args.getLastArg(options::OPT_mnear_code, options::OPT_mfar_code);

  bool isS2 = false;
  StringRef coreName = "s3";
  if (cpu) {
    coreName = StringRef(cpu->getValue());
    isS2 = coreName.equals_lower("s2");
  }
  bool mdaDisabled = disableMDA;

  if (!isS2 && mdaDisabled) {
    D.Diag(diag::err_drv_cannot_mix_options) << coreName << "-mdisable-mda";
    return;
  }

  if(D.CCCIsCXX() && mCode && mCode->getOption().getID() == options::OPT_mfar_code) {
    D.Diag(diag::err_drv_unsupported_opt) << "-mfar-code";
    return;
  }

  // Add any that the user explicitly requested on the command line,
  // which may override the defaults.
  handleTargetFeaturesGroup(Args, Features, options::OPT_m_rl78_Features_Group);

  //if(!D.CCCIsCXX() && !mCode && !coreName.equals_lower("s1")) {
  //    Features.push_back("+far-code");
  //}

  if(mCode && mCode->getOption().getID() == options::OPT_mnear_code) {
    Features.push_back("-far-code");
    Features.erase(std::remove(Features.begin(), Features.end(), "+near-code"), Features.end());
  }
  const Arg *mData = Args.getLastArg(options::OPT_mnear_data, options::OPT_mfar_data);
  if(mData && mData->getOption().getID() == options::OPT_mnear_data) {
      Features.push_back("-far-data");
      Features.erase(std::remove(Features.begin(), Features.end(), "+near-data"), Features.end());
    }
}
