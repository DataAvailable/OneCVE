//===- saber.cpp -- Source-sink bug checker------------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013-2017>  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===-----------------------------------------------------------------------===//

/*
 // Saber: Software Bug Check.
 //
 // Author: Yulei Sui,
 */

#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "SABER/LeakChecker.h"
#include "SABER/FileChecker.h"
#include "SABER/DoubleFreeChecker.h"
#include "AE/Svfexe/AbstractInterpretation.h"
#include "AE/Svfexe/AEDetector.h"
#include "Util/CommandLine.h"
#include "Util/Options.h"
#include "Util/Z3Expr.h"
#include "WPA/Andersen.h"
#include "SABER/SaberCheckerAPI.h"          // 新增
#include <string>
#include <vector>

using namespace llvm;
using namespace SVF;

int main(int argc, char ** argv)
{

    bool npdRequested = false;
    bool uafRequested = false;
    bool leakRequested = false;
    bool legacyNullDerefRequested = false;
    for (int index = 1; index < argc; ++index)
    {
        const std::string argument(argv[index]);
        if (argument == "-npd" || argument == "--npd" ||
                argument.rfind("-npd=", 0) == 0 || argument.rfind("--npd=", 0) == 0)
        {
            npdRequested = true;
        }
        else if (argument == "-uaf" || argument == "--uaf" ||
                 argument.rfind("-uaf=", 0) == 0 || argument.rfind("--uaf=", 0) == 0)
        {
            uafRequested = true;
        }
        else if (argument == "-leak" || argument == "--leak" ||
                 argument.rfind("-leak=", 0) == 0 ||
                 argument.rfind("--leak=", 0) == 0)
        {
            leakRequested = true;
        }
        else if (argument == "-null-deref" || argument == "--null-deref" ||
                 argument.rfind("-null-deref=", 0) == 0 ||
                 argument.rfind("--null-deref=", 0) == 0)
        {
            legacyNullDerefRequested = true;
        }
    }

    std::vector<char*> optionArgs(argv, argv + argc);
    if (npdRequested || uafRequested)
    {
        // Match the abstract-execution defaults used by the standalone `ae`
        // driver without changing the behavior of the other Saber checkers.
        optionArgs.push_back((char*) "-model-consts=true");
        optionArgs.push_back((char*) "-model-arrays=true");
        optionArgs.push_back((char*) "-pre-field-sensitive=false");
    }
    if (uafRequested)
    {
        // UAF still needs exported roots for standalone library bitcode. NPD
        // handles no-main units in AbstractInterpretation and must not force
        // unrelated uncalled roots when a real main entry exists.
        optionArgs.push_back((char*) "-run-uncall-fun=true");
    }
    else if (leakRequested)
    {
        // OneCVE analyzes source-level bitcode units independently.  Library
        // units often have no main(), so exported roots must be considered by
        // LeakChecker or every allocation in those units is skipped.
        optionArgs.push_back((char*) "-run-uncall-fun=true");
    }

    std::vector<std::string> moduleNameVec;
    moduleNameVec = OptionBase::parseOptions(
                        static_cast<int>(optionArgs.size()), optionArgs.data(),
                        "Source-Sink Bug Detector", "[options] <input-bitcode...>"
                    );

    if (legacyNullDerefRequested)
    {
        SVFUtil::errs() << "saber: -null-deref is not a Saber checker; use -npd instead.\n";
        return 1;
    }

    LLVMModuleSet::buildSVFModule(moduleNameVec);
    SVFIRBuilder builder;
    SVFIR* pag = builder.build();


       // ========== 新增：加载自定义 API 配置 ==========
    SaberCheckerAPI *ckAPI = SaberCheckerAPI::getCheckerAPI();


    std::string apiConfigFile = Options::CustomAPIConfig();   // 使用 operator() 获取值
if (!apiConfigFile.empty()) {
    if (!ckAPI->loadCustomAPIsFromFile(apiConfigFile)) {
        SVFUtil::errs() << "Failed to load custom API config: " << apiConfigFile << "\n";
        return 1;
    }
}




    if (Options::NPDCheck() || Options::UAFCheck())
    {
        AndersenWaveDiff* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
        CallGraph* callgraph = ander->getCallGraph();
        builder.updateCallGraph(callgraph);
        pag->getICFG()->updateCallGraph(callgraph);

        AbstractInterpretation& ae = AbstractInterpretation::getAEInstance();
        if (Options::NPDCheck())
            ae.addDetector(std::make_unique<NullptrDerefDetector>());
        if (Options::UAFCheck())
            ae.addDetector(std::make_unique<UseAfterFreeDetector>());
        ae.runOnModule(pag->getICFG());

        AndersenWaveDiff::releaseAndersenWaveDiff();
        LLVMModuleSet::releaseLLVMModuleSet();
        return 0;
    }

    std::unique_ptr<LeakChecker> saber;

    if(Options::MemoryLeakCheck())
        saber = std::make_unique<LeakChecker>();
    else if(Options::FileCheck())
        saber = std::make_unique<FileChecker>();
    else if(Options::DFreeCheck())
        saber = std::make_unique<DoubleFreeChecker>();
    else
        saber = std::make_unique<LeakChecker>();  // if no checker is specified, we use leak checker as the default one.

    saber->runOnModule(pag);
    LLVMModuleSet::releaseLLVMModuleSet();


    return 0;

}
