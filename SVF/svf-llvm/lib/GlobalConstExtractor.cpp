// svf-llvm/lib/GlobalConstExtractor.cpp
#include "SVF-LLVM/GlobalConstExtractor.h"
#include "SVF-LLVM/LLVMModule.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "Util/SVFUtil.h"

using namespace llvm;

namespace SVF {

bool getGlobalConstInt(const GlobalObjVar* globalObj, int64_t& outVal) {
    //std::cout << "getGlobalConstInt called for GlobalObjVar ID " << globalObj->getId() << "\n";
    if (!globalObj) {
        //std::cout << "  globalObj is null\n";
        return false;
    }

    const Value* val = LLVMModuleSet::getLLVMModuleSet()->getLLVMValue(globalObj);
    if (!val) {
        //std::cout << "  getLLVMValue returned null\n";
        return false;
    }
    //std::cout << "  LLVM Value kind: " << val->getValueID() << "\n";

    // 尝试直接作为 ConstantInt（可能全局变量本身就是常量）
    if (const ConstantInt* ci = dyn_cast<ConstantInt>(val)) {
        outVal = ci->getSExtValue();
        //std::cout << "  Direct ConstantInt value: " << outVal << "\n";
        return true;
    }

    const GlobalVariable* gv = dyn_cast<GlobalVariable>(val);
    if (!gv) {
        //std::cout << "  Value is not a GlobalVariable or ConstantInt\n";
        return false;
    }
    if (!gv->hasInitializer()) {
        //std::cout << "  GlobalVariable has no initializer\n";
        return false;
    }

    const Value* stripped = gv->getInitializer()->stripPointerCastsAndAliases();
    //std::cout << "  stripped value kind: " << stripped->getValueID() << "\n";

    if (const ConstantInt* ci = dyn_cast<ConstantInt>(stripped)) {
        outVal = ci->getSExtValue();
        //std::cout << "  ConstantInt value: " << outVal << "\n";
        return true;
    } else {
        //std::cout << "  stripped value is not ConstantInt\n";
    }
    return false;
}
} // namespace SVF