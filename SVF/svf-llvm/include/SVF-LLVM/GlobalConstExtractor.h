// svf-llvm/include/SVF-LLVM/GlobalConstExtractor.h
#ifndef SVF_LLVM_GLOBALCONSTEXTRACTOR_H
#define SVF_LLVM_GLOBALCONSTEXTRACTOR_H

#include "SVFIR/SVFVariables.h"   // for GlobalObjVar
#include <cstdint>

namespace SVF {

/**
 * 从 GlobalObjVar 中提取有符号整数常量值。
 * @param globalObj 指向 GlobalObjVar 的指针
 * @param outVal 输出参数，存储提取到的整数值
 * @return 成功提取返回 true，否则返回 false
 */
bool getGlobalConstInt(const GlobalObjVar* globalObj, int64_t& outVal);

} // namespace SVF

#endif