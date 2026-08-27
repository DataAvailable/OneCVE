//===- PathAllocator.cpp -- Path condition analysis---------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013->  <Yulei Sui>
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
//===----------------------------------------------------------------------===//


/*
 * PathAllocator.cpp
 *
 *  Created on: Apr 3, 2014
 *      Author: Yulei Sui
 */

#include "Util/Options.h"
#include "SABER/SaberCondAllocator.h"
#include "Util/DPItem.h"
#include "Graphs/SVFG.h"
#include <climits>
#include <cmath>

#include "Graphs/CallGraph.h"


// SaberCondAllocator.cpp
#include "WPA/FlowSensitive.h"


#include <string>
#include "SVFIR/SVFIR.h"
#include "SVFIR/SVFStatements.h"
#include "SVFIR/SVFValue.h"
#include "SVFIR/SVFVariables.h"


#include "SVF-LLVM/GlobalConstExtractor.h"
#include "MSSA/MSSAMuChi.h"
#include "MSSA/MemRegion.h"
#include "MSSA/MemSSA.h"
#include "MSSA/MSSAMuChi.h"   // 包含 StoreCHI、CHISet 等

#include <algorithm>
#include <unordered_map>
#include <set>


using namespace SVF;
using namespace SVFUtil;

u64_t DPItem::maximumBudget = ULONG_MAX - 1;
u32_t ContextCond::maximumCxtLen = 0;
u32_t ContextCond::maximumCxt = 0;
u32_t ContextCond::maximumPathLen = 0;
u32_t ContextCond::maximumPath = 0;
u32_t SaberCondAllocator::totalCondNum = 0;


SaberCondAllocator::SaberCondAllocator()
{
    
}

/*!
 * Allocate path condition for each branch
 */
void SaberCondAllocator::allocate()
{
    DBOUT(DGENERAL, outs() << pasMsg("path condition allocation starts\n"));

    const CallGraph* svfirCallGraph = PAG::getPAG()->getCallGraph();
    for (const auto& item: *svfirCallGraph)
    {
        const FunObjVar *func = (item.second)->getFunction();
        if (!SVFUtil::isExtCall(func))
        {
            // Allocate conditions for a program.
            for (FunObjVar::const_bb_iterator bit = func->begin(), ebit = func->end();
                    bit != ebit; ++bit)
            {
                const SVFBasicBlock* bb = bit->second;
                collectBBCallingProgExit(*bb);
                allocateForBB(*bb);
            }
        }
    }

    if (Options::PrintPathCond())
        printPathCond();

    DBOUT(DGENERAL, outs() << pasMsg("path condition allocation ends\n"));
}

/*!
 * Allocate conditions for a basic block and propagate its condition to its successors.
 */
void SaberCondAllocator::allocateForBB(const SVFBasicBlock &bb)
{

    u32_t succ_number = bb.getNumSuccessors();

    // if successor number greater than 1, allocate new decision variable for successors
    if (succ_number > 1)
    {

        //allocate log2(num_succ) decision variables
        double num = log(succ_number) / log(2);
        u32_t bit_num = (u32_t) ceil(num);
        u32_t succ_index = 0;
        std::vector<Condition> condVec;
        for (u32_t i = 0; i < bit_num; i++)
        {
            condVec.push_back(newCond(bb.back()));
        }

        // iterate each successor
        for (const SVFBasicBlock* svf_succ_bb : bb.getSuccessors())
        {
            Condition path_cond = getTrueCond();

            ///TODO: handle BranchInst and SwitchInst individually here!!

            // for each successor decide its bit representation
            // decide whether each bit of succ_index is 1 or 0, if (three successor) succ_index is 000 then use C1^C2^C3
            // if 001 use C1^C2^negC3
            for (u32_t j = 0; j < bit_num; j++)
            {
                //test each bit of this successor's index (binary representation)
                u32_t tool = 0x01 << j;
                if (tool & succ_index)
                {
                    path_cond = condAnd(path_cond, (condNeg(condVec.at(j))));
                }
                else
                {
                    path_cond = condAnd(path_cond, condVec.at(j));
                }
            }
            setBranchCond(&bb, svf_succ_bb, path_cond);

            succ_index++;
        }

    }
}

/*!
 * Get a branch condition
 */
SaberCondAllocator::Condition SaberCondAllocator::getBranchCond(const SVFBasicBlock* bb, const SVFBasicBlock* succ) const
{
    u32_t pos = bb->getBBSuccessorPos(succ);
    if(bb->getNumSuccessors() == 1)
        return getTrueCond();
    else
    {
        BBCondMap::const_iterator it = bbConds.find(bb);
        assert(it != bbConds.end() && "basic block does not have branch and conditions??");
        CondPosMap::const_iterator cit = it->second.find(pos);
        assert(cit != it->second.end() && "no condition on the branch??");
        return cit->second;
    }
}

SaberCondAllocator::Condition SaberCondAllocator::getEvalBrCond(const SVFBasicBlock* bb, const SVFBasicBlock* succ)
{
    // && getCurEvalSVFGNode()->getValue()
if (getCurEvalSVFGNode() ) {
    /*std::cout << "getEvalBrCond (eval): bb " << bb->getId() << " -> succ " << succ->getId()
              << ", cur node kind: " << getCurEvalSVFGNode()->getNodeKind() << std::endl;*/
     currentCallSite = findCallSiteFromNode(getCurEvalSVFGNode());
    return evaluateBranchCond(bb, succ);
} else {
    std::cout << "getEvalBrCond (static): bb " << bb->getId() << " -> succ " << succ->getId()
              << ", cur node is null or no value" << std::endl;
    return getBranchCond(bb, succ);
}
       
}

/*!
 * Set a branch condition
 */
void SaberCondAllocator::setBranchCond(const SVFBasicBlock* bb, const SVFBasicBlock* succ, const Condition &cond)
{
    /// we only care about basic blocks have more than one successor
    assert(bb->getNumSuccessors() > 1 && "not more than one successor??");
    u32_t pos = bb->getBBSuccessorPos(succ);
    CondPosMap& condPosMap = bbConds[bb];

    /// FIXME: llvm getNumSuccessors allows duplicated block in the successors, it makes this assertion fail
    /// In this case we may waste a condition allocation, because the overwrite of the previous cond
    //assert(condPosMap.find(pos) == condPosMap.end() && "this branch has already been set ");

    condPosMap[pos] = cond;
}

/*!
 * Evaluate null like expression for source-sink related bug detection in SABER
 */
SaberCondAllocator::Condition
SaberCondAllocator::evaluateTestNullLikeExpr(const BranchStmt *branchStmt, const SVFBasicBlock* succ)
{

    const SVFBasicBlock* succ1 = branchStmt->getSuccessor(0)->getBB();

    const ValVar* condVar = SVFUtil::cast<ValVar>(branchStmt->getCondition());


    /*if (condVar) {
    std::cout << "Condition: " << condVar->toString() << std::endl;
    std::cout << "Condition name: " << condVar->getValueName() << std::endl;

    // 使用 const 迭代器遍历 Cmp 入边
    for (auto it = condVar->getIncomingEdgesBegin(SVFStmt::Cmp);
              it != condVar->getIncomingEdgesEnd(SVFStmt::Cmp); ++it) {
        auto* edge = *it;
        if (auto* cmpStmt = SVFUtil::dyn_cast<CmpStmt>(edge)) {
            const SVFVar* op0 = cmpStmt->getOpVar(0);
            const SVFVar* op1 = cmpStmt->getOpVar(1);
            std::cout << "Operand0: " << op0->toString() << std::endl;
            std::cout << "Operand1: " << op1->toString() << std::endl;

            // 尝试将操作数转换为常量整数并取值
            if (auto* intConst0 = SVFUtil::dyn_cast<ConstIntValVar>(op0)) {
                // 根据实际接口调整，例如 getSExtValue()
                std::cout << "Operand0 constant value: " << intConst0->getSExtValue() << std::endl;
            }
            if (auto* intConst1 = SVFUtil::dyn_cast<ConstIntValVar>(op1)) {
                std::cout << "Operand1 constant value: " << intConst1->getSExtValue() << std::endl;
            }
        }
    }
}*/
    

    if (condVar->isConstDataOrAggDataButNotNullPtr())
    {
        // branch condition is a constant value, return nullexpr because it cannot be test null
        //  br i1 false, label %44, label %75, !dbg !7669 { "ln": 2033, "cl": 7, "fl": "re_lexer.c" }
        return Condition::nullExpr();
    }
    if (isTestNullExpr(SVFUtil::cast<ICFGNode>(condVar->getICFGNode())))
    {
        // succ is then branch
        if (succ1 == succ)
            return getFalseCond();
        // succ is else branch
        else
            return getTrueCond();
    }
    if (isTestNotNullExpr(condVar->getICFGNode()))
    {
        // succ is then branch
        if (succ1 == succ)
            return getTrueCond();
        // succ is else branch
        else
            return getFalseCond();
    }
    return Condition::nullExpr();
}

/*!
 * Evaluate condition for program exit (e.g., exit(0))
 */
SaberCondAllocator::Condition SaberCondAllocator::evaluateProgExit(const BranchStmt *branchStmt, const SVFBasicBlock* succ)
{
    const SVFBasicBlock* succ1 = branchStmt->getSuccessor(0)->getBB();
    const SVFBasicBlock* succ2 = branchStmt->getSuccessor(1)->getBB();

    bool branch1 = isBBCallsProgExit(succ1);
    bool branch2 = isBBCallsProgExit(succ2);

    /// then branch calls program exit
    if (branch1 && !branch2)
    {
        // succ is then branch
        if (succ1 == succ)
            return getFalseCond();
        // succ is else branch
        else
            return getTrueCond();
    }
    /// else branch calls program exit
    else if (!branch1 && branch2)
    {
        // succ is else branch
        if (succ2 == succ)
            return getFalseCond();
        // succ is then branch
        else
            return getTrueCond();
    }
    // two branches both call program exit
    else if (branch1 && branch2)
    {
        return getFalseCond();
    }
    /// no branch call program exit
    else
        return Condition::nullExpr();

}

/*!
 * Evaluate loop exit branch to be true if
 * bb is loop header and succ is the only exit basic block outside the loop (excluding exit bbs which call program exit)
 * for all other case, we conservatively evaluate false for now
 */
SaberCondAllocator::Condition SaberCondAllocator::evaluateLoopExitBranch(const SVFBasicBlock* bb, const SVFBasicBlock* dst)
{
    const FunObjVar* svffun = bb->getParent();
    assert(svffun == dst->getParent() && "two basic blocks should be in the same function");

    if (svffun->isLoopHeader(bb))
    {
        Set<const SVFBasicBlock* > filteredbbs;
        std::vector<const SVFBasicBlock*> exitbbs;
        svffun->getExitBlocksOfLoop(bb,exitbbs);
        /// exclude exit bb which calls program exit
        for(const SVFBasicBlock* eb : exitbbs)
        {
            if(!isBBCallsProgExit(eb))
                filteredbbs.insert(eb);
        }

        /// if the dst dominate all other loop exit bbs, then dst can certainly be reached
        bool allPDT = true;
        for (const auto &filteredbb: filteredbbs)
        {
            if (!postDominate(dst, filteredbb))
                allPDT = false;
        }

        if (allPDT)
            return getTrueCond();
    }
    return Condition::nullExpr();
}

/*!
 *  (1) Evaluate a branch when it reaches a program exit
 *  (2) Evaluate a branch when it is loop exit branch
 *  (3) Evaluate a branch when it is a test null like condition
 */
SaberCondAllocator::Condition SaberCondAllocator::evaluateBranchCond(const SVFBasicBlock* bb, const SVFBasicBlock* succ)
{
    
    if(bb->getNumSuccessors() == 1)
    {
        return getTrueCond();
    }

    assert(!bb->getICFGNodeList().empty() && "bb not empty");
    //std::cout << "Condition: 返回恒定的True" << std::endl;
    //return getTrueCond();
    if (const ICFGNode* icfgNode = bb->back())
    {
        for (const auto &svfStmt: icfgNode->getSVFStmts())
        {
            if (const BranchStmt *branchStmt = SVFUtil::dyn_cast<BranchStmt>(svfStmt))
            {
                if (branchStmt->getNumSuccessors() == 2)
                {
                    //std::cout << "  found BranchStmt: " << branchStmt->toString() << std::endl;

                    const SVFBasicBlock* succ1 = branchStmt->getSuccessor(0)->getBB();
                    const SVFBasicBlock* succ2 = branchStmt->getSuccessor(1)->getBB();
                    bool is_succ = (succ1 == succ || succ2 == succ);
                    (void)is_succ; // Suppress warning of unused variable under release build
                    assert(is_succ && "not a successor??");

                       // ==============================================
                    // 新增：步骤4：求值普通常量比较分支（如a==5/x>0）
                    // ==============================================
                    
                    Condition evalConstantCmp = evaluateConstantCmpBranch(branchStmt, succ);
                    if (!eq(evalConstantCmp, Condition::nullExpr()))
                        return evalConstantCmp;
                    

                    Condition evalLoopExit = evaluateLoopExitBranch(bb, succ);
                    if (!eq(evalLoopExit, Condition::nullExpr()))
                        return evalLoopExit;

                    Condition evalProgExit = evaluateProgExit(branchStmt, succ);
                    if (!eq(evalProgExit, Condition::nullExpr()))
                        return evalProgExit;

                    Condition evalTestNullLike = evaluateTestNullLikeExpr(branchStmt, succ);
                    if (!eq(evalTestNullLike, Condition::nullExpr()))
                        return evalTestNullLike;
                    
                  
                    
                    break;
                }
            }
        }
    }

    return getBranchCond(bb, succ);
}



SaberCondAllocator::Condition
SaberCondAllocator::evaluateConstantCmpBranch(const BranchStmt *branchStmt, const SVFBasicBlock* succ) {
    
    const ValVar* condVar = SVFUtil::cast<ValVar>(branchStmt->getCondition());
    if (condVar->hasIncomingEdges(SVFStmt::Cmp)) {
    for (auto it = condVar->getIncomingEdgesBegin(SVFStmt::Cmp);
              it != condVar->getIncomingEdgesEnd(SVFStmt::Cmp); ++it) {
        auto* cmpStmt = SVFUtil::dyn_cast<CmpStmt>(*it);
        if (!cmpStmt) continue;

        s64_t val0, val1;
        bool const0 = getConstantValue(cmpStmt->getOpVar(0), val0);
        bool const1 = getConstantValue(cmpStmt->getOpVar(1), val1);
        if (const0 && const1) {
            bool result = evaluateCmp(cmpStmt->getPredicate(), val0, val1);
            const ICFGNode* thenSucc = branchStmt->getSuccessor(0);
            if (succ == thenSucc->getBB())
                return result ? getTrueCond() : getFalseCond();
            else
                return result ? getFalseCond() : getTrueCond();
        }
    }
}
    return Condition::nullExpr();


}

bool SaberCondAllocator::getConstantValue(const SVFVar* var, s64_t& outVal, u32_t depth) {
    if (depth > MAX_DEPTH) return false;
  

    // 1. 直接常量
    if (auto* intConst = SVFUtil::dyn_cast<ConstIntValVar>(var)) {
        outVal = intConst->getSExtValue();
        return true;
    }

    if (auto* constIntObj = SVFUtil::dyn_cast<ConstIntObjVar>(var)) {
    outVal = constIntObj->getSExtValue();
    return true;
    }




// 处理形式参数（PAG 中的 ArgValVar）
if (auto* argVar = SVFUtil::dyn_cast<ArgValVar>(var)) {

    const VFGNode* formalNode = nullptr;
    // 遍历所有 VFG 节点
    for (auto it = vfg->begin(); it != vfg->end(); ++it) {
        const VFGNode* node = it->second;
        if (auto* fp = SVFUtil::dyn_cast<FormalParmVFGNode>(node)) {
            const SVFVar* value = fp->getValue();
            if (value == argVar) {
                formalNode = fp;
                break;
            }
        }
    }

    if (!formalNode) {
        return false;
    }

    // 遍历入边寻找调用边
    for (auto it = formalNode->InEdgeBegin(); it != formalNode->InEdgeEnd(); ++it) {
        const VFGEdge* edge = *it;
        if (edge->isCallVFGEdge()) {
            const VFGNode* srcNode = edge->getSrcNode();
            if (auto* actualParm = SVFUtil::dyn_cast<ActualParmVFGNode>(srcNode)) {
                bool success = getConstantValue(actualParm->getValue(), outVal, depth + 1);
                if (success) {
                 //outs() << "[ParamProp] Actual param value = " << outVal << "\n";
                } else {
                }
                return success;
            }
        }
    }

    return false;
}



if (var->hasIncomingEdges(SVFStmt::Ret)) {
    //std::cout << "  var " << var->getId() << " has Ret edges, entering...\n";
    for (auto it = var->getIncomingEdgesBegin(SVFStmt::Ret);
              it != var->getIncomingEdgesEnd(SVFStmt::Ret); ++it) {
        auto* ret = SVFUtil::dyn_cast<RetPE>(*it);
        if (!ret) continue;
        const SVFVar* src = ret->getRHSVar();
        if (!src) continue;
        //std::cout << "    source var ID: " << src->getId() << ", kind: " << src->getNodeKind() << std::endl;
        // 可选：打印源变量的名称
        // std::cout << "    source var name: " << src->getName() << std::endl;
        // 递归获取返回值节点的常量值
        if (getConstantValue(src, outVal, depth + 1))
            return true;
        else
            //std::cout << "    recursion failed for var " << src->getId() << std::endl;
        break;
    }
}


// 处理 PhiStmt
if (var->hasIncomingEdges(SVFStmt::Phi)) {
    //std::cout << "  var " << var->getId() << " has Phi edges\n";
    s64_t commonVal = 0;
    bool first = true;
    for (auto it = var->getIncomingEdgesBegin(SVFStmt::Phi);
              it != var->getIncomingEdgesEnd(SVFStmt::Phi); ++it) {
        auto* phi = SVFUtil::dyn_cast<PhiStmt>(*it);
        if (!phi) continue;
        // PhiStmt 有多个操作数，每个操作数对应一个入边
        for (u32_t i = 0; i < phi->getOpVarNum(); ++i) {
            const SVFVar* op = phi->getOpVar(i);
            s64_t val;
            if (getConstantValue(op, val, depth + 1)) {
                if (first) {
                    commonVal = val;
                    first = false;
                } else if (val != commonVal) {
                    // 不同操作数值不同，无法确定常量
                    return false;
                }
            } else {
                // 某个操作数不是常量，无法确定
                return false;
            }
        }
        break; // 通常只有一个 PhiStmt 定义该变量
    }
    if (!first) {
        outVal = commonVal;
        return true;
    }
}




    // 2. 处理 LoadStmt：从内存加载
    if (var->hasIncomingEdges(SVFStmt::Load)) {
    //std::cout << "getConstantValue: var " << var->getId() << " has Load edges.\n";
    for (auto it = var->getIncomingEdgesBegin(SVFStmt::Load);
              it != var->getIncomingEdgesEnd(SVFStmt::Load); ++it) {
        auto* load = SVFUtil::dyn_cast<LoadStmt>(*it);
        if (!load) continue;
        const SVFVar* ptr = load->getRHSVar();
        //std::cout << "  load: ptr ID=" << ptr->getId() << "\n";
        PointsTo pts = pta->getPts(ptr->getId());
        //std::cout << "    pts count=" << pts.count() << "\n";
        if (pts.count() == 1) {
            NodeID objId = *pts.begin();
            SVFIR* pag = vfg->getPAG();
            const SVFVar* obj = pag->getGNode(objId);
            //std::cout << "    unique obj ID=" << objId << ", kind=" << obj->getNodeKind() << "\n";
            if (auto* constIntObj = SVFUtil::dyn_cast<ConstIntObjVar>(obj)) {
                outVal = constIntObj->getSExtValue();
                //std::cout << "      ConstIntObjVar value=" << outVal << "\n";
                return true;
            }

  
if (auto* globalObj = SVFUtil::dyn_cast<GlobalObjVar>(obj)) {
    const SVFBasicBlock* loadBB = load->getBB();
    if (!loadBB) return false;
    const FunObjVar* loadFunc = loadBB->getParent();
    if (!loadFunc) return false;

       // 在当前函数内查找最近一次写入
std::set<const SVFBasicBlock*> visited;
const StoreStmt* latestStore = nullptr;
    if (findLatestStore(loadBB, globalObj->getId(), latestStore, visited, load->getICFGNode())) {
    const SVFVar* src = latestStore->getRHSVar();
    if (getConstantValue(src, outVal, depth + 1))
        return true;
}



    // 获取调用图
    CallGraph* cg = vfg->getCallGraph();
    if (!cg) return false;

    // 寻找直接调用 loadFunc 的函数
    const FunObjVar* callerFunc = nullptr;
    for (auto it = cg->begin(); it != cg->end(); ++it) {
        const CallGraphNode* callerNode = it->second;
        for (auto it2 = callerNode->OutEdgeBegin(); it2 != callerNode->OutEdgeEnd(); ++it2) {
            const CallGraphEdge* edge = *it2;
            const CallGraphNode* calleeNode = edge->getDstNode();
            if (calleeNode->getFunction() == loadFunc) {
                callerFunc = callerNode->getFunction();
                break;
            }
        }
        if (callerFunc) break;
    }

    if (callerFunc) {
        // 检查该调用者是否对当前全局变量有赋值
        auto it = globalToAssigningFuncs.find(globalObj->getId());
        if (it != globalToAssigningFuncs.end() && it->second.count(callerFunc)) {
            // 在调用者函数内找到最后一次写入该全局变量的 StoreStmt
            const StoreStmt* latestStore = nullptr;
            u64_t maxIdx = 0;
            for (const auto& entry : bbStores) {
                if (entry.first->getParent() != callerFunc) continue;
                for (const auto& storeInfo : entry.second) {
                    if (storeInfo.objId == globalObj->getId() && storeInfo.idx >= maxIdx) {
                        maxIdx = storeInfo.idx;
                        latestStore = storeInfo.store;
                    }
                }
            }
            if (latestStore) {
                const SVFVar* src = latestStore->getRHSVar();
                if (getConstantValue(src, outVal, depth + 1))
                    return true;
            }
        }
    }

    // 如果没有找到运行时赋值，尝试从初始化器获取（只读全局常量）
    int64_t val;
    if (SVF::getGlobalConstInt(globalObj, val)) {
        outVal = val;
        return true;
    }
    return false;
}


if (auto* stackObj = SVFUtil::dyn_cast<StackObjVar>(obj)) {
    const SVFBasicBlock* loadBB = load->getBB();
    if (!loadBB) return false;

    std::set<const SVFBasicBlock*> visited;
    const StoreStmt* latestStore = nullptr;
    if (findLatestStore(loadBB, stackObj->getId(), latestStore, visited, load->getICFGNode())) {
        const SVFVar* src = latestStore->getRHSVar();
        if (getConstantValue(src, outVal, depth + 1)) {
            return true;
        }
    }
    // 如果找不到或递归失败，可继续其他方法（如 VFG 或回退）
    return false;
}


        } else {
            //std::cout << "    pts count != 1\n";
        }
        break; // 只处理第一个定义
        }
    }
    
    // 3. 处理 CopyStmt：赋值操作
    if (var->hasIncomingEdges(SVFStmt::Copy)) {
        for (auto it = var->getIncomingEdgesBegin(SVFStmt::Copy);
                  it != var->getIncomingEdgesEnd(SVFStmt::Copy); ++it) {
            auto* copy = SVFUtil::dyn_cast<CopyStmt>(*it);
            if (!copy) continue;
            const SVFVar* src = copy->getRHSVar();
            if (getConstantValue(src, outVal, depth + 1))
                return true;
            break;
        }
    }
    
    // 4. 处理 BinaryOpStmt：二元运算
    if (var->hasIncomingEdges(SVFStmt::BinaryOp)) {
        for (auto it = var->getIncomingEdgesBegin(SVFStmt::BinaryOp);
                  it != var->getIncomingEdgesEnd(SVFStmt::BinaryOp); ++it) {
            auto* bin = SVFUtil::dyn_cast<BinaryOPStmt>(*it);
            if (!bin) continue;
            s64_t lhs, rhs;
            if (getConstantValue(bin->getOpVar(0), lhs, depth + 1) &&
                getConstantValue(bin->getOpVar(1), rhs, depth + 1)) {
                switch (bin->getOpcode()) {
                    case BinaryOPStmt::Add: outVal = lhs + rhs; return true;
                    case BinaryOPStmt::Sub: outVal = lhs - rhs; return true;
                    case BinaryOPStmt::Mul: outVal = lhs * rhs; return true;
                    case BinaryOPStmt::SDiv: outVal = lhs / rhs; return true;
                    case BinaryOPStmt::SRem: outVal = lhs % rhs; return true;
                    default: break;
                }
            }
            break;
        }
    }
    
   //cmp比较
    if (var->hasIncomingEdges(SVFStmt::Cmp)) {
    for (auto it = var->getIncomingEdgesBegin(SVFStmt::Cmp);
              it != var->getIncomingEdgesEnd(SVFStmt::Cmp); ++it) {
        auto* cmp = SVFUtil::dyn_cast<CmpStmt>(*it);
        if (!cmp) continue;
        s64_t lhs, rhs;
        if (getConstantValue(cmp->getOpVar(0), lhs, depth + 1) &&
            getConstantValue(cmp->getOpVar(1), rhs, depth + 1)) {
            bool result = false;  // 初始化
            switch (cmp->getPredicate()) {
                case CmpStmt::ICMP_EQ:  result = (lhs == rhs); break;
                case CmpStmt::ICMP_NE:  result = (lhs != rhs); break;
                case CmpStmt::ICMP_UGT: result = (u64_t)lhs > (u64_t)rhs; break;
                case CmpStmt::ICMP_UGE: result = (u64_t)lhs >= (u64_t)rhs; break;
                case CmpStmt::ICMP_ULT: result = (u64_t)lhs < (u64_t)rhs; break;
                case CmpStmt::ICMP_ULE: result = (u64_t)lhs <= (u64_t)rhs; break;
                case CmpStmt::ICMP_SGT: result = (lhs > rhs); break;
                case CmpStmt::ICMP_SGE: result = (lhs >= rhs); break;
                case CmpStmt::ICMP_SLT: result = (lhs < rhs); break;
                case CmpStmt::ICMP_SLE: result = (lhs <= rhs); break;
                default: break;
            }
            outVal = result ? 1 : 0;
            return true;
        }
        break;
    }
}
    

    return false;
}





bool SaberCondAllocator::evaluateCmp(u32_t predicate, s64_t lhs, s64_t rhs) const {
    switch (predicate) {
        case CmpStmt::ICMP_EQ: return lhs == rhs;
        case CmpStmt::ICMP_NE: return lhs != rhs;
        case CmpStmt::ICMP_UGT: return (u64_t)lhs > (u64_t)rhs;
        case CmpStmt::ICMP_UGE: return (u64_t)lhs >= (u64_t)rhs;
        case CmpStmt::ICMP_ULT: return (u64_t)lhs < (u64_t)rhs;
        case CmpStmt::ICMP_ULE: return (u64_t)lhs <= (u64_t)rhs;
        case CmpStmt::ICMP_SGT: return lhs > rhs;
        case CmpStmt::ICMP_SGE: return lhs >= rhs;
        case CmpStmt::ICMP_SLT: return lhs < rhs;
        case CmpStmt::ICMP_SLE: return lhs <= rhs;
        default: assert(false && "Unsupported predicate"); return false;
    }
}


static size_t getNodeIndexInBB(const ICFGNode* node) {
    const SVFBasicBlock* bb = node->getBB();
    size_t idx = 0;
    for (const ICFGNode* n : bb->getICFGNodeList()) {
        if (n == node) return idx;
        ++idx;
    }
    return (size_t)-1; // 不应该发生
}


void SaberCondAllocator::buildStoreMap() {
    SVFIR* pag = vfg->getPAG();
    if (!pag) return;

    for (auto* stmt : pag->getSVFStmtSet(SVFStmt::Store)) {
        auto* store = SVFUtil::dyn_cast<StoreStmt>(stmt);
        if (!store) continue;

        const SVFVar* lhs = store->getLHSVar();
        PointsTo lhsPts = pta->getPts(lhs->getId());
        if (lhsPts.count() != 1) continue;  // 只处理指向唯一对象的 store

        NodeID objId = *lhsPts.begin();
        const SVFBasicBlock* bb = store->getBB();
        if (!bb) continue;

        // 获取该基本块内指令顺序映射
        std::unordered_map<const ICFGNode*, size_t> idxMap;
        size_t idx = 0;
        for (const ICFGNode* node : bb->getICFGNodeList()) {
            idxMap[node] = idx++;
        }
        size_t storeIdx = idxMap[store->getICFGNode()];
        bbStores[bb].push_back({store, objId, storeIdx});

               // 记录对该全局变量有赋值的函数
        const FunObjVar* func = bb->getParent();
        globalToAssigningFuncs[objId].insert(func);
    }

    // 对每个基本块内的存储按指令顺序排序
    for (auto& entry : bbStores) {
        std::sort(entry.second.begin(), entry.second.end(),
                  [](const StoreInfo& a, const StoreInfo& b) {
                      return a.idx < b.idx;
                  });
    }
}

bool SaberCondAllocator::findLatestStore(const SVFBasicBlock* loadBB, NodeID objId,
                                         const StoreStmt*& latestStore,
                                         std::set<const SVFBasicBlock*>& visited,
                                         const ICFGNode* loadNode) {
    if (visited.count(loadBB)) return false;
    visited.insert(loadBB);

    // 1. 检查当前基本块内是否有写入该对象的 store
    auto it = bbStores.find(loadBB);
    if (it != bbStores.end()) {
        // 收集符合条件的存储
        std::vector<const StoreInfo*> candidates;
        for (const auto& storeInfo : it->second) {
            if (storeInfo.objId != objId) continue;
            if (loadNode && loadNode->getBB() == loadBB) {
                size_t loadIdx = getNodeIndexInBB(loadNode);
                if (storeInfo.idx < loadIdx) {
                    candidates.push_back(&storeInfo);
                }
            } else {
                candidates.push_back(&storeInfo);
            }
        }
        if (!candidates.empty()) {
            // 选择索引最大的（最近一次写入）
            auto* best = *std::max_element(candidates.begin(), candidates.end(),
                [](const StoreInfo* a, const StoreInfo* b) { return a->idx < b->idx; });
            latestStore = best->store;
            return true;
        }
    }

    // 2. 递归前驱
    std::vector<const StoreStmt*> candidates;
    for (const SVFBasicBlock* pred : loadBB->getPredecessors()) {
        const StoreStmt* cand = nullptr;
        if (findLatestStore(pred, objId, cand, visited, loadNode)) {
            candidates.push_back(cand);
        }
    }

    if (candidates.empty()) return false;
    if (candidates.size() == 1) {
        latestStore = candidates[0];
        return true;
    }

    // 3. 多个候选，要求值相同
    const SVFVar* commonSrc = candidates[0]->getRHSVar();
    for (size_t i = 1; i < candidates.size(); ++i) {
        if (candidates[i]->getRHSVar() != commonSrc) return false;
    }
    latestStore = candidates[0];
    return true;
}

const CallICFGNode* SaberCondAllocator::findCallSiteFromNode(const SVFGNode* node) const {
    // 如果节点本身就是调用点相关的节点
    if (auto* ap = SVFUtil::dyn_cast<ActualParmVFGNode>(node))
        return ap->getCallSite();
    if (auto* ar = SVFUtil::dyn_cast<ActualRetVFGNode>(node))
        return ar->getCallSite();
    // 遍历入边，寻找调用边
    for (auto it = node->InEdgeBegin(); it != node->InEdgeEnd(); ++it) {
        const SVFGEdge* edge = *it;
        if (edge->isCallVFGEdge()) {
            CallSiteID csId = 0;
            if (auto* callEdge = SVFUtil::dyn_cast<CallDirSVFGEdge>(edge))
                csId = callEdge->getCallSiteId();
            else if (auto* callEdge = SVFUtil::dyn_cast<CallIndSVFGEdge>(edge))
                csId = callEdge->getCallSiteId();
            if (csId != 0)
                return vfg->getCallSite(csId); // vfg 是 SVFG* 成员变量
        }
    }
    return nullptr;
}



bool SaberCondAllocator::isEQCmp(const CmpStmt *cmp) const
{
    return (cmp->getPredicate() == CmpStmt::ICMP_EQ);
}

bool SaberCondAllocator::isNECmp(const CmpStmt *cmp) const
{
    return (cmp->getPredicate() == CmpStmt::ICMP_NE);
}

bool SaberCondAllocator::isTestNullExpr(const ICFGNode* test) const
{
    if(!test) return false;
    for(const SVFStmt* stmt : PAG::getPAG()->getSVFStmtList(test))
    {
        if(const CmpStmt* cmp = SVFUtil::dyn_cast<CmpStmt>(stmt))
        {
            return isTestContainsNullAndTheValue(cmp) && isEQCmp(cmp);
        }
    }
    return false;
}

bool SaberCondAllocator::isTestNotNullExpr(const ICFGNode* test) const
{
    if(!test) return false;
    for(const SVFStmt* stmt : PAG::getPAG()->getSVFStmtList(test))
    {
        if(const CmpStmt* cmp = SVFUtil::dyn_cast<CmpStmt>(stmt))
        {
            return isTestContainsNullAndTheValue(cmp) && isNECmp(cmp);
        }
    }
    return false;
}

/*!
 * Return true if:
 * (1) cmp contains a null value
 * (2) there is an indirect/direct edge from cur evaluated SVFG node to cmp operand
 *
 * e.g.,
 * indirect edge:
 *      cur svfg node -> 1. store i32* %0, i32** %p, align 8, !dbg !157
 *      cmp operand   -> 2. %1 = load i32*, i32** %p, align 8, !dbg !159
 *                       3. %tobool = icmp ne i32* %1, null, !dbg !159
 *                       4. br i1 %tobool, label %if.end, label %if.then, !dbg !161
 *     There is an indirect edge 1->2 with value %0
 *
 * direct edge:
 *      cur svfg node -> 1. %3 = tail call i8* @malloc(i64 16), !dbg !22
 *      (cmp operand)    2. %4 = icmp eq i8* %3, null, !dbg !28
 *                       3. br i1 %4, label %7, label %5, !dbg !30
 *     There is an direct edge 1->2 with value %3
 *
 */
bool SaberCondAllocator::isTestContainsNullAndTheValue(const CmpStmt *cmp) const
{
    if (!getCurEvalSVFGNode()) return false;

    // must be val var?
    const SVFVar* op0 = cmp->getOpVar(0);
    const SVFVar* op1 = cmp->getOpVar(1);
    if (SVFUtil::isa<ConstNullPtrValVar>(op1))
    {
        Set<const SVFVar* > inDirVal;
        inDirVal.insert(getCurEvalSVFGNode()->getValue());
        for (const auto &it: getCurEvalSVFGNode()->getOutEdges())
        {
            inDirVal.insert(it->getDstNode()->getValue());
        }
        return inDirVal.find(op0) != inDirVal.end();
    }
    else if (SVFUtil::isa<ConstNullPtrValVar>(op0))
    {
        Set<const SVFVar* > inDirVal;
        inDirVal.insert(getCurEvalSVFGNode()->getValue());
        for (const auto &it: getCurEvalSVFGNode()->getOutEdges())
        {
            inDirVal.insert(it->getDstNode()->getValue());
        }
        return inDirVal.find(op1) != inDirVal.end();
    }
    return false;
}

/*!
 * Whether this basic block contains program exit function call
 */
void SaberCondAllocator::collectBBCallingProgExit(const SVFBasicBlock &bb)
{

    for (const auto& icfgNode: bb.getICFGNodeList())
    {
        if (const CallICFGNode* cs = SVFUtil::dyn_cast<CallICFGNode>(icfgNode))
            if (SVFUtil::isProgExitCall(cs))
            {
                const FunObjVar* svfun = bb.getParent();
                funToExitBBsMap[svfun].insert(&bb);
            }
    }
}

/*!
 * Whether this basic block contains program exit function call
 */
bool SaberCondAllocator::isBBCallsProgExit(const SVFBasicBlock* bb)
{
    const FunObjVar* svfun = bb->getParent();
    FunToExitBBsMap::const_iterator it = funToExitBBsMap.find(svfun);
    if (it != funToExitBBsMap.end())
    {
        for (const auto &bit: it->second)
        {
            if (postDominate(bit, bb))
                return true;
        }
    }
    return false;
}

/*!
 * Get complement phi condition
 * e.g., B0: dstBB; B1:incomingBB; B2:complementBB
 * Assume B0 (phi node) is the successor of both B1 and B2.
 * If B1 dominates B2, and B0 not dominate B2 then condition from B1-->B0 = neg(B1-->B2)^(B1-->B0)
 */
SaberCondAllocator::Condition
SaberCondAllocator::getPHIComplementCond(const SVFBasicBlock* BB1, const SVFBasicBlock* BB2, const SVFBasicBlock* BB0)
{
    assert(BB1 && BB2 && "expect nullptr BB here!");

    /// avoid both BB0 and BB1 dominate BB2 (e.g., while loop), then BB2 is not necessarily a complement BB
    if (dominate(BB1, BB2) && ! dominate(BB0, BB2))
    {
        Condition cond = ComputeIntraVFGGuard(BB1, BB2);
        return condNeg(cond);
    }

    return getTrueCond();
}

/*!
 * Compute calling inter-procedural guards between two SVFGNodes (from caller to callee)
 * src --c1--> callBB --true--> funEntryBB --c2--> dst
 * the InterCallVFGGuard is c1 ^ c2
 */
SaberCondAllocator::Condition
SaberCondAllocator::ComputeInterCallVFGGuard(const SVFBasicBlock* srcBB, const SVFBasicBlock* dstBB,
        const SVFBasicBlock* callBB)
{
    const SVFBasicBlock* funEntryBB = dstBB->getParent()->getEntryBlock();

    Condition c1 = ComputeIntraVFGGuard(srcBB, callBB);
    setCFCond(funEntryBB, condOr(getCFCond(funEntryBB), getCFCond(callBB)));
    Condition c2 = ComputeIntraVFGGuard(funEntryBB, dstBB);
    return condAnd(c1, c2);
}

/*!
 * Compute return inter-procedural guards between two SVFGNodes (from callee to caller)
 * src --c1--> funExitBB --true--> retBB --c2--> dst
 * the InterRetVFGGuard is c1 ^ c2
 */
SaberCondAllocator::Condition
SaberCondAllocator::ComputeInterRetVFGGuard(const SVFBasicBlock* srcBB, const SVFBasicBlock* dstBB, const SVFBasicBlock* retBB)
{
    const FunObjVar* parent = srcBB->getParent();
    const SVFBasicBlock* funExitBB = parent->getExitBB();

    Condition c1 = ComputeIntraVFGGuard(srcBB, funExitBB);
    setCFCond(retBB, condOr(getCFCond(retBB), getCFCond(funExitBB)));
    Condition c2 = ComputeIntraVFGGuard(retBB, dstBB);
    return condAnd(c1, c2);
}

/*!
 * Compute intra-procedural guards between two SVFGNodes (inside same function)
 */
SaberCondAllocator::Condition SaberCondAllocator::ComputeIntraVFGGuard(const SVFBasicBlock* srcBB, const SVFBasicBlock* dstBB)
{

    assert(srcBB->getParent() == dstBB->getParent() && "two basic blocks are not in the same function??");

    if (postDominate(dstBB, srcBB))
        return getTrueCond();

    CFWorkList worklist;
    worklist.push(srcBB);
    setCFCond(srcBB, getTrueCond());

    while (!worklist.empty())
    {
        const SVFBasicBlock* bb = worklist.pop();
        Condition cond = getCFCond(bb);

        /// if the dstBB is the eligible loop exit of the current basic block
        /// we can early terminate the computation
        Condition loopExitCond = evaluateLoopExitBranch(bb, dstBB);
        if (!eq(loopExitCond, Condition::nullExpr()))
            return condAnd(cond, loopExitCond);

        for (const SVFBasicBlock* succ : bb->getSuccessors())
        {
            /// calculate the branch condition
            /// if succ post dominate bb, then we get brCond quicker by using postDT
            /// note that we assume loop exit always post dominate loop bodys
            /// which means loops are approximated only once.
            Condition brCond;
            if (postDominate(succ, bb))
                brCond = getTrueCond();
            else
                brCond = getEvalBrCond(bb, succ);

            DBOUT(DSaber, outs() << " bb (" << bb->getName() <<
                  ") --> " << "succ_bb (" << succ->getName() << ") condition: " << brCond << "\n");
            Condition succPathCond = condAnd(cond, brCond);
            if (setCFCond(succ, condOr(getCFCond(succ), succPathCond)))
                worklist.push(succ);
        }
    }

    DBOUT(DSaber, outs() << " src_bb (" << srcBB->getName() <<
          ") --> " << "dst_bb (" << dstBB->getName() << ") condition: " << getCFCond(dstBB)
          << "\n");

    return getCFCond(dstBB);
}


/*!
 * Print path conditions
 */
void SaberCondAllocator::printPathCond()
{

    outs() << "print path condition\n";

    for (const auto &bbCond: bbConds)
    {
        const SVFBasicBlock* bb = bbCond.first;
        for (const auto &cit: bbCond.second)
        {
            u32_t i = 0;
            for (const SVFBasicBlock* succ: bb->getSuccessors())
            {
                if (i == cit.first)
                {
                    Condition cond = cit.second;
                    outs() << bb->getName() << "-->" << succ->getName() << ":";
                    outs() << dumpCond(cond) << "\n";
                    break;
                }
                i++;
            }
        }
    }
}

/// Allocate a new condition
SaberCondAllocator::Condition SaberCondAllocator::newCond(const ICFGNode* inst)
{
    u32_t condCountIdx = totalCondNum++;
    Condition expr = Condition::getContext().bool_const(("c" + std::to_string(condCountIdx)).c_str());
    Condition negCond = Condition::NEG(expr);
    setCondInst(expr, inst);
    setNegCondInst(negCond, inst);
    conditionVec.push_back(expr);
    conditionVec.push_back(negCond);
    return expr;
}

/// Whether lhs and rhs are equivalent branch conditions
bool SaberCondAllocator::isEquivalentBranchCond(const Condition &lhs,
        const Condition &rhs) const
{
    Condition::getSolver().push();
    Condition::getSolver().add(lhs.getExpr() != rhs.getExpr()); /// check equal using z3 solver
    z3::check_result res = Condition::getSolver().check();
    Condition::getSolver().pop();
    return res == z3::unsat;
}

/// whether condition is satisfiable
bool SaberCondAllocator::isSatisfiable(const Condition &condition)
{
    Condition::getSolver().add(condition.getExpr());
    z3::check_result result = Condition::getSolver().check();
    Condition::getSolver().pop();
    if (result == z3::sat || result == z3::unknown)
        return true;
    else
        return false;
}

/// extract subexpression from a Z3 expression
void SaberCondAllocator::extractSubConds(const Condition &condition, NodeBS &support) const
{
    if (condition.getExpr().num_args() == 1 && isNegCond(condition.id()))
    {
        support.set(condition.getExpr().id());
        return;
    }
    if (condition.getExpr().num_args() == 0)
        if (!condition.getExpr().is_true() && !condition.getExpr().is_false())
            support.set(condition.getExpr().id());
    for (u32_t i = 0; i < condition.getExpr().num_args(); ++i)
    {
        Condition expr = condition.getExpr().arg(i);
        extractSubConds(expr, support);
    }

}
