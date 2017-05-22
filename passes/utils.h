#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <cassert>

#include <llvm/Pass.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Transforms/Utils/Cloning.h>


#define ifcast(ty, var, val) if (ty *var = dyn_cast<ty>(val))

#ifdef DEBUG_TYPE
#define LOG_LINE(line) (errs() << "[" DEBUG_TYPE "] " << line << '\n')
#else
#define LOG_LINE(line) (errs() << line << '\n')
#endif

#define DEBUG_LINE(line) DEBUG(LOG_LINE(line))

static bool shouldInstrument(llvm::Function &F,
                             std::string *ignoreSection = nullptr) {
    if (F.isDeclaration())
        return false;
    if (F.getName().startswith("_memsentry_"))
        return false;
    if (ignoreSection && !std::string(F.getSection()).compare(*ignoreSection))
        return false;
    return true;
}

#endif /* !UTILS_H */
