/*
 * Should be used in conjuction with -memsentry-benchdomain, and should run
 * after -memsentry.
 * See BenchDomain.cpp for more details.
 */

#define DEBUG_TYPE "memsentry-benchdomain-post"
#include "utils.h"

#include "types.h"

using namespace llvm;


struct MemSentryBenchDomainPost : public FunctionPass {
    public:
        static char ID;
        MemSentryBenchDomainPost() : FunctionPass(ID) {}
        virtual bool runOnFunction(Function &F);
};

bool MemSentryBenchDomainPost::runOnFunction(Function &F) {
    if (!shouldInstrument(F))
        return false;

    SmallVector<Instruction *, 16> DummyInstructions;

    for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
        Instruction *I = &*II;
        MDNode *MD = I->getMetadata("memsentry.benchdomain.dummy");
        if (MD)
            DummyInstructions.push_back(I);
    }

    bool changed = false;
    for (Instruction *I : DummyInstructions) {
        changed = true;
        I->eraseFromParent();
    }

    return changed;
}

char MemSentryBenchDomainPost::ID = 0;
static RegisterPass<MemSentryBenchDomainPost> X("memsentry-benchdomain-post", "MemSentry benchmarking pass for domain-based methods - cleanup pass");
