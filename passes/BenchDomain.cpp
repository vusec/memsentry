/*
 * Benchmark performance of domain-based methods by inserting
 * domain-switches at specified points. For benchmarking address-based methods,
 * this pass is not needed.
 *
 * Usage:
 * This pass inserts memory accesses (tagged as 'safe') at the specified points
 * (e.g., at every call/ret). The MemSentry pass will then insert domain
 * switches for these memory accesses. Finally, the MemSentryBenchDomainPost
 * pass will remove the memory accesses, but leave the domain switches. This can
 * thus be used to benchmark the performance of domain-based approaches at
 * different frequencies of required switches.
 * Passes should thus be used as follows:
 *  -memsentry-benchdomain -memsentry -memsentry-benchdomain-post
 *
 * -memsentry-benchdomain-points=[call-ret,icall,libfunc]
 * -memsentry-benchdomain-libfunc-file=<file>
 *
 * call-ret: insert mem access before every call and return
 * icall:    insert mem access before every indirect call
 * libfunc:  insert mem access before every library function call from
 *           specified list.
 */

#define DEBUG_TYPE "memsentry-benchdomain"
#include "utils.h"

#include <set>
#include <fstream>

#include "types.h"
#include "memsentry-pass.h"

using namespace llvm;

enum points {
    CALLRET,
    ICALL,
    LIBFUNC,
};

cl::opt<points> Points("memsentry-benchdomain-points",
    cl::desc("What points should be treated as safe-region accesses:"),
    cl::values(
        clEnumValN(CALLRET, "call-ret", "Every call and return"),
        clEnumValN(ICALL,   "icall",    "Indirect calls"),
        clEnumValN(LIBFUNC, "libfunc",  "Library functions (syscalls), specify list with -memsentry-benchdomain-libfunc-file."),
        clEnumValEnd), cl::init(CALLRET));

static cl::opt<std::string> LibFuncFile("memsentry-benchdomain-libfunc-file",
        cl::desc("Path to file containing (per line) functions that, when called, should be instrumented."));


struct MemSentryBenchDomain : public ModulePass {
    public:
        static char ID;
        MemSentryBenchDomain() : ModulePass(ID) {}

        virtual bool runOnModule(Module &M);

    private:
        std::set<std::string> libFuncSet;

        void initLibFuncs();
        void handleInst(Instruction *I);
        bool shouldInstrCallRet(Instruction *I);
        bool shouldInstrICall(Instruction *I);
        bool shouldInstrLibFunc(Instruction *I);
};


bool MemSentryBenchDomain::shouldInstrCallRet(Instruction *I) {
    if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
        /* Try to only instrument calls where we can also insert the
         * corresponding switch at the return, to better simulate what a defense
         * could do. */
        CallSite CS(I);
        Function *F = CS.getCalledFunction();
        return !F || shouldInstrument(*F);
    }

    if (isa<ReturnInst>(I))
        return true;

    return false;
}

bool MemSentryBenchDomain::shouldInstrICall(Instruction *I) {
    if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
        CallSite CS(I);
        Function *F = CS.getCalledFunction();
        return F == nullptr;
    }

    return false;
}

bool MemSentryBenchDomain::shouldInstrLibFunc(Instruction *I) {
    if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
        CallSite CS(I);
        Function *F = CS.getCalledFunction();

        if (!F)
            return false;

        if (libFuncSet.find(F->getName()) != libFuncSet.end())
            return true;
    }

    return false;
}

void MemSentryBenchDomain::handleInst(Instruction *I) {
    switch (Points) {
        case CALLRET: if (!shouldInstrCallRet(I)) return; break;
        case ICALL:   if (!shouldInstrICall(I))   return; break;
        case LIBFUNC: if (!shouldInstrLibFunc(I)) return; break;
        default: assert(0); break;
    }

    IRBuilder<> B(I);
    Value *Val = B.getInt8(0);
    Value *Ptr = Constant::getNullValue(B.getInt8PtrTy());
    StoreInst *Dummy = B.CreateStore(Val, Ptr, true);
    Dummy->setMetadata("memsentry.benchdomain.dummy", MDNode::get(I->getContext(), {}));

    memsentry_saferegion_access(Dummy);
}

void MemSentryBenchDomain::initLibFuncs() {
    std::ifstream input(LibFuncFile);
    std::string line;
    while (std::getline(input, line))
        libFuncSet.insert(line);

    for (std::string a : libFuncSet)
        errs() << " F: " << a << "\n";
}

bool MemSentryBenchDomain::runOnModule(Module &M) {
    if (Points == LIBFUNC)
        initLibFuncs();

    for (Function &F : M) {
        if (!shouldInstrument(F))
            continue;
        for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
            Instruction *I = &*II;
            handleInst(I);
        }
    }

    return true;
}

char MemSentryBenchDomain::ID = 0;
static RegisterPass<MemSentryBenchDomain> X("memsentry-benchdomain",
        "MemSentry benchmarking pass for domain-based methods");
