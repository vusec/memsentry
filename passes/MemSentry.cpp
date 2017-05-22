/*
 * MemSentry: protecting safe regions on commodity hardware.
 *
 * This pass applies a specified protection to a program. The points that are
 * allowed access should be specified by a previous pass (e.g., BenchDomain or a
 * defense). An alternative to this is to place all code accessing the safe
 * region in its own section, and specify the name of this section to this pass.
 *
 * For address-based approaches, all read, all writes or both read and writes
 * can be instrumented, as specified by the compile-time flag.
 * For certain domain-based approaches the safe-region is pre-allocated, and the
 * size of this region should be specified at compile time.
 *
 * -memsentry-prot-feature=[sfi*,mpx,vmfunc,crypt]
 * -memsentry-whitelist-section=memsentry_functions
 * -memsentry-rw=[r,w,rw*]                           # For sfi/mpx
 * -memsentry-verify-external-call-args=true         # For sfi/mpx
 * -memsentry-max-region-size=4096                   # For crypt
 */

#define DEBUG_TYPE "memsentry"
#include "utils.h"

#include "types.h"
#include "memsentry-pass.h"

using namespace llvm;

cl::opt<prot_method> ProtMethod("memsentry-prot-method",
    cl::desc("Method of protecting safe region:"),
    cl::values(
        clEnumValN(SFI,    "sfi",    "Software fault isolation (pointer masking)"),
        clEnumValN(MPX,    "mpx",    "Intel MPX (memory protection extensions)"),
        clEnumValN(VMFUNC, "vmfunc", "VM-Functions (requires vmfunc-enabled hypervisor like MemSentry's Dune)"),
        clEnumValN(MPK,    "mpk",    "Intel MPK (memory protection keys). Upcoming, implemented as simulation"),
        clEnumValN(CRYPT,  "crypt",  "Encryption (using Intel AES-NI)"),
        clEnumValEnd), cl::init(SFI));

cl::opt<readwrite> ReadWrite("memsentry-rw",
    cl::desc("What type of memory accesses to protect when using address-based approaches:"),
    cl::values(
        clEnumValN(READWRITE, "rw", "Reads and writes"),
        clEnumValN(READ,      "r",  "Reads only"),
        clEnumValN(WRITE,     "w",  "Writes only"),
        clEnumValEnd), cl::init(READWRITE));

static cl::opt<std::string> WhitelistSection("memsentry-whitelist-section",
        cl::desc("Functions in this section are allowed access to the safe region"),
        cl::init("memsentry_functions"));

static cl::opt<bool> VerifyExternalCallArguments(
        "memsentry-verify-external-call-args",
        cl::desc("For address-based methods, add checks to all pointer-type "
            "arguments to external functions (make sure uninstrumented "
            "libraries cannot use invalid pointers."),
        cl::init(true));

static cl::opt<unsigned> MaxRegionSize("memsentry-max-region-size",
        cl::desc("For methods that need to pre-allocate the entire safe-region,"
            " the maximum size that should be supported."),
        cl::init(4096));

/*
 * External function, used to mark instruction as safe from other passes.
 */
void memsentry_saferegion_access(Instruction *I) {
    I->setMetadata(MemSentrySafeMDName, MDNode::get(I->getContext(), {}));
}

static Function *getHelperFunc(Module *M, std::string name) {
    Function *F = M->getFunction(name);
    if (!F) {
        errs() << "Cannot find func '" << name << "'\n";
        exit(1);
    }
    return F;
}

void setGV(Module &M, StringRef name, size_t value) {
    GlobalVariable* GV = M.getNamedGlobal(name);
    if(!GV) {
        errs() << "Error: no " << name << " global variable found\n";
        exit(1);
    }
    Type *Ty = GV->getType()->getPointerElementType();
    Constant *Val = ConstantInt::get(Ty, value);
    GV->setInitializer(Val);
}

static bool hasPointerArg(Function *F) {
    FunctionType *FT = F->getFunctionType();
    for (unsigned i = 0, n = FT->getNumParams(); i < n; i++) {
        Type *type = FT->getParamType(i);
        if (type->isPointerTy())
            return true;
    }
    return false;
}


bool callsIntoWhitelistedFunction(CallSite &CS) {
    Function *F = CS.getCalledFunction();
    if (!F) // Indirect call
        return false;
    return F->getSection() == WhitelistSection;
}


/* Determines whether an instruction should be allowed access to the safe region
 * (i.e., a previous pass has marked it as such).
 */
bool isAllowedAccess(Instruction *I) {
    MDNode *MD = I->getMetadata(MemSentrySafeMDName);
    return MD != NULL;
}

class Protection;

struct MemSentryPass : public ModulePass {
    public:
        static char ID;
        MemSentryPass() : ModulePass(ID) {}
        virtual bool runOnModule(Module &M);

    private:
        Protection *prot;

        void handleInst(Instruction *I);
};

class Protection {
    protected:
        Module *M;
        InlineFunctionInfo *inliningInfo;
        enum prot_method protMethod;
        std::string protMethodStr;
    public:
        Protection(Module *M, enum prot_method protMethod) {
            this->M = M;
            this->inliningInfo = new InlineFunctionInfo();
            this->protMethod = protMethod;
            this->protMethodStr = prot_method_strings[protMethod];
        }
        virtual ~Protection() { }

        virtual void handleLoadInst(LoadInst *LI) {
            handleMemInst(LI);
        }
        virtual void handleStoreInst(StoreInst *SI) {
            handleMemInst(SI);
        }
        virtual void handleLoadIntrinsic(MemTransferInst *MTI) {
            handleMemInst(MTI);
        }
        virtual void handleStoreIntrinsic(MemIntrinsic *MI) {
            handleMemInst(MI);
        }
        virtual void handleMemInst(Instruction *I) {
            assert(0 && "Not implemented");
        }

        virtual void handleCallInst(CallSite &CS) = 0;


        /*
         * Inline calls to _memsentry_<protMethod>*. This is done afterwards,
         * instead of immediately, so the optimizeBB function can more easily
         * see (and optimize) region changes.
         */
        void inlineHelperCalls(Function &F) {
            bool has_changed;
            do {
                has_changed = false;
                for (inst_iterator it = inst_begin(F), E = inst_end(F); it != E; ++it) {
                    Instruction *I = &(*it);
                    CallInst *CI = dyn_cast<CallInst>(I);
                    if (!CI)
                        continue;
                    Function *F = CI->getCalledFunction();
                    if (!F)
                        continue;
                    if (F->getName().startswith("_memsentry_" + protMethodStr)) {
                        InlineFunction(CI, *inliningInfo);
                        has_changed = true;
                        break;
                    }
                }
            } while (has_changed);
        }
        virtual void postInstrumentation() {
            for (Function &F : *M) {
                if (!shouldInstrument(F, &WhitelistSection))
                    continue;
                inlineHelperCalls(F);
            }
        }
};


class AddressProtection : public Protection {
    protected:
        Function *checkFunc;

        Value* verifyPtr(Value *ptrVal, Instruction *I) {
            if (isa<Constant>(ptrVal)) {
                //LOG_LINE("+ Ignoring constant " << *I);
                return ptrVal;
            }
            //LOG_LINE("Masking " << *I);
            IRBuilder<> B(I);
            Value *funcArg = B.CreateBitCast(ptrVal, checkFunc->getFunctionType()->getParamType(0));
            Value *masked = B.CreateCall(checkFunc, { funcArg });
            Value *casted = B.CreateBitCast(masked, ptrVal->getType());
            return casted;
        }
    public:
        AddressProtection(Module *M, enum prot_method protMethod)
            : Protection(M, protMethod) {
                std::string checkFuncName = "_memsentry_" + protMethodStr;
                checkFunc = getHelperFunc(M, checkFuncName);
            }

        virtual void handleLoadInst(LoadInst *LI) {
            if (!isAllowedAccess(LI))
                LI->setOperand(0, verifyPtr(LI->getOperand(0), LI));
        }

        virtual void handleStoreInst(StoreInst *SI) {
            if (!isAllowedAccess(SI))
                SI->setOperand(1, verifyPtr(SI->getOperand(1), SI));
        }

        virtual void handleLoadIntrinsic(MemTransferInst *MTI) {
            if (!isAllowedAccess(MTI))
                MTI->setSource(verifyPtr(MTI->getRawSource(), MTI));
        }

        virtual void handleStoreIntrinsic(MemIntrinsic *MI) {
            if (!isAllowedAccess(MI))
                MI->setDest(verifyPtr(MI->getRawDest(), MI));
        }

        /* Verify pointer args to external functions if flag is set. */
        void handleCallInst(CallSite &CS) {
            Function *F = CS.getCalledFunction();
            if (!VerifyExternalCallArguments)
                return;
            if (callsIntoWhitelistedFunction(CS))
                return;
            if (CS.isInlineAsm())
                return;
            if (!F)
                return; /* Indirect call */
            if (!F->isDeclaration() && !F->isDeclarationForLinker())
                return; /* Not external */

            if (F->isIntrinsic() && hasPointerArg(F)) {
                switch (F->getIntrinsicID()) {
                    case Intrinsic::dbg_declare:
                    case Intrinsic::dbg_value:
                    case Intrinsic::lifetime_start:
                    case Intrinsic::lifetime_end:
                    case Intrinsic::invariant_start:
                    case Intrinsic::invariant_end:
                    case Intrinsic::eh_typeid_for:
                    case Intrinsic::eh_return_i32:
                    case Intrinsic::eh_return_i64:
                    case Intrinsic::eh_sjlj_functioncontext:
                    case Intrinsic::eh_sjlj_setjmp:
                    case Intrinsic::eh_sjlj_longjmp:
                        return; /* No masking */
                    case Intrinsic::memcpy:
                    case Intrinsic::memmove:
                    case Intrinsic::memset:
                    case Intrinsic::vastart:
                    case Intrinsic::vacopy:
                    case Intrinsic::vaend:
                        break; /* Continue with masking */
                    default:
                        errs() << "Unhandled intrinsic that takes pointer: " << *F << "\n";
                        break; /* Do mask to be sure. */
                }
            }

            Instruction *I = CS.getInstruction();
            for (unsigned i = 0, n = CS.getNumArgOperands(); i < n; i++) {
                Value *Arg = CS.getArgOperand(i);
                if (Arg->getType()->isPointerTy()){
                    verifyPtr(Arg, I);
                }
            }
        }

};

class DomainProtection : public Protection {
    protected:
        Function *beginFunc, *endFunc;
        std::string beginFuncName, endFuncName;

        void changeDomain(Instruction *I) {
            CallInst *CIb = CallInst::Create(beginFunc);
            CIb->insertBefore(I);
            CallInst *CIe = CallInst::Create(endFunc);
            CIe->insertAfter(I);
        }

        /*
         * Optimizes a basicblock by merging regions which have no mem accesses
         * or so in between, thus eliminating needless switching of regions.
         * Returns true if the function needs to be called again: when a
         * modification to a BB is made, it cannot continue iterating over that
         * BB.
         */
        bool optimizeBB(BasicBlock &BB) {
            bool inMap = false;
            bool noMemSinceUnmap = false;
            Instruction *lastUnmap = NULL;

            for (Instruction &II : BB) {
                Instruction *I = &II;
                LoadInst *LI = dyn_cast<LoadInst>(I);
                StoreInst *SI = dyn_cast<StoreInst>(I);
                MemIntrinsic *MI = dyn_cast<MemIntrinsic>(I);
                CallInst *CI = dyn_cast<CallInst>(I);
                if (LI || SI || MI)
                    noMemSinceUnmap = false;
                else if (CI) {
                    Function *F = CI->getCalledFunction();
                    if (!F)
                        continue;
                    if (F->getName() == beginFuncName) {
                        assert(!inMap);
                        inMap = true;
                        if (noMemSinceUnmap) {
                            lastUnmap->eraseFromParent();
                            I->eraseFromParent();
                            return true;
                        }
                    }
                    else if (F->getName() == endFuncName) {
                        assert(inMap);
                        inMap = false;
                        noMemSinceUnmap = true;
                        lastUnmap = I;
                    }
                    else {
                        noMemSinceUnmap = false;
                    }
                }
            }
            (void)inMap; /* Silence compiler, assert doesn't count as use. */
            return false;
        }
    public:
        DomainProtection(Module *M, enum prot_method protMethod)
            : Protection(M, protMethod) {
                beginFuncName = "_memsentry_" + protMethodStr + "_begin";
                endFuncName = "_memsentry_" + protMethodStr + "_end";
                beginFunc = getHelperFunc(M, beginFuncName);
                endFunc = getHelperFunc(M, endFuncName);
            }

        virtual void handleMemInst(Instruction *I) {
            if (isAllowedAccess(I))
                changeDomain(I);
        }

        void handleCallInst(CallSite &CS) {
            if (callsIntoWhitelistedFunction(CS))
                changeDomain(CS.getInstruction());
        }

        virtual void postInstrumentation() {
            // Optimize domain-based instrumentation by removing unnecessary
            // switches back and forth.
            for (Function &F : *M) {
                if (!shouldInstrument(F, &WhitelistSection))
                    continue;

                for (BasicBlock &BB : F) {
                    unsigned cnt = 0;
                    while (optimizeBB(BB)) cnt++;
                    //LOG_LINE("Optimized away " << cnt << " domain switches in " << F.getName());
                }
                inlineHelperCalls(F);
            }
        }
};



static Protection* getProtectionInstance(Module *M, enum prot_method protMethod) {
    switch(protMethod) {
        case SFI:
        case MPX:
            return new AddressProtection(M, protMethod);

        case VMFUNC:
        case MPK:
        case CRYPT:
            return new DomainProtection(M, protMethod);

        default:
            assert(0 && "Not implemented!");
            return NULL;
    }
}

void MemSentryPass::handleInst(Instruction *I) {
    ifcast(LoadInst, LI, I) {
        if (ReadWrite != WRITE)
            prot->handleLoadInst(LI);
    }
    else ifcast(StoreInst, SI, I) {
        if (ReadWrite != READ)
            prot->handleStoreInst(SI);
    }
    else ifcast(MemIntrinsic, MI, I) {
        MemTransferInst *MTI = dyn_cast<MemTransferInst>(MI);
        if (MTI && ReadWrite != WRITE)
            prot->handleLoadIntrinsic(MTI);
        if (ReadWrite != READ)
            prot->handleStoreIntrinsic(MI);
    }
    else if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
        CallSite CS(I);
        prot->handleCallInst(CS);
    }
}



bool MemSentryPass::runOnModule(Module &M) {
    LOG_LINE("Starting, ProtMethod=" << prot_method_strings[ProtMethod]);

    // Fix up tracking variables so static lib knows compilation params
    setGV(M, "_memsentry_prot_method", ProtMethod);
    setGV(M, "_memsentry_max_region_size", MaxRegionSize);

    // Get right instrumentation class (address-based or domain-based)
    this->prot = getProtectionInstance(&M, ProtMethod);

    for (Function &F : M) {
        if (!shouldInstrument(F, &WhitelistSection))
            continue;
        LOG_LINE("Instrumenting " << F.getName());
        for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
            Instruction *I = &*II;
            handleInst(I);
        }
    }

    // Optimize inserted instrumentation further if need be.
    LOG_LINE("Optimizing...");
    this->prot->postInstrumentation();

    return true;
}

char MemSentryPass::ID = 0;
static RegisterPass<MemSentryPass> X("memsentry", "MemSentry pass");
