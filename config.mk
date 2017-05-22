# Configures which LLVM to use

# Ubuntu 16.04 system LLVM
CLANG    := clang
OPT      := opt-3.8
LLINK    := llvm-link-3.8
LLVMCONF := llvm-config-3.8

# Local (asserts enabled)
#LLVMPATH := /path/to/llvm/install/bin
#CLANG    := $(LLVMPATH)/clang
#OPT      := $(LLVMPATH)/opt
#LLINK    := $(LLVMPATH)/llvm-link
#LLVMCONF := $(LLVMPATH)/llvm-config
