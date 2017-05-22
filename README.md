# MemSentry

The MemSentry pass and runtime of the EuroSys'17 publication "No Need to Hide:
Protecting Safe Regions on Commodity Hardware".

Allows for deterministic isolation of safe regions (part of many systems
security defenses), instead of relying on probabilistic information hiding
(ASLR). MemSentry can be used to enhance existing defenses, and to serve as a
testbed for different (hardware-assisted) protection features.

Currently MemSentry supports:
 - Address-based:
   - SFI: Software fault isolation, mask every pointer so it cannot point to
          safe region.
   - MPX: Intel Memory Protection Extensions: verify every pointer.
 - Domain-based:
   - VMFUNC: Intel VT-x VM-Functions: map/unmap pages in the EPT (requires
             modified hypervisor such as our patched Dune).
   - AES-NI: Intel AES instructions: encrypt safe region.
   - MPK: Intel Memory Protection Keys: upcoming feature to change page
          permissions, for benchmarking purposes only.

MemSentry consists of a number of LLVM passes (developed on LLVM 3.8), a static
library consisting of the core runtime, and additional runtime code/tools
depending on the used feature. For instance, VMFUNC requires a compatible
hypervisor, and the address-based approaches require a certain address-space
layout.

## Usage

To apply the isolation of MemSentry to a defense, it should provide:
 - Safe regions: what information to protect
 - Whitelisted/safe code: what code should be allowed access to the safe region
 - Protection method: how to protect the safe region

### Allocating safe regions

The first thing a defense should indicate is what its safe region is, and thus
what data should be protected by MemSentry. This is done by allocating the safe
region using a special MemSentry function, as follows:

```
#include "memsentry-runtime.h"

...

    char *saferegion = saferegion_alloc(size);
```

The current code assumes such allocations are rare and long-lived, and thus
there is currently no way of freeing this region for example. The defense itself
should take care that the attacker cannot corrupt a pointer to the safe region.


### Allowing access to the safe region

Next, the MemSentry pass needs to know which code is allowed to access the safe
region. The defense should pass this information on to MemSentry, and can do so
in two ways: by calling `memsentry_saferegion_access(ins)` in its own pass
(running before MemSentry), or by placing all code accessing the safe region in
a special section. See the compilation flags for how to pass the name of the
section to MemSentry. A combination of these approaches can be used at the same
time.

### Compilation and protection method

Finally, when applying the defense to a program, MemSentry should be added to
the compilation process: its pass should run (with the appropriate parameters),
and the runtime should be linked in. MemSentry can run either via `opt`, or
during LTO via `ld.gold`. MemSentry benefits most from running after
optimizations, as this will eliminate a large number of memory accesses.

An example of how to run MemSentry is as follows:
```
opt ...
    -defense-passes ...                        # Run defense normally
    -memsentry-prot-method=mpx                 # Protect safe region using MPX
    -memsentry-rw=w                            # Instrument only writes
    -memsentry-whitelist-section=my-functions  # See above
    -memsentry
    ...
```

See `opt -memsentry -help | grep memsentry` for a full list of options.

## Benchmarking

MemSentry can also benchmark different approaches by switching domains at
predetermined points in the application. The frequency of the switches are
a major factor for the performance. For this, the MemSentryBenchDomain pass can
used as follows:

```
opt ...
    -memsentry-benchdomain-points=[call-ret,icall,libfunc]  # Benchmark options
    -memsentry-prot-method=.. -memsenty-max-region-size=..  # MemSentry options
    -memsentry-benchdomain -memsentry -memsentry-benchdomain-post ...
```
