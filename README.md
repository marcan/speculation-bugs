# CPU security bugs caused by speculative execution

This repo is an attempt to collect information on the class of information
disclosure vulnerabilities caused by CPU speculative execution that were
disclosed on January 3rd, 2018.

Existing nomenclature is inconsistent and there is no agreed-upon name for the
entire class of bugs, but the names Spectre and Meltdown have been used for
subclasses of attacks.

This is a combination of publicly available information and educated guesses/
speculation based on the nature of the attacks. Pull requests with corrections
or discussion are welcome.

Table of Contents
=================

   * [Common attack characteristics](#common-attack-characteristics)
   * [Attacks](#attacks)
      * [[MISPREDICT] Branch mis-prediction leaks subsequent data](#mispredict-branch-mis-prediction-leaks-subsequent-data)
      * [[BTI] Branch Target Injection](#bti-branch-target-injection)
      * [[PRIV-LOAD] Privileged data reads from unprivileged code](#priv-load-privileged-data-reads-from-unprivileged-code))
      * [[PRIV-REG] Privileged register reads from unprivileged code](#priv-reg-privileged-register-reads-from-unprivileged-code)
   * [Impacted CPU matrix](#impacted-cpu-matrix)
   * [PoCs](#pocs)
   * [Deployed or in-development mitigations](#deployed-or-in-development-mitigations)
      * [[PRIV-LOAD] Linux: KPTI](#priv-load-linux-kpti)
      * [[BTI] Linux: retpolines](#bti-linux-retpolines)
      * [[BTI] Linux: IBRS patch series](#bti-linux-ibrs-patch-series)
      * [[PRIV-LOAD] Windows: KB4056892 (OS Build 16299.192)](#priv-load-windows-kb4056892-os-build-16299192)
   * [CPU Vendor response](#cpu-vendor-response)
   * [Software/Service Vendor response](#softwareservice-vendor-response)
   * [Future Speculation](#future-speculation)
   * [References](#references)

## Common attack characteristics

All of the attacks cause information disclosure from higher-privileged or
isolated same-privilege contexts, leaked via an architectural side channel,
typically the CPU data cache. The basic premise is that CPU speculative
execution is not clean and can persistently alter such microarchitectural state,
even when the speculated instructions are rolled back and should never have run.
Malicious software can trigger these "impossible" instruction sequences and then
observe the result through a side channel, leaking information.

This is a CPU bug that violates the isolation guarantees of the architecture.
Future CPUs are likely to include partial hardware solutions as well as require
OS cooperation (i.e. an architecture definition change adding requirements to
system software). Pure software- or hardware- based solutions are unlikely to
be comprehensive or have acceptable performance.

The specific exploits involve various ways of exploiting speculative execution.
Different CPUs from various vendors are affected in different ways, and
software mitigations also vary.

So far, all exploits rely on exfiltrating data via the data cache. A value is
speculatively obtained, then an indirect load is performed that can bring in
data into the cache from a different address depending on one or more bits of
the value to be leaked.

## Attacks

### [MISPREDICT] Branch mis-prediction leaks subsequent data

Google name: **Variant 1: Bounds check bypass**\
Research name: **Spectre**\
CVE: **CVE-2017-5753**

The CPU mispredicts a branch and speculatively executes code which leaks
sensitive data into a data cache load.

Sample code:

```C
unsigned long untrusted_offset_from_caller = ...;
if (untrusted_offset_from_caller < arr1->length) {
 unsigned char value = arr1->data[untrusted_offset_from_caller];
 unsigned long index2 = ((value&1)*0x100)+0x200;
 if (index2 < arr2->length) {
   unsigned char value2 = arr2->data[index2];
 }
}
```

If `untrusted_offset_from_caller` is out of bounds, the CPU may speculatively
read `value` and then cause a cache load from `arr2` that depends on it. The
attacker can then profile loads from `arr2` (directly or by invoking other code)
to determine which cache line was loaded, and thus one bit of `value`.

The attacker need not necessarily control `arr2` directly. Cache loads can be
detected indirectly, e.g. because they caused some other data to be evicted.
This can potentially work from an entirely different process.

#### Attack scenarios

* JITs/interpreters: Easy. Sandbox escape (same-context leak). Shared
memory/threads make it easier.
* Same-CPU cross-process: Medium. Attacker needs to trigger the vulnerable code
in the vulnerable process, then get a signal from the cache directly (e.g. by
timing accesses to memory which has colliding cache tags on the same CPU core
or sharing a level of cache). This includes attacks on the kernel and on
hypervisors.
* Remote/service: Hard. Attacker needs some way of triggering the vulnerable
code, then getting a timing signal back from the relevant cache lines. Probably
not practical in most circumstances.

#### Mitigations

A serialization instruction can be inserted between the condition check and the
read from `arr2` in order to force the speculation to be resolved. This may be
microarchitecture-specific in order to make the right guarantees.

A complete fix without manual involvement (e.g. marking security-critical code)
seems impractical, short of disallowing all speculative memory accesses
entirely. Heuristics such as disallowing speculative memory accesses whose
address depends on previously speculatively fetched data will probably fix most
(but not all) practical cases.

Compilers may be able to make a better judgement on which code patterns are
likely to be dangerous and insert the appropriate serialization instructions.

### [BTI] Branch Target Injection

Google name: **Variant 2: Branch target injection**\
Research name: **Spectre**\
CVE: **CVE-2017-5715**

The CPU indirect branch predictor can be "trained" to mis-predict an indirect
branch into an attacker-controlled destination. This can then leak data via the
cache. Chaining multiple gadgets ending in indirect branches, ROP-style, is
possible.

This attack requires intimate knowledge of the inner workings of the CPU branch
prediction implementation. This does not mitigate the attack, but does make
exploitation more difficult (and makes cross-platform attacks much harder).

#### Attack scenarios
* JIT: Tricky, but probably possible with careful instruction massaging?
* Same-cpu cross-process: Possible. Includes attacks on the kernel/hypervisor.
* Remote/server: Not possible.

#### Mitigations

Disable indirect branch prediction entirely by using an alternative instruction
sequence. This is microarchitecture-specific. Requires recompiling all code with
this sequence.

Flush branch predictor state on privilege level changes and context switches.
Causes some performance loss (how much?). Current CPUs do not implement a
mechanism to do this this. Hyperthreading makes things more complicated, as two
threads of different privilege level or isolation may be running on the same CPU
and sharing the branch prediction resources. Complete fix may require disabling
hyperthreading or introducing OS scheduler changes to ensure that sibling
threads are always owned by the same application/user/security context.

Ideally future CPUs would guarantee that hyperthreads have independent branch
prediction resources to avoid sharing state, and/or would have efficient methods
of isolating branch prediction state (e.g. tagging prediction entries with a
process/protection key).

### [PRIV-LOAD] Privileged data reads from unprivileged code

Google name: **Variant 3: Rogue data cache load**\
Research name: **Meltdown**\
CVE: **CVE-2017-5754**

Some CPUs will perform speculative memory reads from memory that the current
context does not have access to read. While these accesses will ultimately fail,
their result can be used in further speculation and thus leak. This chiefly
allows userspace to read kernel (and thus physical) memory.

#### Attack scenarios

* JIT: Possible. Combined with [MISPREDICT], can read arbitrary kernel memory.
* Same-cpu cross-privilege: Easy. Combine with [MISPREDICT] to avoid
actual page faults (not required).
* Remote/service: Same as [MISPREDICT] on affected systems. Probably not
practical.

This is by far the worst attack on affected systems, as it allows physical
memory reads from Javascript on major browsers.

#### Mitigations

Do not map privileged address space into unprivileged contexts at all. On
systems without a functional mechanism to do this without TLB flushing (e.g.
PCID) that actually prevents the speculative load, this will incur a significant
performance penalty.

### [PRIV-REG] Privileged register reads from unprivileged code

ARM name: **Variant 3a**

A variant of [PRIV-LOAD], where instead of memory, a privileged system register
is being read.

#### Attack scenarios

* JIT: Not possible.
* Same-cpu cross-privilege: Easy, but limited impact.
* Remote/service: Not possible.

## Impacted CPU matrix

### Intel

| CPU/µArch                      | MISPREDICT     | BTI                       | PRIV-LOAD         | PRIV-REG |
| ------------------------------ | -------------- | ------------------------- | ----------------- | -------- |
| i486                           | N              | N                         | N                 | N        |
| Nehalem                        | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Westmere                       | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Sandy Bridge                   | Y<sup>3</sup>  | Y<sup>[1](#intel-1)</sup> | **Y**<sup>2</sup> |          |
| Ivy Bridge                     | Y<sup>3</sup>  | Y<sup>[1](#intel-1)</sup> | **Y**<sup>2</sup> |          |
| Haswell                        | Y<sup>3</sup>  | Y<sup>[1](#intel-1)</sup> | **Y**<sup>2</sup> |          |
| Broadwell                      | Y<sup>3</sup>  | Y<sup>[1](#intel-1)</sup> | **Y**<sup>2</sup> |          |
| Skylake                        | Y<sup>3</sup>  | Y<sup>[1](#intel-1)</sup> | **Y**<sup>2</sup> |          |
| Kaby Lake                      | Y<sup>3</sup>  | Y<sup>[1](#intel-1)</sup> | **Y**<sup>2</sup> |          |
| Coffee Lake                    | Y<sup>3</sup>  | Y<sup>[1](#intel-1)</sup> | **Y**<sup>2</sup> |          |
| Knights Landing                | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Knights Mill                   | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Avoton                         | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Rangeley                       | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Apollo Lake                    | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Denverton                      | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| SoFIA                          | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Lincroft                       | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Cloverview                     | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Bay Trail                      | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Tunnel Creek                   | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |
| Stellarton                     | Y?<sup>4</sup> | Y<sup>[1](#intel-1)</sup> | Y?<sup>4</sup>    |          |

2: [Meltdown paper](https://meltdownattack.com/meltdown.pdf) confirms
[PRIV-LOAD] on Ivy Bridge, Haswell, Skylake. Sibling microarchitectures presumed
vulnerable too.\
3: [Spectre paper](https://meltdownattack.com/spectre.pdf) confirms
[MISPREDICT],[BTI] on Ivy Bridge, Haswell, Skylake. Sibling microarchitectures
presumed vulnerable too.\
4: Presumed affected since the issues appear to be pervasive to Intel CPUs and
no counterexamples are known yet.

### AMD

| CPU/µArch                      | MISPREDICT              | BTI                      | PRIV-LOAD               | PRIV-REG |
| ------------------------------ | ----------------------- | ------------------------ | ----------------------- | -------- |
| Zen (17h)                      | Y<sup>[1](#amd-1)</sup> | Y?<sup>[1](#amd-1)</sup> | N<sup>[1](#amd-1)</sup> |          |

### ARM

See [ARM Vendor Response](#arm-1) for source.

| CPU/µArch                      | MISPREDICT | BTI   | PRIV-LOAD | PRIV-REG |
| ------------------------------ | ---------- | ----- | --------- | -------- |
| Cortex-R7                      | Y          | Y     | N         | N        |
| Cortex-R8                      | Y          | Y     | N         | N        |
| Cortex-A8 (under review)       | Y          | Y     | N         | N        |
| Cortex-A9                      | Y          | Y     | N         | N        |
| Cortex-A15 (under review)      | Y          | Y     | N         | Y        |
| Cortex-A17                     | Y          | Y     | N         | N        |
| Cortex-A57                     | Y          | Y     | N         | Y        |
| Cortex-A72                     | Y          | Y     | N         | Y        |
| Cortex-A73                     | Y          | Y     | N         | N        |
| Cortex-A75                     | Y          | Y     | **Y**     | N        |
| All others                     | N          | N     | N         | N        |

### IBM

Red Hat [says](https://access.redhat.com/security/vulnerabilities/speculativeexecution)
System Z, POWER8, POWER9 are affected.

IBM says firmware patches will be available January 9 for POWER7 and up:  https://www.ibm.com/blogs/psirt/potential-impact-processors-power-family/

### Apple

No info.

### Nvidia

No info (CPUs). GPUs not affected.

### Qualcomm

No info.

### Marvell

No info.

### Cavium

No info.

### Samsung

No info.

## PoCs

### [MISPREDICT] Google Project Zero: basic same-process PoC

Platforms:
* Intel Haswell Xeon
* AMD FX CPU
* AMD PRO CPU
* ARM Cortex A57

Not an actual attack against real software, just a [PoC](https://gist.github.com/ErikAugust/724d4a969fb2c6ae1bbd7b2a9e3d4bb6) with synthetic code.

### [MISPREDICT] Google Project Zero: arbitrary kernel reads with eBPF JIT

Platforms:
* Intel Haswell Xeon CPU
* AMD PRO CPU

A process running with normal user privileges under a modern Linux kernel with a
distro-standard config, can perform arbitrary reads in a 4GiB range in kernel
virtual memory.

This is an interpreter/JIT attack in the kernel. On Haswell, it works in both
JIT and interpreter mode, as the speculation seems to be deep enough to reach
even in interpreter mode. On AMD, JIT is required.

Mitigation: AMD: disable eBPF JIT (`net.core.bpf_jit_enable` sysctl). Intel:
disable BPF entirely?

### [BTI] Google Project Zero: HV guest root process can read host physical memory

Platforms:
* Intel Haswell Xeon CPU

A process running with root privileges inside a KVM guest created using
virt-manager, with a specific (now outdated) version of Debian's distro kernel
running on the host, can read host kernel memory at a rate of around 1500
bytes/second, with room for optimization. 

Mitigation: None yet. Kernel/compiler patches in the works.

### [PRIV-LOAD] Google Project Zero: Partial kernel memory read from userspace

Platforms:
* Intel Haswell Xeon CPU

A process running with normal user privileges can read kernel memory under some
precondition, presumed to be that the targeted kernel memory is present in the
L1D cache.

Mitigation: KPTI.

## Deployed or in-development mitigations

### [PRIV-LOAD] Linux: KPTI

Linux kernel page-table isolation. Shipped in Linux 4.14.11 and will ship in
4.15. 4.14.11 version is rough around the edges; future versions should fix
further issues.

### [BTI] Linux: retpolines

* [Retpoline: a software construct for preventing branch-target-injection](https://support.google.com/faqs/answer/7625886)

Still in development.

Kernel assembly mitigation + compiler mitigation (both for kernel and userspace)
that uses a different code sequence (using the `ret` instruction) to avoid
the indirect branch predictor on Intel CPUs. Instead, retpolines set up a fake
return address prediction (using the return address stack, which is specific to
`call`/`ret`) that leads to an infinite loop, thus poisoning speculative
execution.

This incurs some small performance impact for every indirect branch. Requires
recompiling all affected software (not just the kernel, but all of userspace)
for full mitigation.

This is microarchitecture-specific and thus not necessarily applicable to all
CPUs. Kernel implementation will likely enable it only when a vulnerable CPU is
detected. In fact, it's insufficient on Skylake and newer CPUs, where even `ret`
may predict from the indirect branch predictor as a fallback; those need IBRS.

### [BTI] Linux: IBRS patch series

[Patchset](https://lkml.org/lkml/2018/1/4/615) (under review).

Support for Intel's architectural mitigation in lieu of retpolines. Required
on Skylake and newer, where even retpolines may be vulnerable. Requires
microcode update on current CPUs. Perf hit vs. retpolines on older CPUs. Future
CPUs will have "cheap" support.

### [PRIV-LOAD + BTI] Windows: KB4056892 (OS Build 16299.192)

Out-of-band update. Presumably does roughly the same thing as KPTI. Also [contains IBRS support](https://twitter.com/aionescu/status/948818841747955713).

Some AV software is incompatible (probably due to evil kernel hooks). AV users
require this registry key to be set for the fix to be enabled:

```
Key="HKEY_LOCAL_MACHINE"
Subkey="SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat"
Value Name="cadca5fe-87d3-4b96-b7fb-a231484277cc"
Type="REG_DWORD”
Data="0x00000000”
```

A PowerShell command has been [detailed](https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution) (installable via `Install-Module SpeculationControl`) called `Get-SpeculationControlSettings` which shows the status of both mitigations.

Microsoft mentions at this time server operating systems must explicitly enable mitigations.

## CPU Vendor response

### Intel

* [Intel responds to security research findings](https://newsroom.intel.com/news/intel-responds-to-security-research-findings/)

PR fluff. No real content. Tries to deflect blame. No useful technical
information.

* [Speculative Execution and Indirect Branch Prediction Side Channel Analysis Method](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00088&languageid=en-fr)

Security advisory. Applies to [BTI]. Contains list of CPU marketing names
affected.

* [Intel Issues Updates to Protect Systems from Security Exploits](https://newsroom.intel.com/news-releases/intel-issues-updates-protect-systems-security-exploits/)
* [Intel Analysis of Speculative Execution Side Channels](https://newsroom.intel.com/wp-content/uploads/sites/11/2018/01/Intel-Analysis-of-Speculative-Execution-Side-Channels.pdf)

For [MISPREDICT], recommends an `LFENCE` barrier.

For [BTI], Intel is introducing new interfaces to the CPU through microcode:

* `IBRS`: Indirect Branch Restricted Speculation: Marketing-speak for "we
flipped a chicken bit", presumably.
* `STIBP`: Single Thread Indirect Branch Predictors isolates branch prediction
state between two hyperthreads.
* `IBPB`: Indirect Branch Predictor Barrier instruction prevents leakage of
indirect branch predictor state across contexts (for use on context/privilege
switches).

Alternatively, Intel is recommending retpolines for [BTI], especially on current
processors where that may be faster than the microcode patches for `IBPB`.
Retpolines also require a microcode patch on Broadwell and newer CPUs,
presumably because on those even `ret` ends up being predicted in an exploitable
way.

For [PRIV-LOAD], Intel recommends KPTI. Processors supporting PCID have reduced
performance impact. Future CPUs will have a hardware fix.

TODO: further info on microcode updates released.

### AMD

* [AMD Update on Processor Security](https://www.amd.com/en/corporate/speculative-execution)

Claims "near zero" risk for [BTI] but offers no proof. This suggests reliance
on obscurity (AMD's branch predictor has not yet been reverse engineered).
Assume vulnerable unless proven otherwise.

AMD CPUs are affected by [MISPREDICT] and not affected by [PRIV-LOAD].

TODO: [Gentoo bug 643476](https://bugs.gentoo.org/643476) claims microcode
update to disable branch prediction (entirely?) on family 17h (Zen) is
available ([SUSE notice](https://lists.opensuse.org/opensuse-security-announce/2018-01/msg00005.html)).
Performance impact unknown.

### ARM

* [ARM Processor Security Update](https://developer.arm.com/support/security-update)

Comprehensive list of affected ARM CPUs.

For [MISPREDICT], ARM recommends using a newly defined barrier `CSDB` together
with a conditional move to guard the loaded value with the preceding condition.

For [BTI] there is no architectural solution, but specific implementations may
have branch prediction control features that may allow for mitigation.

For [PRIV-LOAD], there is an Aarch64 implementation of KPTI which uses ASID to
isolate the two address spaces, avoiding TLB maintenance overhead.

For [PRIV-REG] the impact is small (KASLR bypass), but can be mitigated by
having the kernel use dummy values or a different virtual base for registers
that might hold virtual kernel addresses while in usermode (e.g. ensure
`VBAR_EL1` doesn't leak the true main kernel base).

### IBM

No response.

### Nvidia

* [NVIDIA's response to speculative side channels](http://nvidia.custhelp.com/app/answers/detail/a_id/4609)

GPUs not affected. SoC info and mitigations work in progress. Pending further
info.

### Apple

No response on the CPU side of things for Apple's custom ARM cores.

## Software/Service Vendor response

### Google Chrome

* [Actions Required to Mitigate Speculative Side-Channel Attack Techniques](https://www.chromium.org/Home/chromium-security/ssca)

Enable Site Isolation in `chrome://flags` to prevent cross-origin exploitation
of same-process vulns (e.g. JIT).

Starting with Chrome 64, the V8 JS engine will have additional mitigations
(which?). Also `SharedArrayBuffer` is being disabled. This makes the attacks
harder (but is not a perfect fix).

### Mozilla Firefox

* [Mitigations landing for new class of timing attack](https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/)

Removing `SharedArrayBuffer` and reducing resolution of `performance.now()` to
20µs. This makes the attacks harder (but is not a perfect fix).

Starting with Firefox 57.0.4, [both techniques are enabled](https://www.mozilla.org/en-US/security/advisories/mfsa2018-01/).

### Microsoft Edge / IE

* [Mitigating speculative execution side-channel attacks in Microsoft Edge and Internet Explorer](https://blogs.windows.com/msedgedev/2018/01/03/speculative-execution-mitigations-microsoft-edge-internet-explorer/)

Removing `SharedArrayBuffer` and reducing resolution of `performance.now()` to
20µs plus random jitter. This makes the attacks harder (but is not a perfect
fix).

### Google (all products)

* [Google’s Mitigations Against CPU Speculative Execution Attack Methods](https://support.google.com/faqs/answer/7622138)

Summary:

* Android: 2018-01-05 Security Patch Level mitigates by restricting high
precision timers. KPTI not included yet.
* Chrome OS: Version 63 includes KPTI on Intel machines with kernel 3.18/4.4.
* Cloud: Infrastructure has been hitlessly patched. Guest instances for
Cloud Dataflow/Cloud Datalab/Cloud Dataproc/Cloud Launcher/Cloud Machine
Learning Engine/Compute Engine/Kubernetes Engine need to be updated/restarted
with fixes.

### Apple

* [About speculative execution vulnerabilities in ARM-based and Intel CPUs](https://support.apple.com/en-us/HT208394)

Mitigations for [PRIV-READ] shipped in iOS 11.2, macOS 10.13.2, and tvOS 11.2.
watchOS is not impacted. Claims no performance impact.

Safari mitigations incoming for [BTI] and [MISPREDICT]. <2.5% perf impact.

### Red Hat

[Advisory](https://access.redhat.com/security/vulnerabilities/speculativeexecution) and mitigations for CVE-2017-5754, CVE-2017-5753 and CVE-2017-5715 released. Expected [performance impact analysis](https://access.redhat.com/articles/3307751) on different scenarios released, based on Red Hat's own testing. 

### Ubuntu

Preliminary [Advisory](https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SpectreAndMeltdown) published with no mitigations/patches released so far for Ubuntu Linux.

### VMware

[Advisory](https://www.vmware.com/us/security/advisories/VMSA-2018-0002.html) and patches for ESXi 5.5, 6.0 and 6.5 released.
Patch for ESXi 5.5 lacks mitigation for CVE-2017-5753.

### Cisco

[Advisory](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180104-cpusidechannel) released, but no mitigations or vulnerable product confirmation so far.

## Future Speculation

[BTI], [PRIV-READ], and [PRIV-REG] are CPU implementation bugs that are easily
fixable in newer silicon (with some OS support for [BTI]). [MISPREDICT] is,
however, inherent in how modern speculation works, and may change how we have to
think about writing secure code in the future, much like how we think about
memory races and atomicity in multithreaded code today. In the future, I expect
we'll end up seeing speculation guard compiler intrinsics and teaching people to
use them.

## References

* [Google Project Zero blog post](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html)
* [Meltdown paper](https://meltdownattack.com/meltdown.pdf)
* [Spectre paper](https://spectreattack.com/spectre.pdf)
* [LWN summary of the vulnerabilities](https://lwn.net/SubscriberLink/742702/e23889188fce9f7f/)
* [LWN collection of Meltdown/Spectre posting](https://lwn.net/Articles/742999/)
* [ARM Processor Security Update](https://developer.arm.com/support/security-update)
* [ARM Cache-speculation Side-channels whitepaper](https://developer.arm.com/-/media/Files/pdf/Cache_Speculation_Side-channels.pdf?revision=966364ce-10aa-4580-8431-7e4ed42fb90b&la=en)
* [AMD Update on Processor Security](https://www.amd.com/en/corporate/speculative-execution)
* [Intel responds to security research findings](https://newsroom.intel.com/news/intel-responds-to-security-research-findings/)
* [Intel: Speculative Execution and Indirect Branch Prediction Side Channel Analysis Method](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00088&languageid=en-fr)
* [Intel Issues Updates to Protect Systems from Security Exploits](https://newsroom.intel.com/news-releases/intel-issues-updates-protect-systems-security-exploits/)
* [Intel Analysis of Speculative Execution Side Channels](https://newsroom.intel.com/wp-content/uploads/sites/11/2018/01/Intel-Analysis-of-Speculative-Execution-Side-Channels.pdf)
* [Windows 10 KB4056892](https://support.microsoft.com/en-us/help/4056892/windows-10-update-kb4056892)
* [Chrome: Actions Required to Mitigate Speculative Side-Channel Attack Techniques](https://www.chromium.org/Home/chromium-security/ssca)
* [Chrome: Mitigation with Site Isolation](http://www.chromium.org/Home/chromium-security/site-isolation)
* [Mozilla: Mitigations landing for new class of timing attack](https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/)
* [MS Edge/IE: Mitigating speculative execution side-channel attacks in Microsoft Edge and Internet Explorer](https://blogs.windows.com/msedgedev/2018/01/03/speculative-execution-mitigations-microsoft-edge-internet-explorer/)
* [Google’s Mitigations Against CPU Speculative Execution Attack Methods](https://support.google.com/faqs/answer/7622138)
* [About speculative execution vulnerabilities in ARM-based and Intel CPUs](https://support.apple.com/en-us/HT208394)
* [Retpoline: a software construct for preventing branch-target-injection](https://support.google.com/faqs/answer/7625886)
* [VMSA-2018-0002VMware ESXi, Workstation and Fusion updates address side-channel analysis due to speculative execution](https://www.vmware.com/us/security/advisories/VMSA-2018-0002.html)
* [Redhat: Kernel Side-Channel Attacks - CVE-2017-5754 CVE-2017-5753 CVE-2017-5715](https://access.redhat.com/security/vulnerabilities/speculativeexecution)
* [Ubuntu: Information Leak via speculative execution side channel attacks (CVE-2017-5715, CVE-2017-5753, CVE-2017-5754 aka Spectre and Meltdown)](https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SpectreAndMeltdown)
* [Cisco: CPU Side-Channel Information Disclosure Vulnerabilities](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180104-cpusidechannel)
