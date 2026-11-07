Portal Go system-wide AEC investigation, October 2, 2026

RESULT
AEC was not disabled. No working system-wide change was found using the existing ADB shell or an ordinary installed app. This does not prove that privileged access can never be obtained.

DEVICE
192.168.1.72:5555, PortalGo / terry
Facebook/terry_prod/terry:10/QKQ1.210213.001/5051355900018050:user/prod-keys
Shell UID 2000, SELinux Enforcing, ro.debuggable=0, verified boot green, bootloader locked.

NEW FINDINGS
1. A public older terry firmware dump provides the vendor libraries and native service binaries that the current device denies to both shell and an ordinary app. The analyzed dump is version 5051319600009050, not the device's exact version. Static findings therefore require on-device validation.
Source: https://dumps.tadiphone.dev/dumps/facebook/terry

2. TuningManagerService has setStaxParam(int appType, int parameter, float/int value), plus tuning load and restore methods. Its native vendor Binder interface is com.facebook.vendor.audio.ITuningManagerService. Direct access to /dev/vndbinder is denied to shell by SELinux. A copied vndservice binary falls back to the regular Binder driver, so a successful service listing does not mean vendor Binder access worked. Audit logs explicitly confirm the denial.

3. The tuning service contains an Audio Weaver TCP server gated by persist.vendor.audio.stax.awe.server.enable, default false. A direct attempt to set it to true failed. The related persist.vendor.audio.stax_enable_debug property is also protected. The server was not enabled. It is a tuning entry point, not itself an AEC-off switch.

4. The separate com.facebook.alohasdk.audio.IAudioDebugServiceManager exposes collection and file retrieval through a callback Binder. It is a diagnostic API, not an AEC setter. An attempt to bind with a real callback failed, with an explicit SELinux denial of Binder transfer from shell to audiodebug_domain. The daemon remained alive with the original PID 3552.

5. All three known AudioServiceManager binding variants were checked. Synchronous bind2 and getAudioService throw SecurityException for missing com.facebook.alohasdk.permission.PLATFORM_AUDIO. Legacy one-way bind returns no service and logs the same permission check. A successful one-way transact is not a successful bind.

6. /dev/stax-ctrl is system:audio, mode 0660, SELinux audio_device. Shell is not in the audio group. Vendor binaries and HAL libraries were also inaccessible to a temporary ordinary app and its run-as context.

7. audio_parameter_updates is an AudioService cache used to reapply AudioSystem parameters after service recovery. It is not a DSP control socket.

8. Installed aiservice code defines NS_MODE bits for statistical suppression (1), data-driven suppression (2) and residual echo suppression (4). It initializes STATISTICAL_PLUS_RESIDUAL_ECHO. This is distinct from AEC_ENABLE. Disabling linear AEC alone would not necessarily disable residual echo suppression. No parameter values were read or changed successfully on this device.

9. Installed packages were checked for DEBUGGABLE. No Meta app was debuggable. The only debuggable package found was the temporary read probe created during this investigation.

LIMITS
No new acoustic A/B recordings were made. The earlier pink-noise results were not independently remeasured. No bootloader unlock, exploit, firmware flash, reboot or system partition modification was attempted. No microphone gain workaround was added. The repository was not changed.

ARTIFACTS
firmware/: older firmware binaries, symbols and annotated disassembly
ai/, services/, analytics/, settings/: decompiled installed APKs
bugreport.zip, bugreport.txt: current device diagnostics, kept locally
final-audio-state.txt: audio state and relevant SELinux audit entries
BindProbe.java, DebugBindProbe.java, ReadProbe.java: local probe source

ACCESS NEEDED
A verified privileged execution path that can access the DSP control device or a Meta-authorized audio service is still needed. Persistent changes would additionally need testing across capture restarts and reboot. No claim is made that a root command alone would bypass SELinux or provide persistence.


FOLLOW-UP INVESTIGATION, October 2, 2026

DSP processing is still not disabled. No DSP parameter was changed in this follow-up.

10. CVE-2024-31317 is patched in the exact installed framework, despite
ro.build.version.security_patch reporting 2020-08-05. Pulled the device's
/system/framework/framework.jar and decompiled android.os.ZygoteProcess.
maybeSetApiBlacklistExemptions explicitly rejects newline, carriage return and
NUL at lines 449-454 of ZygoteProcess.java. This matches the published fix.
The community unmetaportal account-cleanup technique relies on this bug and
therefore does not provide an access path on this build. No injection payload
was applied. hidden_api_blacklist_exemptions remains null.
Reference: https://rtx.meta.security/exploitation/2024/06/03/Android-Zygote-injection.html

11. The installed AI APK exports AiInternalControlService and
SmartCameraInternalControlService without manifest-level permissions, but their
Binder methods enforce ACCESS_SMART_CAMERA_CONTROL_SERVICE through Meta's
SmartCameraIPCPermissionManager. Exported does not mean callable without the
internal permission checks. AiInternalControlService only accepts the
voice_activity_detection session property in this build. It does not expose a
raw DSP parameter setter. The native AudioService setters remain separate.
Evidence: ai-manifest.txt and ai/sources/com/facebook/alohaapp/app/services/smartcamera/service/.

12. Traced all direct calls to fb_tms_set_stax_param_float/int in the older
firmware audio HAL. They handle speaker volumes, battery level, board
temperature and significant motion. These are not arbitrary microphone DSP
parameter forwarding paths. The older HAL still cannot establish the exact
current firmware's behavior. No speculative AudioSystem parameter was set.

13. A new read-only shell helper attempted to bind AiInternalControlService
and request its version. The app_process command exited 137 with Killed before
printing a binding result. This attempt does not establish that service binding
or its permission check succeeded or failed. Static checks in item 11 are the
evidence for the service restrictions. Source: ControlServiceProbe.java.
The temporary dex was removed from /data/local/tmp afterward.

14. Direct tinymix access still fails with Failed to open mixer. No custom
native dump handler was found in the older AudioServiceManager or tuning service
symbols and current dumpsys calls returned no useful control interface.

No firmware flash, bootloader unlock, reboot, persistent setting change,
repository edit or acoustic A/B test was performed in this follow-up.
Remaining requirement: a working privileged execution path or an accessible
vendor interface that can read and write the actual capture DSP parameters.


ADDITIONAL INVESTIGATION, October 2, 2026, 19:09-19:25 UTC

AEC was not disabled. No DSP parameter was successfully read or changed.

15. Reconfirmed the connected target is PortalGo / terry at 192.168.1.72:5555,
firmware 5051355900018050, shell UID 2000, SELinux Enforcing, verified boot
green and bootloader locked.

16. Tested legacy com.facebook.aloha.AlohaService, separate from
IAudioServiceManager. Transaction 15 (getAudioProcessingParam) returned
exception code -1. Transaction 29 (setProperty) attempting to enable
persist.vendor.audio.stax.awe.server.enable also returned -1. Logcat explicitly
reported missing com.facebook.alohasdk.permission.USE_PLATFORM_SDK for that
attempt. The property was empty before and after. No tuning server was enabled.
An older firmware alohamanager binary additionally contains a
SET_VENDOR_PROPERTY check and property-prefix filtering. This older binary is
supporting static evidence, not proof of exact current implementation.

17. Traced installed AI app noise suppression code. C2QL.A0D initializes
STATISTICAL_PLUS_RESIDUAL_ECHO. A0J has a DISABLED branch but it is private and
the discovered caller passes the fixed enabled mode. No accessible off control
was found. Public high/low methods adjust suppression limits, not the AEC
switch. The only references to AEC_ENABLE in the decompiled AI Java sources
are the parameter enumeration.

18. Copied the current libvraudio.so. Its service exposes spatial playback
worlds, sound positions, room reverb and playback controls. No capture DSP
parameter setter was found in its exported interface.

19. The actual DSP is exposed through dbmd_7-spi, dbmdx-stax and dbmdx-codec
under /sys/bus/spi/devices/spi32766.0. /dev/dbmdx-1 through -3 and
/dev/stax-ctrl are system:audio mode 0660. Shell cannot access the inspected
sysfs attributes, including /sys/devices/virtual/misc/stax-ctrl/version.
No module parameter directory was present for dbmdx_core or dbmdx_stax.
No writable shell control was found. No driver writes were attempted.

20. Copied the installed vendor.facebook.hardware.alohamanagervendor@1.0.so.
Its nonstandard HIDL method is hasBeenReceivedBefore, not an audio setter.
lshal debug of IAlohaManagerVendor/default reported no service or no permission
to connect. The service is listed but listing does not establish access.

No app was installed, no recording was made, no service was stopped and no
firmware was flashed. No reboot, exploit or bootloader unlock was attempted.
The failed property write left the value unchanged. Repository files were
not edited. New artifacts are device.apk and decompiled device/, the current
framework jars and native interface libraries plus the older alohamanager
binary and its disassembly in firmware/.


CONTINUED RESEARCH, October 2, 2026, through 20:22 UTC

21. CVE-2024-0044 installer/run-as forgery: exact current Android 10
PackageManager Settings.writePackageListLPrInternal does not put the installer
package name in packages.list. The documented Android 12/13 attack route is
absent. No payload was submitted. See PackageSettings.java.

22. Current retail MobileConfig providers export debug_only_* query paths,
but debug_only_set_overridden_configs and debug_only_service_command are
empty handlers. The ordinary read query attempted returned no result.
The Settings Debug page can be opened with MAIN action and
extra_settings_location_ordinal=9. Its MobileConfig button did not open the
editor. The editor code separately checks the internal-debug MC flag.
SettingsContentProvider additionally checks ACCESS_SETTINGS internally.

23. Found official Meta Portal 4.9 kernel source:
https://github.com/facebookincubator/Portal-Kernel/tree/portal-msm-4.9-kernel-master
Commit b4577154e48224e7ee1fe07a59656c10e7ea8b7e, published June 24, 2026,
build label 3051355900000000. Makefile is 4.9.227, matching the running kernel
version, but source-to-installed-binary identity has NOT been established.
The source includes CVE-2019-2215 poll cleanup, CVE-2022-20421 reference
cleanup, CVE-2023-20938/21255 failure-boundary fix and CVE-2023-33107 GPU
range-overflow checks. Do not infer exact device patch status from this alone.
The published GPU interface has no modern timeline or VBO interface used by
CVE-2022-22057 and CVE-2024-23380.

24. Built and ran a native access diagnostic, no malformed requests or exploit.
/dev/kgsl-3d0 opens from shell. Read-only KGSL queries report chip 0x06010501
and version fields 3.14 / 3.1. /dev/stax-ctrl, /dev/dbmdx-1 and
/dev/snd/controlC0 all return EACCES. A harmless one-entry BPF array-map
creation also returns EACCES. Source: kernel-access-probe.c.
Published stax driver exposes ioctl blobs but no alternative bypass sysfs knob.

25. Current /vendor/etc/audio_effects.conf comments out the Qualcomm AEC/NS
implementations. AudioFlinger lists no loaded AEC or NS effect, so the
Android AudioEffect interface does not expose this DSP processing.
Pulled all 17 current /vendor/etc/audio/terry files to current-tuning/.
Current DSP module binaries remain unreadable to shell.

26. Fresh acoustic baseline reproduced suppression using temporary MicProbe:
MIC, 16kHz mono, media14: quiet -37.5/-47.6 dBFS, playback -72.1/-72.5.
Test spkr_vol=-96 sent AFTER playback began: quiet -47.9, playback -73.7.
HAL logs confirm receiving the key, but no improvement. Restored spkr_vol
to -12.5, which is the existing media14 render level confirmed in logs.
No recordings were stored, only level statistics.

27. Older TMS disassembly shows supported voice_call_type values
0,4,5,6,7,8 map to capture parameter30011 values 0,1,4,5,2,6.
Live voice_call_type=8 produced a successful TMS capture parameter write
(apptype=0, parameter30011, value6), disproving an inference that an empty
shell getprop value means capture processing is unconfigured. Properties can
be unreadable to shell. Profile8 test: quiet -51.4, playback -73.3.
Restored voice_call_type=0. Other supported profiles are being tested.
The earlier statement no DSP parameters were changed applies to previous
rounds, not these temporary profile tests. AEC_ENABLE was not written.

28. Completed additional profile tests, MIC 16kHz mono, media14:
voice_call_type=7 (DSP value2): quiet -54.4, playback -74.6 dBFS.
voice_call_type=6 (DSP value5): quiet -52.6, playback -73.9 dBFS.
voice_call_type=5 (DSP value4): quiet -54.7, playback -72.5 dBFS.
Each command was sent before capture and again after playback started.
TMS logs confirm actual writes to capture parameter30011 and restoration
to value0 after every run. None disabled speaker-correlated suppression.
The baseline and test statistics do not establish speech intelligibility
during music because there was no independent speech source.

29. Cleanup: MicProbe uninstalled successfully, native diagnostic and UI
XML removed from /data/local/tmp, KS relaunched. Media volume was restored
to14. No AEC_ENABLE or NS_MODE write, kernel exploit, reboot, bootloader
unlock or firmware flash was performed. No repository edits.
Logs: profile-test-log.txt. Temporary helper sources retained locally.
Current result: hardware echo cancellation has NOT been disabled.


CONTINUED RESEARCH, October 2, 2026, through 21:50 local time

30. Extracted the exact installed kernel from Meta OTA build
5051355900018050 and reconstructed its ELF and kallsyms. The public Portal
4.9 source accepts the running config with no diff. Generated structure
offsets and compared 53 exploit symbols against the installed kernel with no
mismatches. The installed remove_waiter implementation is vulnerable to the
CVE-2026-43499 GhostLock primitive. CVE-2024-31317 is patched in the exact
framework and is not the selected route.

31. Ported the public NVIDIA Shield GhostLock implementation to the exact
Portal build. The Portal requires signal-return stack stamping because its
multicast setsockopt stack frame does not overlap the stale futex waiter. A
safe signal-return self-test passed. A compatibility probe also confirmed the
required futex, scheduler, ping socket, ashmem, configfs, virtual-address and
/proc/pid/mem behavior.

32. Corrected KernelSnitch for the Portal 4.9 private futex-key layout, which
stores mm before address. The kernel also randomizes memstart_addr, so a narrow
scan beginning at PAGE_OFFSET cannot find mm_struct on most boots. Added an
exact slab-tiled scan of the full 256 GiB linear-map window. It successfully
leaked mm_struct at ffffffcd2ae33b80 and reclaimed its order-2 slab page at
ffffffcd2ae30000.

33. The first successful page leak reached the GhostLock signal-return trigger
while the payload still used the old ffffffc0 direct-map assumption. The
Portal rebooted before a KASLR pointer or privilege change was obtained.
Network ADB disabled at reboot as documented for this device. The Portal and
Kiosk Satellite returned normally on the network and the Kiosk web service at
port 2324 responds. Port 5555 remains closed until ADB is enabled over USB.

34. Added per-run direct-map calculation from the leaked mm_struct address.
The allocator normally places mm_struct slabs in the Normal zone beginning at
physical 0x100000000. For the successful leak this resolves memstart_addr to
fffffff400000000 and the kernel image linear alias to ffffffcc80080000, which
explains the stale-alias reboot. Added GHOSTLOCK_STOP_AFTER_PAGE so the live
alias can be verified after ADB is restored without entering the GhostLock
trigger. The rebuilt preload SHA-256 is
e3961489472f78db03bc863809df65dec5a920410f3517a14555e8639ffed421.

Current result: hardware echo cancellation remains enabled. The next step is
to restore ADB over USB, run page-only alias verification, inspect pstore and
then retry the KASLR stage with the runtime alias.


CONTINUED RESEARCH, October 2, 2026, through 22:15 local time

35. Two independent page-only runs on boot eac7a910-8ad3-45f8-a025-c26a85f35b19
leaked mm_struct at fffffff7043bad80 and fffffff70a1c3b80. Both resolved
memstart_addr to ffffffca00000000 and the kernel image linear alias to
fffffff680080000. Both exited before the GhostLock trigger with UID 2000.
This confirms the runtime alias calculation across separate allocations.

36. A fixed-base, stop-after-FOPS run on the next allocation resolved
memstart_addr to ffffffc9c0000000 and the kernel alias to fffffff6c0080000.
The Portal rebooted during the signal-return route before arbitrary read/write
or cleanup completed. Kiosk Satellite and its port 2324 service recovered.
UID, SELinux and audio processing were not changed.

37. Source review found two causes in the unvalidated Portal FOPS route. The
signal-return variant ignored GHOSTLOCK_SLIDE_FOPS_ROUTE and retained the
boot-ID leak write target. The fixed-base path also skipped initialization of
the consumer delay, allowing sched_setattr to race before rt_sigreturn copied
the forged waiter onto the kernel stack. The exact disassembly confirms the
stale waiter at syscall stack offset -0x238 and the FPSIMD copy destination at
-0x270, so the existing 0x38 vregs offset is correct.

38. Corrected the FOPS signal-return target, added a 50 ms post-handler delay
and restored the equivalent delay in the alternate main route. Added a
scratch-only rb_erase checkpoint that writes only inside the reclaimed page
and skips ashmem open. The rebuilt preload SHA-256 is
2ec0871389cf54044a104e02b64ca0019b5c7109d941e10041ba2aed73556333.

Current result: hardware echo cancellation remains enabled. Network ADB is
off after the reboot. The next run should use the scratch-only checkpoint
after ADB is restored over USB, then proceed to the cleanup-verified FOPS
checkpoint only if that route returns cleanly.

39. The full reclaim spray reached the signal-return stamp cleanly, proving
the prior low-volume spray had not reliably replaced the freed slab. Source
tracing then showed that PAGE_PAYLOAD_FOPS performs its first constrained
write during FUTEX_CMP_REQUEUE_PI, before the signal-return trigger. The
so-called scratch route changed only the later write, leaving ashmem fops
pointing at the reclaimed page until reboot. Added a pre-signal CFI path that
verifies arbitrary read/write, restores boot-ID and ashmem fops and holds the
waiter asleep without entering the later PI-chain trigger. The rebuilt preload
SHA-256 is c74368774e4201c1be629c24d1f9a51c7bdd3fbbdba1dff059e5085d49fc36c1.

Current result: hardware echo cancellation remains enabled. Network ADB must
be restored once more. The next checkpoint now restores the temporary global
pointer before holding the still-sleeping waiter.

40. The pre-signal checkpoint held the waiter safely and kept the Portal,
Kiosk Satellite and network ADB stable. CFI stopped at step 4 because ashmem
still exposed its original operations. The initial rb_erase write used the
runtime linear alias of ashmem_misc.fops. Changed this target to the known
writable canonical .data address, leaving runtime aliases only for the
reclaimed page itself. Added logging of the exact readback on a future miss.
The held process was released with a normal reboot. The rebuilt preload
SHA-256 is 76f602797858478ec79f9f402fc00d2b121592b500951f601e6be27aaaedc6ee.

Current result: hardware echo cancellation remains enabled. The Portal and
Kiosk Satellite recovered normally. Network ADB requires USB enablement for
the canonical-target checkpoint.

41. The canonical-target pre-signal run also stopped at CFI step 4. The
ashmem read returned zero bytes and the expected fake table was absent. This
proves the initial requeue does not perform the constrained write. The write
occurs during the later priority adjustment. Review also found the earlier
scratch mode redirected only the signal-frame node while the reclaimed-page
node still targeted ashmem. Updated scratch mode so both rb-tree removals
write only inside the reclaimed page. The held process was released with a
normal reboot. The rebuilt preload SHA-256 is
019120a2e60761515ec8c2fd876934fb44f67f9a036a2c077094321dd73a8c82.

Current result: hardware echo cancellation remains enabled. The next run is
the first fully isolated test of whether the post-signal priority chain itself
returns safely without modifying ashmem.

42. The fully isolated scratch run still rebooted after the signal-return
stamp, proving the failure is inside rt_mutex_adjust_prio_chain rather than an
ashmem user racing the temporary pointer. With nice 1, the stale waiter has
priority 121 and displaces the fake sentinel at priority 130. That enters the
fake owner's incomplete pi_waiters and scheduler state. Added a controlled
GHOSTLOCK_SIGRETURN_NICE setting. Nice 19 gives the stale waiter priority 139,
so the sentinel stays on top. The constrained rb_erase still runs, while the
owner update branch becomes a no-op and the chain can return after observing
fake_task.pi_blocked_on as NULL. The rebuilt preload SHA-256 is
d8f3f1837cd08e57e2f1a7a63ae31b52cd403e27071226b8ade2ca20166e8de7.

Current result: hardware echo cancellation remains enabled. Network ADB must
be restored for the isolated nice-19 branch test.

43. The isolated nice-19 run still rebooted after the signal-return stamp.
Added independent control of the forged waiter's priority and extended the
nice control to zero. The next diagnostic uses SCHED_BATCH nice 0 and forged
waiter priority 120. Those equal values make rt_mutex_adjust_pi return before
locking the fake mutex or removing either rb-tree node. A clean return will
confirm signal-frame placement and isolate the failure to the tree-write path.
The rebuilt preload SHA-256 is
7216259b6e74a34e9d11e415d0eb148ddffc68409b7694cce8832cadea6e8a81.

Current result: hardware echo cancellation remains enabled. Network ADB must
be restored for the equal-priority early-exit probe.

44. The equal-priority probe also rebooted after the signal-return stamp.
This does not yet distinguish a bad stack overlap from a sched_setattr path
whose effective kernel priority differs from the requested nice value. Added
GHOSTLOCK_SIGRETURN_NO_SCHED. It performs the same rt_sigreturn FPSIMD copy,
then the consumer acknowledges the trigger without making any scheduler
syscall. A clean return will prove the stack placement itself is safe. The
rebuilt preload SHA-256 is
dcf7fbd8b6280b2ae95aff6db7ec7cc1a1ee083ebe55c585ffb3618d62e1784c.

Current result: hardware echo cancellation remains enabled. Network ADB must
be restored for the no-scheduler signal-return control.

45. Exact call-chain disassembly initially identified all three frames but the
recorded sum was wrong by 0x100. The corrected stale waiter is at syscall
SP-0x288: sys_futex uses 0x80 bytes, do_futex uses 0x140,
futex_wait_requeue_pi uses 0x1a0 and its rt_mutex_waiter begins at frame offset
0xd8. rt_sigreturn starts its FPSIMD copy at SP-0x270, so it misses the first
0x18 bytes of the waiter and cannot stamp the complete object. The pselect and
multicast routes also cannot stamp the complete waiter.

46. Found an exact unprivileged replacement in PTRACE_SETREGSET for a stopped
descendant. The installed call chain uses sys_ptrace 0x50, arch_ptrace 0x10,
ptrace_request 0xe0, ptrace_regset 0x40 and fpr_set 0x280. fpr_set copies a
0x210-byte user FPSIMD state beginning at syscall SP-0x3a0. The corrected stale
waiter therefore begins at offset 0x118 in the copy and fits completely. Implemented a
ptrace route that prepares a traced child before creating the dangling waiter,
stamps the waiter through NT_PRFPREG and supports a post-route hold so cleanup
cannot cause a false reboot during validation.

Current result: hardware echo cancellation remains enabled. The corrected
ptrace route is built and ready for a no-scheduler live-hold test once network
ADB is available.

47. The first ptrace route passed its no-scheduler live-hold control. The
traced descendant stopped normally, PTRACE_SETREGSET returned zero with an
iovec length of 0x210. The consumer acknowledged the copy without entering
sched_setattr. The waiter returned to userspace and the process remained alive
at the explicit post-route checkpoint. The Portal stayed responsive, SELinux
remained enforcing, ADB stayed connected and Kiosk Satellite returned HTTP
200. Later arithmetic review showed that this control wrote at offset 0x18,
which is 0x100 below the actual waiter. It proves the ptrace copy itself is
stable but does not validate waiter replacement.

Current result: hardware echo cancellation remains enabled. The next test is
the equal-priority scheduler probe through the corrected ptrace route after a
normal reboot clears the held dangling state.

48. The equal-priority scheduler probe through the first ptrace implementation
entered sched_setattr and rebooted Android. Kiosk Satellite recovered with
HTTP 200 and network ADB returned to its normal disabled-after-reboot state.
Rechecking the installed prologues exposed an arithmetic error: 0x80 + 0x140 +
0x1a0 - 0xd8 is 0x288, not 0x388. The real waiter starts at syscall SP-0x288,
so the ptrace FPSIMD payload belongs at offset 0x118 from its SP-0x3a0 copy
destination. Updated the implementation and comments to use offset 0x118.

Current result: hardware echo cancellation remains enabled. The next run is a
no-scheduler live-hold control at the corrected offset 0x118. Only after that
stays stable should the equal-priority scheduler probe be repeated.

49. The corrected offset 0x118 passed the no-scheduler live-hold control.
PTRACE_SETREGSET returned zero with an iovec length of 0x210, the waiter
returned to userspace and the process reached the explicit post-route hold.
The Portal remained responsive, SELinux stayed enforcing, ADB reported device
and Kiosk Satellite returned HTTP 200. A normal reboot cleared the held
dangling state and Kiosk Satellite recovered normally. Added an explicit
GHOSTLOCK_PTRACE_MATCH_TASK_PRIO diagnostic that derives the waiter priority
and scheduler update from the target thread's observed policy and nice value.
The normal ptrace and FOPS routes retain their forged priority defaults.

Current result: hardware echo cancellation remains enabled. Network ADB needs
USB enablement for the corrected equal-priority scheduler probe.

50. The corrected equal-priority probe passed. The waiter thread reported
SCHED_OTHER, nice 0 and kernel priority 120. PTRACE_SETREGSET stamped priority
120 at offset 0x118, the consumer forced a SCHED_BATCH policy change and
sched_setattr returned zero. The process reached the post-route hold. SELinux
remained enforcing, ADB stayed connected and Kiosk Satellite returned HTTP
200. This validates the complete waiter replacement and the exact
rt_mutex_adjust_pi early-return comparison on the installed build.

Current result: hardware echo cancellation remains enabled. The next
checkpoint uses the corrected ptrace placement with nice 19 and redirects the
rb_erase write entirely into the reclaimed page. This keeps the original
ashmem operations pointer untouched while validating the PI-chain return.

51. The first corrected-offset scratch run reached the scheduler trigger but
did not return and Android restarted. Kiosk Satellite stayed available or
recovered with HTTP 200. The failure is explained by transitive PI donation:
the nice 0 owner waits on f_pi_chain and donates effective priority 120 to the
target waiter. sched_setattr(nice 19) therefore leaves task->prio at 120. The
reinserted stale waiter outranks the priority-130 sentinel and enters the fake
owner's deliberately incomplete pi_waiters state. Added controls to set both
the waiter and owner threads to nice 19 before either PI lock is taken. With
both sides at effective priority 139, the priority-130 sentinel remains the
top waiter after rb_erase and the fake-owner update branch should stay a no-op.

Current result: hardware echo cancellation remains enabled. The next scratch
checkpoint must set GHOSTLOCK_SLIDE_WAITER_NICE=19 and
GHOSTLOCK_SLIDE_OWNER_NICE=19 along with GHOSTLOCK_SIGRETURN_NICE=19.

52. The all-nice-19 scratch run still restarted Android, but the separate
equal-priority control proved the priority model. With both PI participants at
nice 19, /proc reported priority 39 and inferred task->prio 139 after the
cycle formed. A priority-139 ptrace stamp then made sched_setattr return zero
through the early-exit branch and reached the live hold. The remaining scratch
failure is therefore after fake-lock acquisition, not priority donation.
Added GHOSTLOCK_SLIDE_NO_OWNER for the next isolated route. With the
priority-130 sentinel remaining top across the priority-139 reinsertion, an
ownerless fake lock returns directly after the scratch-only rb_erase and
avoids all fake task_struct accesses.

Current result: hardware echo cancellation remains enabled. The next scratch
checkpoint adds GHOSTLOCK_SLIDE_NO_OWNER=1 to the three nice-19 controls.

53. Added GHOSTLOCK_RB_ERASE_NO_CHILD to split fake-lock and tree validation
from the one-child constrained write. In this diagnostic the forged stale
node is red with no children, so rb_erase only clears a pointer inside the
reclaimed page. Combined with the ownerless lock and unchanged sentinel top,
the chain should return without a rebalance, wakeup or fake task access. A
successful no-child hold will prove fake-lock acquisition and basic tree
reinsertion before restoring the scratch child pointer.

54. The first ownerless no-child attempt became unresponsive during setup,
before the waiter logged its scheduler state or created the ptrace tracee.
Kiosk Satellite timed out briefly and then recovered with HTTP 200 after the
Portal restarted. This attempt did not reach the PI-chain diagnostic. Added
GHOSTLOCK_RECLAIM_ORDER2_ONLY so the immediate and burst reclaim stages use
the exact order-2 fragment layout that matches the freed mm_struct slab page.
The earlier mixed spray alternated those exact fragments with larger sends,
which left only half of the immediate reclaim attempts with the verified
base-relative payload layout.

55. The ptrace stack stamper did not honor GHOSTLOCK_RB_ERASE_NO_CHILD. The
first two purported no-child runs therefore repeated the known one-child
scratch graph. Added the missing branch and explicit stamp logging. The first
actual no-child run logged a zero left child and still restarted the Portal
after sched_setattr entered the forged lock path.

56. Verified the installed rb-tree color encoding and exact rb_erase
disassembly. Linux uses low bit 0 for red and low bit 1 for black. The stale
node's aligned parent value already marks it red and the sentinel value 1
already marks the one-node root black. A temporary diagnostic reversed these
colors and was discarded. The corrected no-child graph now uses aligned local
scratch as the red node's synthetic parent while retaining the black sentinel.
The remaining leading explanation is that the freed order-2 slab page was not
occupied by the expected socket fragment. CONFIG_PSTORE_RAM is enabled, so
the next step is to collect the persistent fault PC before changing reclaim
geometry again.

Current result: hardware echo cancellation remains enabled. Network ADB needs
USB enablement after the last kernel restart so pstore can be collected.

57. Android bugreport can retrieve the ramoops console even though Meta's
SELinux policy denies both the shell and BootReceiver direct access to
/sys/fs/pstore/console-ramoops-0. The first recovered panic is at
rt_mutex_adjust_prio_chain+0x1c0, the load of
lock->waiters.rb_leftmost->lock. The stale waiter is still present but its
lock pointer refers to the original PI mutex, not the prepared fake lock.
This disproves the earlier conclusion in item 50: the equal-priority control
could exit because the old and requested priorities were both 120 and did not
prove that PTRACE_SETREGSET overlapped the stale waiter.

58. A full 0x210-byte ptrace priority carpet with value 139 produced the same
panic. That run still had an effective priority of 120 because the nice 0
waiter donated priority through the owner chain, so it did not provide a
valid overlap oracle. A valid oracle must remove the owner's donation before
the vulnerable waiter leaves FUTEX_WAIT_REQUEUE_PI.

59. The first owner-chain diagnostic attempted to release the owner after the
waiter returned from FUTEX_WAIT_REQUEUE_PI. The persistent log and panic show
that this ordering is impossible: FUTEX_CMP_REQUEUE_PI returned -1/EDEADLK,
the main thread signaled the waiter and the kernel panicked during waiter
cleanup before the post-wait marker. The owner must be removed first while
the waiter's stack object is still live.

60. Signaling the owner before the waiter does not remove the donation on
this kernel. FUTEX_LOCK_PI is restartable here. The signal was handled and
the owner returned to futex_lock_pi with normal nice 19 while the main thread
waited. Added a one-second absolute CLOCK_REALTIME timeout to the owner's
FUTEX_LOCK_PI call. The next diagnostic waits for that timeout and only then
signals the vulnerable waiter.

61. Added GHOSTLOCK_SKIP_FOPS_PAGE_PREP for the priority-carpet diagnostic.
It supplies nonzero placeholder state and skips KernelSnitch, mm_struct slab
preparation and socket reclaim. A successful priority-carpet overlap exits
before any placeholder can be dereferenced, so this removes unrelated
allocator variance from the stack-placement test.

62. Rechecked the exported aiservice control surfaces. Every binder method in
AiInternalControlService and SmartCameraInternalControlService enforces the
smart-camera signature permission for cross-UID callers. AI session
properties expose only voice_activity_detection. The sound-preprocessing
debug dialog writes two shared preferences for WebRTC software AGC and
hardware AGC. It does not call AEC_ENABLE and its hardware AGC preference is
consumed by the calling engine rather than the system capture path. No
exported bridge to setAudioProcessingParam was found.

Current result: hardware echo cancellation remains enabled. The timeout-based
owner-chain diagnostic is built but cannot be deployed until network ADB is
restored after the intentional reboot.

63. The clean timeout-based carpet reached the decisive state and still
panicked. Exact call-chain reconstruction from the installed disassembly
explains why. The dangling waiter reported in pstore belongs to the owner
thread's rt_mutex_slowlock frame, whose waiter is at syscall-entry S-0x368.
The earlier ptrace call ran on the WAIT_REQUEUE_PI thread and therefore wrote
to a different kernel stack. On the owner thread, fpr_set's 0x210-byte buffer
starts at S-0x3a0, so the complete dangling waiter begins at buffer offset
0x38 and fits through offset 0x88. Added GHOSTLOCK_PTRACE_OWNER_STACK to run
PTRACE_SETREGSET on the owner immediately after its controlled timeout, use
offset 0x38 and skip the later waiter-thread stamp.

Current result: hardware echo cancellation remains enabled. The owner-stack
priority-carpet build is ready for the next clean-boot run.

64. The owner-stack priority carpet at ptrace-buffer offset 0x38 changed the
persistent panic from a dereference at 0x23e to a dereference at 0x38 in the
same rt_mutex_adjust_prio_chain+0x1c0 instruction. This proves the ptrace
copy reaches the dangling owner-thread waiter far enough to change its
priority and enter the stale chain. The stale waiter's lock pointer was still
the original PI lock. The route had an unintended 50 ms delay between the
ptrace syscall and sched_setattr, during which interrupts could reuse the
owner's kernel stack and overwrite parts of the forged waiter.

65. Retried with that delay and the spin delay both set to zero, a fully
prepared reclaimed page, a forged waiter priority of 139 and the no-child
scratch graph. The mm_struct page leak and full order-2 reclaim completed. The
owner timed out and logged the intended fake lock fffffffa933b1350 and scratch
parent fffffffa933b3000. The scheduler transition then stopped making progress.
The Portal remained reachable briefly before going offline and rebooting,
consistent with a kernel lockup and watchdog reset rather than the immediate
page fault seen in earlier runs. The next persistent log should identify which
raw spinlock or tree operation stalled.

Current result: hardware echo cancellation remains enabled. Network ADB needs
USB enablement after this watchdog restart so the persistent kernel log can be
collected.

66. Persistent log from the supposed lockup is another immediate
rt_mutex_adjust_prio_chain+0x1c0 null dereference. x20 is the original PI
lock, not the prepared fake lock fffffffa933b1350. The prior interpretation
that the dangling waiter belonged to the owner thread was wrong. The task
being reprioritized is the WAIT_REQUEUE_PI thread, and its pi_blocked_on must
point to that thread's local rt_waiter. Installed disassembly confirms its
placement: sys_futex 0x80, do_futex 0x140 and
futex_wait_requeue_pi.constprop.23 0x1a0 with rt_waiter at frame+0xd8. This is
syscall SP-0x288. The ptrace fpr_set buffer begins at syscall SP-0x3a0, so
the correct input offset remains 0x118 on the WAIT_REQUEUE_PI thread. The
owner timeout only removes priority donation before the waiter is released.
It does not change which stack holds the dangling object.

A scheduler-disabled diagnostic is prepared to report the actual
PTRACE_SETREGSET return value at offset 0x118. Network ADB went offline after
the bugreport and now refuses connections, so USB enablement is required
before running it.

Current result: hardware echo cancellation remains enabled.

67. A scheduler-disabled run proved PTRACE_SETREGSET succeeds on the
WAIT_REQUEUE_PI thread: ret=0, errno=0, iov_len=0x210 and input offset 0x118.
The corrected real run then reclaimed an order-2 page at ffffffc3c95f8000,
stamped fake lock ffffffc3c95f9350 and scratch parent ffffffc3c95fb000, and
completed sched_setattr with ret=0. The forged waiter returned, the route child
exited with status 0 and the parent reached the scratch-only route checkpoint.
This proves the full trigger can return without crashing but does not by itself
prove that rb_erase performed its constrained write.

Current result: hardware echo cancellation remains enabled.



68. The first scratch completion used a forged waiter priority of 139, which
could match the WAIT_REQUEUE_PI task after nice 19 and let rt_mutex_adjust_pi
return before rb_erase. A live fops attempt with priority 139 confirmed that
PTRACE_SETREGSET succeeded but ashmem_misc.fops was unchanged. Retrying the
no-child scratch route with waiter priority 130 also completed cleanly. A live
fops attempt with priority 130 again left ashmem_misc.fops unchanged. The
installed rb_erase path would write the forged parent value if it received the
forged tree node, so either an earlier chain condition is still exiting or a
forged waiter field is not landing at the assumed stack offset. The next run
will log the post-sched_setattr task priority and use the direct-map alias of
ashmem_misc.fops to separate those cases.

Current result: hardware echo cancellation remains enabled.
69. The in-flight ptrace scheduler race eliminated the silent early exit and
caused a controlled kernel panic in rt_mutex_adjust_prio_chain. The panic task
was the scheduler consumer. x28 held the exact expected stale waiter address
ending in 0x3c38, proving the 0x118 overlap calculation. The forged priority
had landed and started the chain, but waiter->lock at x20 contained unrelated
kernel-stack data instead of the fake lock. The normal 0x210-byte arm64
copy_from_user implementation copies in increasing address order, so a fault
after offset 0x1c0 can expose a fully written 0x118..0x168 waiter without ever
exposing a partial pointer set. CONFIG_USERFAULTFD is disabled. The next route
uses a two-page input with the second page PROT_NONE, causing the copy to fault
only after the complete forged waiter is live while the remote scheduler
consumer is already looping.

Current result: hardware echo cancellation remains enabled.

70. The PROT_NONE fault-tail run still panicked at
rt_mutex_adjust_prio_chain+0x1c0. The scheduler consumer saw the expected stale
waiter at fffffff853283c38 and the forged priority forced the chain walk, but
the waiter lock register was fffffff8592ef000 instead of the prepared fake
lock fffffff89b639350. The task and next-lock registers both held that same
value. This means ordinary kernel-stack reuse replaced the lock field before
the consumer reached it while the forged priority remained live. A synchronous
PROT_NONE fault returns too quickly to preserve the coherent copied waiter.
The next variant places the byte immediately after the complete waiter on a
cold file-backed page. Its major page fault should hold copy_from_user inside
the syscall while the scheduler consumer uses the fully written waiter.

Current result: hardware echo cancellation remains enabled.

71. The first cold file-backed tail run confirmed the second page was absent
from the page cache before PTRACE_SETREGSET, but the scheduler consumer entered
too early. The panic moved to _raw_spin_trylock+0x18 with x20 equal to the
waiter thread's user-stack area rather than the prepared fake lock. This is a
ptrace call-frame local written over the stale waiter before copy_from_user
replaces the complete object. Added a gated mode that opens the waiter thread's
/proc stat file before the race and makes the consumer wait until that thread
enters uninterruptible D state on the cold page fault. If the page fault is too
short to observe, the consumer performs no second scheduler call and the run
returns safely. The next live checkpoint also uses an ownerless fake mutex so
a successful rb_erase write returns without walking a fake task_struct.

Current result: hardware echo cancellation remains enabled.

72. The matching-priority D-state control still panicked in
_raw_spin_trylock+0x18. The scheduler reached the stale waiter only after the
cold file page became ready and the ptrace frame unwound. x20 was zero, not
the placeholder lock value 1. Waiting for D state therefore identifies the
right page fault but does not keep it blocked long enough. The installed ext4
source takes an inode-wide i_mmap_sem read lock for mapped-file faults and a
write lock while shrinking a file. A live probe showed that truncating warmed
page cache takes about 24 ms for 64 MiB, 47 ms for 128 MiB and 58 ms for
256 MiB. FALLOC_FL_ZERO_RANGE is unavailable on the encrypted userdata file.
The next route maps the ptrace tail from the first page of a file, warms a
separate 64 MiB range in that inode and truncates only the warm range while
copy_from_user faults on the retained first page.

Current result: hardware echo cancellation remains enabled.

73. Auditing the installed `pselect6` call chain ruled it out as a coherent
waiter carrier: its copied fd-set storage begins at syscall entry SP-0x1a8,
well above the stale WAIT_REQUEUE_PI waiter at SP-0x288. Native `sendmmsg`
provides an exact alternative. On this kernel, the nested `sockaddr_storage`
begins at SP-0x290, so an eight-byte prefix followed by the 0x50-byte waiter
lands precisely over the stale object. A connected loopback TCP socket with a
full send buffer keeps that copy live in `sk_stream_wait_memory`. The
equal-priority control observed that wchan, completed one `sched_setattr` call
with ret=0, unblocked through receiver shutdown, and exited cleanly. This
confirms deterministic placement and lifetime without a fault-window race.

Current result: hardware echo cancellation remains enabled.

74. The first live `ashmem_misc.fops` attempt used the default scheduler
transition to nice 1. The forged waiter was reinserted at priority 121 ahead
of the priority-130 sentinel, and the scheduler thread remained in kernel
context at 100% CPU. This matches the ownerless return branch attempting to
wake the new top waiter's forged task pointer. A second attempt changed the
task to priority 139 so the sentinel would remain top, but the device stopped
servicing shell requests and had to reboot before its final trace was
captured. The next build adds entry/return logging around `sched_setattr` and
a non-ashmem proof mode: the same constrained write redirects the boot-id
sysctl data pointer to the pinned fake table, whose first 16 bytes can be read
back through `/proc/sys/kernel/random/boot_id`. Output will be retained in a
file across reboot.

Current result: hardware echo cancellation remains enabled.

75. A reboot-persistent trace located the priority-139 attempt precisely. The
consumer entered `sched_setattr`, never returned, and consumed one CPU in
kernel context. Reading `/proc/sys/kernel/random/boot_id` concurrently still
returned the original UUID, proving the constrained `rb_erase` write had not
executed. The stall is therefore in acquisition of the reclaimed-page fake
mutex, before the tree operation. The next route no longer forges the waiter
lock pointer. `sendmmsg` copies only the eight-byte prefix and 0x18-byte
`rb_node`, preserving the stale waiter's legitimate task, priority and live
PI-mutex pointer. After the original owner-chain timeout, a helper thread at
priority 130 blocks on that real PI mutex and supplies a valid kernel-managed
sentinel. Changing the vulnerable task from priority 120 to 139 then forces
the forged dequeue while keeping the helper as the top waiter, allowing the
real owner and lock graph to provide the return path.

Current result: hardware echo cancellation remains enabled.

76. The first preserve-lock run reached the scheduler consumer despite its
retained userspace trace ending at the owner-timeout checkpoint. Ramoops shows
the expected stale waiter in x28, but waiter->lock in x20 was the userspace
pointer 0x7da29e5000. Signal delivery and rt_sigreturn therefore overwrite the
field before the partial sendmmsg copy; the real PI-mutex pointer cannot be
preserved this way. The panic occurred in _raw_spin_trylock before rb_erase,
so the boot-id pointer remained untouched.

The next route uses a deterministic kernel-owned lock instead of either the
overwritten real pointer or the reclaimed-page fake lock. The installed image
exports msm_bus_dbg_cllist_lock at image offset 0x22504f8. It is a statically
initialized rt_mutex in BSS and is used only by the optional MSM bus debug
interface. Its direct-map alias supplies a valid unlocked wait_lock and empty
waiter tree. The full sendmmsg copy points the forged waiter at this lock; an
ownerless requeue wakes init_task, which is already runnable, and returns.
This one-shot diagnostic dirties the debug lock's waiter tree and must be
followed by reboot unless the resulting kernel-write primitive restores it.

Current result: hardware echo cancellation remains enabled.

77. The static-mutex run did reach `rt_mutex_adjust_prio_chain` with both the
expected stale waiter and the requested `msm_bus_dbg_cllist_lock` direct-map
alias. It faulted in `_raw_spin_trylock` because that alias was unmapped. The
faulting alias was exactly 1 GiB below the alias reconstructed independently
from the panic task's valid direct-map stack pointer. This is consistent with
the leaked `mm_struct` slab page having fallen back from the nearly depleted
Normal zone into the upper half of DMA: the old reconstruction always assumed
that the slab page was in Normal, shifting `memstart_addr` by one 1-GiB
alignment unit when that assumption was false. Current Normal free pages sit
at approximately the zone low watermark, so this fallback is realistic during
the multi-process slab grooming run. The build now logs all three possible
2/3/4-GiB physical-zone reconstructions and has a diagnostic-only page leak
mode that performs no scheduler trigger. It also accepts an explicit zone or
verified `memstart_addr` for the eventual live route.

Current result: hardware echo cancellation remains enabled.

78. The five- and eight-collision diagnostic runs found timing candidates but
no `mm_struct`; a four-collision run completed twice and both independent
leaks produced the same three possible `memstart_addr` values. The ambiguity
is exactly the physical 2/3/4-GiB zone number, not a variable hash result.
The build can now precondition the Normal zone with a temporary anonymous
memory balloon before slab grooming. More significantly, a new release mode
uses the absolute timeout already supported by `FUTEX_WAIT_REQUEUE_PI` instead
of delivering SIGUSR1. This should leave the stale waiter's legitimate task
and PI-mutex pointers intact. The partial `sendmmsg` copy then replaces only
the vulnerable rb-node fields and can use the real kernel-owned mutex without
requiring any direct-map reconstruction for lock acquisition. This path still
needs a live non-writing scheduler control before a constrained write.

Current result: hardware echo cancellation remains enabled.

79. Reading the reboot bugreport's arm64 virtual-memory layout provides the
exact live linear-map range directly; it is no longer necessary to infer
`memstart_addr` from the physical zone of the leaked slab. With that exact
base, the static-lock route acquired `msm_bus_dbg_cllist_lock` and advanced
from `_raw_spin_trylock` to `rt_mutex_adjust_prio_chain+0x1c0`. It then
dereferenced address `0x38`: disassembly shows that instruction loads
`lock->waiters.rb_leftmost->lock`, and the idle static mutex has an empty
waiter tree. The next route uses `proc_uid_lock`, whose address is also known
from the exact image. A controlled cold ext4 page fault pauses one
`/proc/uid` enumeration while it owns that mutex, and a second enumeration
queues a legitimate priority-130 top waiter. This supplies the valid
kernel-managed owner and leftmost waiter that the constrained rb-tree removal
requires.

Current result: hardware echo cancellation remains enabled.

80. A second `/proc/uid` enumeration cannot serve as the real top waiter for
`proc_uid_lock`. `iterate_dir()` first takes the directory inode's write-side
`i_rwsem`, so the second enumeration blocks before reaching `proc_uid_lock`.
An app-process creation does reach the lock independently through UID
registration. Starting the debuggable `me.jxl.portalreadprobe` process while a
nice-19 holder is stopped in an ext4-backed `getdents64` copy boosts that holder
from kernel priority 139 to 120. This priority inheritance is definitive proof
that a normal-priority real waiter is queued on the mutex, unlike a nonzero
`wchan` alone.

81. The first app-process sentinel runs, with 64 and then 256 retained mappings,
still faulted at `rt_mutex_adjust_prio_chain+0x1c0`. Ramoops again showed the
correct `proc_uid_lock` alias in x20 but a NULL `lock->waiters.rb_leftmost`.
The retained timestamps identified the cause: panic-proof `O_SYNC` logging ran
after the PI check and before `sched_setattr`. A release log held the global log
mutex while ext4 completed the truncate, and the consumer's entry log then
waited behind it for roughly ten seconds. The real waiter had left before the
scheduler entered the chain walk. The consumer now performs no disk logging in
that interval and rechecks the holder's donated priority immediately before the
scheduler call. It also accepts only `sk_stream_wait_memory` as proof that
`sendmmsg` has copied the complete waiter; transient `avc_has_perm` and
`notif_lock` waits are no longer sufficient.

82. Moving signal return before the lock gate closes the remaining lifetime
race. The vulnerable waiter now completes its interrupted futex cleanup and
parks at a userspace barrier. The gate then starts the ext4 truncate, blocks the
nice-19 `/proc/uid` holder, and uses a pre-forked `run-as
me.jxl.portalreadprobe` process to queue directly through UID registration.
After the holder's kernel priority is observed at 120, the barrier releases the
waiter directly into `sendmmsg`. A scheduler-disabled control reached
`sk_stream_wait_memory` with holder priority 20 in `/proc` (kernel priority
120), nice 19, and both holder and truncate still active (`proc_done=0/0`).
This verifies the real top waiter survives at the exact scheduler boundary.

83. The first live run with the reordered gate used the exact current-boot
`memstart_addr` `0xffffffcdc0000000` and passed page reclaim and stale-waiter
setup. The ADB shell then disconnected and the device rebooted before a return
trace, rather than producing the previous userspace continuation. The reboot's
ramoops record has not yet been collected because network ADB came back
disabled. Its fault PC will determine whether the forged dequeue advanced past
the old `+0x1c0` NULL dereference into `rb_erase` or a later invariant.

Current result: hardware echo cancellation remains enabled.

84. The reordered proc-lock run's ramoops record showed a late panic in the
legitimate `run-as` waiter, not in the scheduler consumer. The forged scheduler
operation had returned zero. After the exploit child released its gates,
`run-as` entered `proc_register_uid`, attempted to take `proc_uid_lock`, and
faulted in `rb_next+0x1c` on a poisoned parent link. The forged waiter had used
the direct-map alias while the live lock graph used its canonical address; the
route now uses `canon_addr(SLIDE_PROC_UID_LOCK_IMAGE)` consistently.

85. Android's bundled `simpleperf` provides a repeatable KASLR disclosure on
this build even though kallsyms names are hidden. A one-second `cpu-clock`
record includes raw kernel callchain PCs. Samples ending in `0x3d7e` identify
`el0_svc_naked+0x34`, so subtracting `0x3d7e` yields the current runtime
`_text`. The exploit now validates and accepts that base through
`GHOSTLOCK_KASLR_BASE`. A separate ARM64 `PRFM` timing scan did not distinguish
the mapped 128 MiB kernel-module range from adjacent holes and is retained only
as a negative diagnostic.

86. With the canonical proc lock, the scheduler consumer again returned zero.
The child then exited and the real waiter later panicked in `rb_next`, proving
that cleanup, rather than the constrained write itself, caused the reboot. A
held mode now leaves the socket waiter and lock gate alive while another thread
performs immediate post-write work. Critical-window logging can be made
stderr-only with `GHOSTLOCK_VOLATILE_LOG`, avoiding `O_SYNC` delays on the same
ext4 filesystem used by the gate.

87. The held boot-ID run proved the constrained kernel write. It redirected
the boot-ID sysctl data pointer to the reclaimed-page candidate and returned
`11000000-0000-0000-70ea-8a0291ffffff`, decoded as `q0=0x11` and
`q1=0xffffff91028aea70`. The second word is the exact canonical write target
stored by the RB unlink. The device rebooted only after the finite ext4
truncate completed and released the legitimate waiter into the damaged tree.

88. The first in-child ashmem FOPS checkpoint also completed the scheduler
operation, then faulted in `try_module_get+0x2c` from `misc_open`; the fake
table's owner argument was `0xc`. This explains the earlier boot-ID `q0=0x11`:
the known slab address had not retained the sprayed file-operations payload.
The large proc-lock gate was allocating page tables and VMAs after the target
page reclaim and could reuse that page before the trigger.

89. The proc-lock gate is now preallocated inside page preparation while the
leaked `mm_struct` remains pinned. All page-preparation child processes already
exist at that point. Only after the 64 GiB mapping and page tables are complete
does the exploit free the order-2 target slab and spray it with the mixed
order-2/order-3 socket payload. The FOPS checkpoint also uses canonical
KASLR-adjusted addresses until it reads the real `memstart_addr` through the
configfs primitive and configures direct-map translation.

Current result: hardware echo cancellation remains enabled.

90. Preallocating the complete proc-lock gate did not change the FOPS-open
failure. The scheduler operation returned zero, but `misc_open()` again passed
`0xc` as the fake table's owner to `try_module_get()`. This disproves the
specific theory that the gate's later VMA and page-table allocations caused
the corrupt first word. A new held diagnostic uses `MSG_PEEK` on every reclaim
socket after the scheduler write. It searches for the canonical
`ashmem_misc.fops` target at the fake table's exact per-message offset and
reports the adjacent words without consuming or freeing the backing page. The
next run can therefore distinguish payload corruption from a later FOPS-open
effect without deliberately panicking the device.

Current result: hardware echo cancellation remains enabled.

91. The held payload inspection returned `table_hits=0` across 64 reclaim
socket pairs. This means the constrained write succeeded without the leaked
order-2 slab page being owned by any queued socket payload. The owner values
`0x11` and `0xc` were unrelated freed-page contents, not corruption after a
successful reclaim.

92. Exact allocator analysis found the mismatch. `unix_stream_sendmsg()` uses
the task page-fragment cache, whose refill is an order-3 compound allocation
with an order-0 fallback on this kernel. The 16 KiB data fragment merely uses
half of that order-3 page. It cannot directly reclaim the order-2
`mm_struct` slab page. The earlier `GHOSTLOCK_RECLAIM_ORDER2_ONLY` name
described message length, not the allocator order, and was therefore
misleading.

93. `/dev/kgsl-3d0` is available to the shell. A live
`KGSL_IOC_GPUMEM_ALLOC_ID` probe successfully allocated and mapped 16 KiB
buffers with alignment exponent 14. The exact KGSL implementation requests
an order-2 compound page for that geometry, and the installed live device
tree has no `qcom,gpu-mempools` node, so it uses the direct `alloc_pages()`
path rather than falling back through configured pool sizes. The exploit now
retains a pre-free drain set, performs the KGSL allocations immediately after
freeing the target, writes the payload through each userspace mapping, and
checks every mapped fake table after the constrained write. The first launch
selected the old sigreturn route because the stack-route environment variable
was omitted; it was interrupted before a scheduler write. A parent-death
signal now prevents future ADB interruptions from leaving the gate child
orphaned.

Current result: hardware echo cancellation remains enabled.

94. The corrected sendmmsg/KGSL run reached the vulnerable scheduler path and
`sched_setattr` returned zero. The child then spent about 0.38 seconds scanning
the legacy socket queue; the finite ext4 gate expired and the legitimate
waiter rebooted the device before the KGSL mapping scan began. The KGSL scan
now runs first and skips the socket queue by default. The proc_uid gate also
accepts a larger backing-file size so the held interval can be extended for
post-write verification.

Current result: hardware echo cancellation remains enabled.

95. A repeat with a 512 MiB proc_uid backing file showed that increasing the
gate size does not leave a useful post-write interval. It delays the scheduler
operation proportionally, but `sched_setattr` returns only when the ext4 gate
finishes; the damaged legitimate waiter can then reboot the device before a
different thread runs. Collision detection now executes in the scheduler
consumer itself immediately after the syscall returns. It reads only the
already populated KGSL mappings before logging, waking another thread, or
making another syscall, and reports the matching mapping as `kgsl_hit` in the
scheduler return line.

Current result: hardware echo cancellation remains enabled.

96. The first same-thread fast-scan run rebooted after the owner-chain timeout
without emitting the scheduler return line. The constrained operation and the
legitimate waiter can resume on different CPUs when the ext4 gate releases, so
even code placed immediately after `sched_setattr` is not guaranteed to execute
before the waiter panics. An optional KGSL watcher is now pinned to a spare CPU
and continuously scans the already populated mappings while the consumer is
blocked in the kernel. It performs no syscall after affinity setup until it
observes the write, then emits a minimal `KGSL_WATCH_HIT` marker directly to
stderr.

Current result: hardware echo cancellation remains enabled.

97. Exact KGSL source review identified why the first watcher run died before
the owner timeout: `kgsl_page_alloc_ops.vmflags` includes `VM_DONTCOPY`, so
the GPU mappings are absent in the forked route child. The watcher now starts
in the pre-fork parent that owns those mappings and remains alive in `waitpid`
for the entire trigger. When parent watching is enabled, the child also skips
its post-`sched_setattr` KGSL scan so it cannot fault on a non-inherited VMA.

Current result: hardware echo cancellation remains enabled.

98. The corrected parent-side watcher remained valid through a complete
constrained-write run, but reported no hit among 2,048 KGSL mappings; the
consumer returned zero with `kgsl_hit=0`. This exposed an ordering gap in the
reclaim sequence. A freed object in a frozen SLUB page may not return its
order-2 slab to buddy until the later CPU-partial marker drain, while all KGSL
allocations previously happened before that drain. KGSL reclaim is now split:
an early batch follows the target close, and the remaining allocations run
immediately after the marker drain, before socket allocation or logging.

Current result: hardware echo cancellation remains enabled.

99. KGSL's page-size selector on this driver family does not provide a 16 KiB
class: a 16 KiB user buffer is normally assembled from 8 KiB order-1 chunks.
The fixed-offset watcher could therefore miss the constrained word if buddy
split the target order-2 page and KGSL mapped its second physical page at a
different virtual slot. The fast watcher now checks eight bytes into every
4 KiB slot in every mapping. Its nonzero result encodes
`mapping_index * 4 + page_slot + 1`, with the sign still indicating whether
the preceding owner word is zero.

Current result: hardware echo cancellation remains enabled.

100. The all-slot KGSL watcher still reported zero after the two-stage 64 MiB
reclaim, ruling out both a complete buffer collision and a split target-page
collision. Linux 4.9 SLUB can retain an empty slab as the current CPU slab or
on CPU/node partial lists, where no buddy allocator can reach it. A new
optional cache-cycle phase refills old `mm_struct` partial slabs with fresh
address spaces, advances allocation into later slabs, then releases the fresh
objects in allocation order. This makes the target an early empty slab and
uses later frees to overflow CPU partial storage before KGSL's next reclaim
stage.

Current result: hardware echo cancellation remains enabled.

101. The first cache-cycle test was stopped before the vulnerable trigger. It
started the 576 refill processes after preallocating and faulting the 256 MiB
proc_uid gate through 256 VMAs, so every clone copied an enormous page-table
footprint and made the device unresponsive. Refill tasks are now killed and
reaped individually as soon as `/proc/<pid>/mem` pins their `mm_struct`, and
proc_uid gate construction is deferred until after cache cycling and KGSL
reclaim. At that point KGSL owns any captured page, while the gate still exists
before the proc-lock trigger.

Current result: hardware echo cancellation remains enabled.

102. With gate construction deferred, a 20-slab cache cycle completed in about
two seconds and all three KGSL reclaim stages reached 4,096 mappings. The
constrained scheduler operation still returned zero, but the all-slot watcher
reported no KGSL overlap. Successful use of the fake graph despite that miss
keeps the UNIX page-fragment allocation as the leading page owner: an order-3
allocation can absorb the order-2 target after buddy coalescing, while the old
socket verifier checked only one assumed stream offset. A parent-side socket
watcher now peeks the full queued payload and scans every aligned word for the
constrained target, independent of fragment offset or order-3 half.

Current result: hardware echo cancellation remains enabled.

103. The first full-stream socket watcher reported `SOCKET_WATCH_HIT=-1097`
before the vulnerable operation. Decoding word 1096 gives byte offset `0x2240`,
the fake waiter's deliberately pristine `write_right` field; its preceding
word was nonzero, as the negative sign indicated. The watcher now treats this
as a negative control and continues scanning. It reports only the constrained
write's owner-zero signature: a zero word immediately followed by the canonical
`ashmem_misc.fops` target.

Current result: hardware echo cancellation remains enabled.

104. The corrected owner-zero watcher stayed quiet before and after a complete
constrained-write run. `sched_setattr` returned zero, while both the all-page
KGSL scan and full queued socket scan reported no target. This confirms that
the earlier `SOCKET_WATCH_HIT=-1097` was only the pristine stack-waiter value.
It also clarifies why the write can succeed without a reclaim collision: the
forged rb node is supplied by the blocked `sendmmsg` kernel stack. The target
page needs controlled contents only for the fake file-operations table used
after the global pointer redirect.

Current result: hardware echo cancellation remains enabled.

105. Meta's published Portal 4.9 kernel source at commit
`b4577154e48224e7ee1fe07a59656c10e7ea8b7e` matches the device's QCS605/SDM670
ION layout. A live heap probe found shell-accessible writable mappings for ION
heap IDs 13, 19, 22, and 27, but the matching device tree defines all four as
dedicated DMA/CMA heaps. They cannot reclaim a normal-zone `mm_struct` slab.
The system heap at ID 25 rejects 16 KiB alignment and, on this configuration,
uses allocation orders 9, 4, and 0 rather than order 2. The probe is retained
as `tools/ion-heap-probe.c`.

Current result: hardware echo cancellation remains enabled.

106. Exact network allocator review produced a true order-2, payload-controlled
reclaim path. A `0x3c00` UNIX datagram stays in the linear skb; after
`skb_shared_info` is added, its allocation is larger than the 8 KiB kmalloc
ceiling but smaller than 16 KiB, so `kmalloc_order()` requests one order-2
compound page. The queued datagram retains the page and remains observable with
`MSG_PEEK`. The first run queued 256 such allocations immediately after a
20-slab `mm_struct` cache cycle. The constrained write completed, but the
watcher found no collision. The allocator class now matches; the remaining
failure is returning the target SLUB page to the buddy allocator.

Current result: hardware echo cancellation remains enabled.

107. The persistent reclaim miss came from inherited slab geometry, not the
allocator search. `mm_struct` is 896 bytes and the device exposes 16 possible
CPUs. In the exact Portal 4.9 `calculate_order()` implementation, the default
minimum is `4 * (fls(16) + 1) = 24` objects. An order-2 slab holds only 18,
while an order-3 slab holds 36 and passes the waste test, so SLUB selects
order 3. The previous `MM_ORDER=2` grooming isolated only half of the actual
32 KiB slab and necessarily left live objects in the other half. The target
can never reach buddy in that state. The geometry is now corrected to order 3;
the existing UNIX stream page-fragment path can request and retain a matching
32 KiB compound allocation.

Current result: hardware echo cancellation remains enabled.

108. Corrected order-3 grooming with the cache-recycle phase disabled produced
the first real payload collision. `SOCKET_WATCH_HIT=328194` decodes to reclaim
pair 20 and stream byte offset `0x1008`, exactly the constrained fake-table
word with a zero owner. A second run invoked the CFI stage directly from the
parent watcher and collided at offset `0x7008`; the surrounding operations at
that placement were zero, so the first `ASHMEM_SET_NAME` returned `ENOTTY`.
The two offsets differ by three 8 KiB chunks. The stream payload now tiles the
compact fake operations table at offsets `0x1000`, `0x3000`, `0x5000`, and
`0x7000`, while every copy retains pointers for the same leaked kernel table
address.

Current result: hardware echo cancellation remains enabled.

109. The tiled FOPS collision route completed arbitrary kernel read/write on
the exact Portal Go build. The configfs primitive found the exploit process
task, changed all credential IDs to zero, installed full capability masks and
changed `selinux_enforcing` from 1 to 0. The resulting process reported UID 0
and EUID 0. A direct Java Binder client then obtained
`com.facebook.alohasdk.IAudioService` through manager transaction 3 and issued
audio transaction 4 with `(3001, 0.0)`. Transaction 3 readback returned `0.0`:
`PORTAL_AUDIO_CTL_OK id=3001 before=NaN requested=0.0 after=0.0`.
The device remained on the same boot and responsive after the call. Ordinary
ADB stayed UID 2000 and continued to receive the expected `PLATFORM_AUDIO`
permission denial, confirming the successful call came from the temporary
root process. `tools/PortalAudioCtl.java` preserves the exact protocol.

Current result: hardware AEC is disabled for the active audio-service
lifetime. Persistence across an audio-service or device restart and acoustic
behavior with the separate residual-echo NS bit still require validation.

110. A combined privileged-action run confirmed the complete service-level
audio change and persistent wireless ADB. `AEC_ENABLE` 3001 read back `0.0`;
`NS_MODE` 4001 changed from `5.0` to `0.0` and also read back `0.0`. Before
launching the Java Binder client, the root process appended the protobuf record
`persist.adb.tcp.port=5555` to `/data/property/persistent_properties`, preserving
the file metadata and SELinux label and committing it with an atomic rename.
The device then rebooted from boot ID
`2b34b396-83d4-41e0-8f2b-382e202bbfb9` to
`ff0bcffb-66d9-49a0-bfdc-06713ffa00fb`. Wireless ADB returned without
`adb tcpip` or another device-side enable command, and the new boot reported
`persist.adb.tcp.port=5555`, `adb_enabled=1`, and SELinux enforcing. The live
`service.adb.tcp.port` property was empty after boot, demonstrating that the
persistent property alone controls startup here.

Current result: hardware AEC and residual-echo suppression are disabled for
the active audio-service lifetime. Wireless ADB is persistent across reboot.
Boot-time reapplication of the audio settings and an acoustic A/B test remain.

111. Replaced the one-shot Java control path with a native 32-bit Binder
client linked against `libbinder_ndk`. The privileged process successfully
called the same private manager and audio transactions without starting a JVM:
parameter 3001 read back `0.0`, parameter 4001 changed from `5.0` to `0.0`, and
both reported `match=1`. This removes `app_process`, APK permissions and Java
process startup from the time-critical post-exploit path.

112. A privileged snapshot of the installed AI service established its native
startup chain. `libaddressspace.so` requires `libcoldstart.so`, which requires
`libcoldstart_1.so`. The last file is 57,256 bytes and has a unique
`libdl.so\0` dynamic-string slot at file offset `0x18d5`. Replacing it with the
equal-length `libpa.so\0` name adds the watchdog to a library that is loaded on
every AI service start. The watchdog itself requires `libdl.so`, preserving the
original dependency transitively. The installer copies the unmodified library
to `libcoldstart_1.portal-original.so` before changing the live file.

113. Installed the native watchdog as
`/data/user/0/com.facebook.portal.aiservice/lib-compressed/libpa.so`. The
installing privileged process verified the dependency patch and synced both
files before reboot. On boot `315bea69-7e08-4bdc-96ce-a0ba033b48e7`, PID 3526
logged `persistent audio watchdog started`, then verified parameter 3001 as
zero and parameter 4001 as zero. Meta subsequently reset parameter 4001 to
`5`; five seconds later the watchdog logged `before=5 after=0 ok=1`.

114. Cleared logcat and performed a second normal reboot to boot ID
`9691ab7e-a9c1-4938-8455-567ea96ab6df`. A fresh AI service process, PID 3418,
again loaded the watchdog without host action. It set both parameters to zero,
then caught and repaired another `NS_MODE` reset from `5` to `0`. The earlier
ordinary APK helper was uninstalled while the native watchdog continued to
run. `tools/provision_portal.py` now packages the exact successful
exploit settings, checks the firmware fingerprint, builds and stages both
binaries, retries nondeterministic reclaim misses, and verifies two separate
post-install boots.

Current result: hardware AEC and residual-echo suppression are disabled
system-wide and automatically restored after reboot, audio-service restart,
or a later parameter rewrite. Wireless ADB is also persistent. The remaining
measurement task is an acoustic A/B capture with an independent speech source.

115. Hardened the deployed watchdog after observing that the first build wrote
two healthy messages to logcat every five seconds. The current build checks
once per second for 30 clean passes after startup or any correction, then every
five seconds in steady state. It logs only startup, corrections, failures and
recovery. The idempotent installer replaced `libpa.so` while recognizing the
already patched dependency at offset `0x18d5`. Fresh processes verified both
parameters on boot IDs `30d9a2c6-9bd2-4ec7-bd6c-88ccf915f266` and
`72d69b44-bd45-4ba6-8494-da4515f396ee`. On the second boot Meta reset NS mode
to `5` six seconds after initial verification; the startup cadence corrected it
to `0` on the following pass. The live AI service is PID 3511 and the ordinary
APK helper remains uninstalled.

116. Kiosk Satellite version `2026.10.6` is installed as
`me.jxl.kiosk_satellite`, and
`me.jxl.kiosk_satellite/.KioskAdminReceiver` was already an enabled admin for
user 0. Normal `dpm set-device-owner` provisioning is blocked by the Portal's
four existing Meta accounts. Exact Android 10 framework inspection confirmed
that the owner state is stored in `/data/system/device_owner_2.xml`, while the
system user's active-admin policy is `/data/system/device_policies.xml`.

117. Added a guarded privileged Device Owner action to the existing exploit.
It refuses to proceed unless the Kiosk package and receiver are present in the
active-admin policy, refuses any different existing owner file, and snapshots
the original policy under
`/data/local/tmp/portal-device-owner-backup/device_policies.xml`. Because no
owner file existed, it also records that fact in `device_owner_2.absent`. The
action creates a mode-0600 owner file with the policy file's system ownership
and SELinux label, syncs it, commits it by atomic rename, and syncs the parent
directory. An initial guarded run used the per-user policy path and stopped at
the active-admin check without writing an owner file; changing it to Android
10's system-user path resolved the check.

118. GhostLock attempt 3 obtained the arbitrary read/write primitive and
temporary root, refreshed the already-installed audio watchdog, and logged
`kiosk device owner install ... already=0 ... ok=1`. After reboot to boot ID
`31327449-dca9-47ab-919c-8608945b6eb1`, DevicePolicyManager reported Kiosk
Satellite as Device Owner for user 0 and `ro.device_owner=true`. Android also
applied the owner's default `no_add_managed_profile` restriction. The original
four Meta accounts remained present.

119. A second normal reboot changed the boot ID to
`73b06f93-35bc-47f5-bb99-ff324ca27c7e`. Kiosk Satellite remained Device Owner,
`ro.device_owner` remained `true`, and the independently started audio
watchdog again read back AEC 3001 and NS mode 4001 as zero. The host verifier
now accepts Android's normalized
`ComponentInfo{package/package.Class}` owner spelling as well as the shorthand
admin spelling. A subsequent `--device-owner` run took the idempotent
already-owner path and neither invoked the exploit nor rewrote policy. The
retry harness also now requires a completed boot with a different boot ID
after every attempt, preventing reuse of stale kernel state.

Current result: Kiosk Satellite is the persistent Device Owner for user 0;
hardware AEC and residual-echo suppression remain disabled across boot and
wireless ADB remains persistent.

120. Mapped the Portal firmware-update stack on the exact installed image.
The native `/system/bin/otad` service delegates installation to Android's A/B
`update_engine` and reads its policy from MobileConfig unit 5014,
`sessionless_aloha_ota_daemon`. Parameter 36 is
`firmware_ota_update_enable`. The compiled fallback is false. The daemon also
contains an early `otad.nodemon` property check, but the property is a
nonpersistent `default_prop`; Android rejects both shell and temporary-root
attempts to set it through the property service. It cannot safely be stored in
`persistent_properties`, which accepts only `persist.*` names.

121. Disabling the entire `com.facebook.aloha.platformmobileconfig` broker did
make the OTA daemon fall back to false, but generated continuous errors across
unrelated Portal services and removed audio configuration access. That test
was rolled back. Exact decompilation of
`com.facebook.alohaservices.alohausers` instead found Meta's supported local
override layer and its `files/mobileconfig/mc_overrides.json` storage. A
privileged snapshot confirmed the live sessionless MobileConfig directory and
that no prior override file existed.

122. Installed one atomic local override for
`5014: sessionless_aloha_ota_daemon` / parameter
`36: firmware_ota_update_enable: false`. The file uses the provider's
10044:10044 ownership and app-data SELinux label. The installer records an
absent-file marker under `/data/local/tmp/portal-ota-backup`, refuses to
replace any unrelated existing override, and restarts only the provider after
the write. The dedicated `com.facebook.aloha.otaui` and
`com.facebook.aloha.alohaotasetup` packages are persistently disabled for user
0; PlatformMobileConfig itself remains enabled.

123. Verified the OTA block after two ordinary clean boots. On boot
`e36fba77-d832-4adb-a0c0-7dbc552d67e6` and again on boot
`5757afe1-3d74-46f9-a245-10239d30571e`, `otad` remained idle, had no downloaded
JSON manifest, and reported `kFirmwareOtaUpdateEnable=false`. Meta's provider
logged parameter key `18296358819858434` as
`latestBoolean: false, source: OVERRIDE`, proving that the local file won over
server configuration. Both OTA packages remained disabled on the second boot.
Kiosk Satellite remained Device Owner, `persist.adb.tcp.port` remained 5555,
and the audio watchdog again verified AEC 3001 and NS 4001 at zero.

Current result: automatic firmware updates are pinned off across boot while
the shared MobileConfig service remains healthy. Hardware AEC and residual
echo suppression remain disabled, wireless ADB is persistent, and Kiosk
Satellite remains Device Owner.

124. Renamed the multi-purpose host tool from
`tools/install_audio_persistence.py` to `tools/provision_portal.py` and made
its actions explicit. `--debloat` and `--restore-bloat` use PackageManager
without launching GhostLock; privileged actions still build and stage only the
binaries they require. An invocation with no action retains the original audio
provisioning behavior.

125. Added a conservative debloat profile for Meta Analytics, Messenger,
WhatsApp, Portal Feed, Superframe, and Meta Contacts. The first run stores each
package's original state in
`/data/local/tmp/portal-debloat-backup-v1.tsv`; restore uses that snapshot
instead of blindly enabling every package. An initial immediate reboot exposed
that PackageManager had reported the live disabled states before flushing
`package-restrictions.xml`, so all six reverted. Waiting 15 seconds and issuing
`sync` made the states durable.

126. The completed provisioner run verified the disabled set on clean boot IDs
`c43f3691-0874-445b-bf85-1e55907194dc` and
`401c4711-17d7-4990-bfbe-544243306f25`. None of the six application processes
were running. The verifier also required both camera devices, AI Service,
Kiosk Satellite's Home activity, and the sole Portal WebView provider to become
ready, with a bounded wait for Meta services that start after Android reports
`sys.boot_completed=1`. Device Owner, wireless ADB, the OTA block, and the
audio watchdog remained intact; the watchdog again repaired NS mode from 5 to
0 on the final boot.

Current result: the conservative debloat profile is active and reversible, and
the retained camera, kiosk, WebView, audio, OTA, Device Owner, and ADB paths are
healthy after two clean boots.

127. Mapped all four Portal account providers to privileged services in
`com.facebook.alohaservices.alohausers`: `com.facebook.aloha.sso`,
`com.facebook.aloha.pl`, `com.facebook.aloha.hw`, and
`com.facebook.aloha.privowner`. Meta's official device-owner removal path is
coupled to a valid server-side proxy user, and the exported `CLEAR_ACCOUNT`
receiver only removes the proxy SSO account. Disabling the entire package was
rejected because it also provides MobileConfig and shared Portal services.

128. Live database inspection found the local identity state in two actual
files, rather than the schema label seen in decompiled code. `aloha_users_db`
contains `aloha_proxy_user` and `aloha_device_owners`;
`aloha_users_database` contains `device_accounts` and `device_owners`. The new
`PortalAccountCtl` uses Android's hidden AccountManager Binder interface under
the package UID, discovers these exact tables through `sqlite_master`, and
deletes their rows transactionally. It scans unrelated database files
read-only. The original account type/name inventory was saved mode 0600 at
`/data/local/tmp/portal-meta-accounts-before-v1.tsv` before mutation.

129. The identity service recreates proxy, platform-login, and hardware
accounts immediately after a simple AccountManager removal. The completed
sequence force-stops the service, removes the accounts and local rows, repeats
the pass to close that race, disables only its four authenticator components,
and performs one final system-UID AccountManager pass. The successful run
removed three accounts left from prior research, cleared three database rows,
removed one SSO account recreated during the first pass, disabled all four
components, and finished with zero accounts. The private-owner account had
already been removed by an earlier test and did not recreate.

130. Two ordinary verification boots, IDs
`8db565c4-f7c2-40dc-9df5-aba6b4a98390` and
`8762d7c6-1db1-400f-9559-8df8dc9f5f33`, retained zero target accounts and all
four disabled authenticators while the `alohausers` package remained enabled.
Both cameras, AI Service, Kiosk Satellite Home, and Portal WebView passed on
both boots, and SELinux was enforcing. A repeated provisioner run detected the
completed state and skipped GhostLock, proving the action is idempotent.

Current result: the Portal no longer has local Meta accounts and cannot
recreate them through its account authenticators. Camera, kiosk, WebView,
audio, OTA, Device Owner, and wireless ADB paths remain healthy.

131. Traced Kiosk Satellite's LED-free presence source through AIService. The
observable contract is the exact `Notify people presence` log emitted when
AIService's world model contains at least one person. Background segmentation,
liveness metrics, and re-identification consume later results and are not
required to produce that presence notification. Tracking and pose estimation
remain part of the retained path.

132. Added the reversible `--optimize-presence` action. Its privileged stage
atomically installs AIService's private `settings_config.xml` with four false
values: `enable_cv_background_detector_v2`, `enable_liveness_metric`,
`enable_color_based_reid`, and `enable_face_rec_based_reid_v3`. It preserves
the private directory's UID, GID, and SELinux label. An unrelated existing
settings file is first snapshotted and then left untouched. When the file was
originally absent, an absence marker is stored under
`/data/local/tmp/portal-presence-backup`. The paired
`--restore-presence-profile` action restores that exact state and refuses to
overwrite a later unrelated edit.

133. The verifier treats Kiosk Satellite's real input as a required runtime
contract. On every verification boot it requires the AIService process, its
active camera client, an allowed CAMERA AppOp, all four XML values logged as
false, and the exact `Notify people presence` heartbeat. This means a person
must be visible during provisioning; lack of a heartbeat fails the run rather
than silently accepting a broken detector.

134. Installed and verified the profile on two clean boots,
`64e187d4-1999-4152-83ba-f66d763dcf86` and
`57488e98-61b0-45be-9128-4447503e8c1e`. Both boots satisfied the camera and
presence contract with SELinux enforcing. In six matched samples, total
AIService CPU averaged 47.8% of one core before the change and 22.1% after it,
about a 54% reduction. The `BackgroundDetec` thread, previously averaging
11.6%, and the liveness worker were absent. Re-identification workers also
disappeared from the sampled thread list.

135. AIService contains an internal `CAMERA_2_FPS` resource profile, but the
exposed `enable_2fps_throttle` debug control is backed by debug preferences and
is not loaded from the durable settings XML at process start. The numeric pose
FPS value is likewise read from a separate preferences store. No speculative
frame-rate override was installed; the current profile contains only the four
switches proven across reboot.

Current result: Kiosk Satellite's log-based, LED-free person detector remains
live while optional AIService work is disabled. The profile is active,
reversible, and reduced sampled AIService CPU by roughly half across the tested
workload.

136. Investigated an unattended alternative to requiring a visible person on
each verification boot. AIService's presence-state content provider is not a
suitable external heartbeat: it is protected by the signature/privileged
`com.facebook.aloha.permission.ACCESS_STATESDB` permission, Kiosk Satellite
does not request that permission, and its last-seen state is held in memory
and resets with the provider process.

137. Identified two live frame markers, `Frame available for analysis stream`
and `Frame available for roi stream`, plus a shell-readable dump from
AIService's `CameraService`. The dump contains the loaded
`AlohaFrameProcessor` and populated `PoseEstimatorManagerMetrics`. Decompiled
control flow confirms that pose-estimator results are written into
`WorldModelManager`; the model listener is the code that emits `Notify people
presence` when its person count is positive. Together these signals exercise
the retained path without requiring a positive detection.

138. Replaced the person-dependent heartbeat gate with the unattended pipeline
contract. Every verification boot now requires the AIService process, active
camera client, allowed CAMERA AppOp, analysis and ROI frame markers, loaded
frame processor, populated pose metrics, and all four optimized settings. A
real presence event is still reported when observed but is optional. The new
contract passed ordinary clean boots
`3fda320e-05a2-447c-88e8-a9ad3319dceb` and
`b9d4ba78-94ca-4ea7-bef0-90824d49db81`; both boots also emitted the real
Kiosk Satellite presence marker.

Current result: `--optimize-presence` installation and its two-reboot
verification are fully unattended. The optimized profile remains durable,
and each reboot proves that the camera-to-world-model path is processing live
frames before the provisioner accepts the result.

139. Evaluated a persistent `su` or root-command binary callable from ADB.
`/data` is mounted `nosuid`, so both setuid mode bits and file capabilities are
ignored there. The ADB shell starts as UID 2000 with no effective or permitted
capabilities and a bounding set of only `0xc0`. Meta's `adbd` recognizes the
standard `service.adb.root` property, but this production build has
`ro.secure=1` and `ro.debuggable=0`, so the property cannot enable root. The
installed CVE-2024-31317 fix also rules out using the Zygote settings injection
as an on-demand elevation path.

140. Checked the device's system and vendor init files for an executable or
import hook under `/data`; none exists. `/system` and `/vendor` are read-only
dm-verity mappings covered by a locked, green AVB chain. The build has no
remount utility or active persistent overlay, and its fs-manager library marks
the vendor overlay route unsupported. A patched `adbd`, init service, or boot
image therefore cannot be installed through the existing data-only
provisioning path.

141. GhostLock already changes the live `adbd` credentials to UID 0 with full
capabilities and a kernel SELinux SID while its privileged actions run. That
state lasts only for the current boot. The exploit's reclaim route
intentionally disturbs the `proc_uid` lock, which can panic the device when a
later legitimate waiter uses it; the provisioner reboots immediately after
the requested action for this reason. Leaving the patched daemon available as
an interactive root shell, or automatically rerunning this race after every
boot, would turn a bounded provisioning operation into an unstable persistent
service.

Current result: the supported exploit can safely perform explicit root actions
and make their resulting configuration durable, but it cannot safely provide
a device-local root shell that survives reboot. A true persistent ADB root
service requires a separately verified early-boot execution hook or a way to
modify the AVB-protected boot chain. A host-side service could rerun GhostLock
after every reboot, but would inherit the exploit's freeze/panic risk and is
not treated as a supported persistence mechanism.

142. Added an exact target registry and moved host selection to the full
`ro.product.device` plus `ro.build.fingerprint` pair. Read-only inspection can
report an unknown target, while every mutating action stops before building or
staging if the pair is absent. The initial registry contains only Portal Go
`terry` build `5051355900018050`; future model support requires its own target
entry and preload output.

143. Added the `--profile kiosk` action set, `--status`, `--dry-run`, private
backup archives, a persistent operation manifest, and `--recover`. The state
manifest records selected actions, exact target and fingerprint, source
revision, artifact SHA-256 values, state, and verification boots. Recovery
cleans stale staged binaries and resumes only a schema-validated pending
manifest. Kiosk Satellite APK acquisition remains a manual step and is not
part of the profile.

144. Added a resolver-backed privacy action using Android 10 strict Private
DNS. A test with `dns.google` survived boots
`ca89c119-f6e9-4ba1-ba83-47dae48a9b1b` and
`8cc1f564-389d-4cae-b349-ab81c9cbaf26`. The paired restore recovered the
original absent mode and hostname on boots
`efd9e1d0-a5ea-465b-baab-1de5bcba40d5` and
`65b4686d-621d-4dec-8c4c-12a0f5af25c1`. The device does not contain a safe
durable per-domain firewall hook, so filtering policy intentionally remains at
the selected DNS-over-TLS resolver.

145. Implemented exact audio rollback using the original AIService loader
saved by the first install. The privileged restore validates the backup as an
ELF with the original `libdl.so` dependency, refuses an unrelated live loader,
restores its ownership and SELinux label, removes `libpa.so`, and sets AEC/NS
to firmware defaults 1/5. Added a paired OTA rollback that restores the exact
MobileConfig file or its recorded absence and re-enables the two OTA packages.
Both rollbacks passed boots `6731347b-a944-475b-8f46-1d9dcb14d5e5` and
`7b4f92c5-281b-4ea5-baf1-eac6cafe9932`; no audio watchdog started.

146. A combined rollback exposed that restarting Meta's OTA provider inside
the temporarily privileged process could finish the file mutation and then
stall before the final success message on the exploit's deliberately damaged
`proc_uid` lock. The live restart is redundant because the host immediately
reboots and verifies OTAService's newly loaded value. It is now diagnostic
only. The host also waits for every requested action-specific `ok=1` marker,
so a combined run cannot be accepted after only its first action.

147. Reinstalled audio suppression, the OTA block, and the optimized presence
profile. On boots `0e5edea7-bb6d-4193-b050-dc6717236160` and
`e278180d-2958-4c59-a008-05e2c441f125`, the audio watchdog read AEC/NS as zero,
OTAService reported `kFirmwareOtaUpdateEnable=false` from a local override,
and the unattended presence contract passed with both frame streams, a loaded
frame processor, populated pose metrics, and all four reduced-workload values.
SELinux returned to enforcing and wireless ADB remained on port 5555.

Current result: all requested fleet-management additions except automatic
Kiosk Satellite APK installation are implemented. The Portal ends in its
audio-disabled, OTA-blocked, presence-optimized kiosk state, and the new
rollback paths have been exercised end to end.

148. Upstream Shizuku `13.6.0.r1086.2650830c` confirms that its Android 10
manager cannot start ADB mode from `BOOT_COMPLETED`; upstream enables that
path only on Android 13 and later. A host watcher would work but would require
another computer after every Portal reboot. Implemented a device-local helper
instead. It uses the classic ADB protocol only against `127.0.0.1:5555`, signs
the daemon's token with a per-device RSA key, and invokes the official
Shizuku native starter. It never submits an unknown public key, so a failed or
interrupted setup cannot leave an ADB authorization prompt.

149. Meta's required `com.facebook.appverifier` rejected the official Shizuku
certificate with `INSTALL_FAILED_VERIFICATION_FAILURE`; its logs showed the
Rikka certificate mismatching Meta's allowlist. Disabling that package for
the duration of `pm install` allowed both official Shizuku and the local helper
to install. The final installer uses an in-shell cleanup trap to restore the
original verifier state and applies the Package Manager settle delay plus
`sync`. Clean boot `74c8f741-b55d-4b85-954a-2f2b45030da8` retained the
verifier as enabled.

150. The privileged action appended the helper's generated public key to
`/data/misc/adb/adb_keys` without replacing the file or its SELinux label. The
first post-install verifier clears Android's initial stopped-package state with
one explicit broadcast; later boots use the normal `BOOT_COMPLETED` delivery.
`shizuku_server` ran as user `shell` on clean verification boots
`8c94eb85-cb0e-476d-af15-abd02e41d804` and
`caa1c1cc-ef32-46e7-85e1-a6422795902b`, then again after boot
`74c8f741-b55d-4b85-954a-2f2b45030da8`. SELinux was enforcing. Direct PEM and
public-key validation now makes repeat provisioning reuse the same helper key.
The final rebuilt helper repeated the unattended start on boot
`411d1d93-4625-476d-bf88-4e1d76581595`, with the package verifier enabled and
SELinux enforcing.

Current result: `--shizuku` provides unattended, device-local Shizuku shell
privileges after reboot without rerunning GhostLock and without an always-on
host. It does not provide persistent UID-0 root. The paired
`--remove-shizuku` action removes its key and installed packages.

151. A Kiosk Satellite `2026.10.7` update submitted through the working
Shizuku server failed with `INSTALL_FAILED_VERIFICATION_FAILURE`. The live
logs proved that Shizuku staged the expected package and invoked `pm install`
as shell, after which `com.facebook.appverifier` compared the KS certificate
against eight Meta certificates and logged `App certificate rejected`.
Setting the independent Android global `package_verifier_enable` value to `0`
allowed a non-Meta helper reinstall and the KS update while the Meta verifier
package itself stayed enabled. The provisioner now exposes this as
`--allow-app-updates`, stores the prior value for
`--restore-app-verifier`, includes it in `--profile kiosk`, reports it in
`--status`, and verifies it across two reboots without requiring Shizuku or
the kernel exploit. It passed boots
`be358d6b-4a95-47be-aa3d-e5ce0cb01b90` and
`63da4d22-c086-4f25-b410-18bdae844e5c`; KS reported `2026.10.7`, and
`shizuku_server` returned as shell after the final boot.

152. Field testing corrected the earlier presence-profile conclusion. With
`enable_cv_background_detector_v2=false` and hardware cropping left at its
default, AIService could retain a narrow Smart Camera region of interest after
the background detector stopped. The standard Android crop still appeared as
the full 4032-by-3016 sensor, but Meta's active dewarp metadata showed only
about 1896 pixels of its 3962-pixel croppable width. Kiosk Satellite therefore
lost much of the Portal's practical presence field of view even though the
pose and world-model pipeline remained live.

Decompilation located the independent `enable_hardware_cropping` setting in
`AlohaCameraPipeline`. When false, Meta selects the uncropped source size and
does not install the moving hardware crop. The corrected profile keeps the
background detector, liveness scoring, and both re-identification paths off,
and adds `enable_hardware_cropping=false`. It passed clean boots
`caeb7900-2966-4766-a562-7ae01840f445` and
`c8d086e7-b265-40df-8ab5-57193df064bd`: all five settings loaded, both frame
streams and pose metrics remained active, the `BackgroundDetec` and liveness
threads were absent, and the active camera request no longer contained Meta's
dewarp crop. The Android crop remained the full 4032-by-3016 frame. A
five-minute sample averaged 35.5% of one CPU core. That preserves a meaningful
saving from the 47.8% stock baseline while retaining full-frame pose
processing. A final Kiosk Satellite edge-of-scene test confirmed that the
usable presence field of view was restored with the background detector still
disabled.

The verifier now treats full-scene capture as part of the presence contract.
It requires Meta's `Disabled hardware cropping` log and rejects a profile boot
if the active request still contains `dewarp_crop_rect.width`. This prevents a
future CPU optimization from passing while silently narrowing Kiosk
Satellite's detection coverage.

153. Enumerated enabled receivers, services, providers, and worker entry points
inside retained Meta packages, then classified the cloud-facing and periodic
work without disabling whole platform packages. The resulting manifest has 198
components: 143 background workers, 16 bug-reporting components, 15 diagnostic
components, 12 Firebase components, 10 MQTT components, and two push
components. `PortalComponentCtl` applies the saved component states through
`IPackageManager` from the temporary root process, and `--restore-bloat`
restores every original default/enabled/disabled state from
`/data/local/tmp/portal-debloat-components-backup-v1.tsv`.

Live testing found two unsafe exceptions. Meta's
`com.facebook.mqttlite.MqttService` and the device package's
`RegisteredMqttSystemBroadcastReceiver` both issue an enable operation on their
own component immediately before use. Disabling either produced a failure and
restart loop. The final profile exempts those two, disables the other 196
components, and verifies that representative MQTT, push, diagnostic, and bug
report services are absent while AIService, both cameras, Kiosk Home, and
Portal WebView remain available. The retained core MQTT client still attempts
`mqtt-mini.facebook.com`; DNS or firewall filtering is required to block that
last endpoint safely.

154. Traced Meta's optional presence frame-rate controls. The persistent keys
are `/settings/aloha/enable_analysis_throttle` and
`/settings/aloha/analysis_throttle_fps` in AIService's `prefs_db`, encoded as a
boolean and double. Merely writing them does not change the live pipeline:
`ResourceProfileManager` starts in its performance profile. Meta's exported
hidden `AlohaDebugSettingsFragment.onPause` is the path that calls
`AlohaFrameProcessor` with the arbitrary rate. Launching the activity and
returning Home produced `Setting AI Processing FPS 2.000000`.

That activity also reapplies every Smart Camera checkbox and can re-enable
hardware cropping. The privileged preference stage therefore backs up and
writes the five full-scene profile switches as false before activation. A new
normal application, `dev.portal.presencehelper`, starts after boot, waits for
AIService startup, invokes the hidden activity once, returns to Home, and then
exits. This survives reboot without a host and adds no permanent polling
workload.

A direct `startActivity` attempt was denied by Android 10's background-launch
policy even with target SDK 25. The completed helper uses the same minimal
classic ADB protocol design as the Shizuku launcher, but with an independent
per-device key. Temporary root appends its public key to `adb_keys`; the app
connects only to `127.0.0.1:5555`, runs the debug-activity and Home commands as
shell, closes the socket, and exits. The restore path removes the exact key.

At 2 FPS, observed steady AIService CPU fell from roughly 30-37% of one core to
mostly 6-19%, with startup/transient spikes. The active camera request retained
its `[8, 30]` AE target range, showing that the setting limits Meta's analysis
callback rather than sensor capture. Kiosk Satellite's RTSP implementation
owns a separate Camera2 capture and encoder path, so its configured output rate
is not replaced with the presence-analysis rate. The provisioner requires the
selected `Setting AI Processing FPS` log, the helper's completion log, full
field of view, both AI frame streams, frame processor, and populated pose
metrics across two normal boots.

The finished implementation passed boots
`05bb2ca3-7517-4256-9981-2351b20e2456` and
`bcba4923-4c5f-4dc4-bf91-f2465a6967ce`. Each boot applied 2 FPS through the
loopback helper, retained the full-scene request and live pose pipeline, and
kept the 196-component debloat profile. The helper stopped after activation.
The final camera request contained `[8, 30]`, a 41,771,488 ns frame duration,
and no `com.facebook.alohasdk.dewarp_crop_rect.width` tag.
The active Kiosk Satellite RTSP server simultaneously delivered 640-by-480
H.264. A ten-second client probe decoded 56 frames over 9.98 seconds (5.5 FPS),
direct evidence that the 2 FPS Meta analysis cap does not limit RTSP output.
An additional ordinary reboot to
`41aa8497-07d8-483a-90e5-e2c52012abb0` repeated the cap, full-scene, and
196-component checks with SELinux enforcing. The helper was no longer running
after activation, and Meta's package verifier remained enabled.

155. Subsequent stability testing corrected the account-removal scope recorded
in findings 127-130. The hardware account type and authenticator are part of
Portal device identity rather than a removable user login. Disabling
`HWAuthenticatorService` caused camera/platform startup instability. The final
implementation removes only proxy SSO, platform-login, and private-owner
accounts and disables their three authenticators; it explicitly re-enables the
hardware authenticator. The current verifier requires zero user accounts,
three disabled user authenticators, and the hardware authenticator enabled.

156. Investigated a persistent 80% charge limit on Portal Go firmware
`5051355900018050`. The desired policy is to charge while externally powered
below 80%, stop charging at 80% while leaving the adapter connected to the
system rail, and resume when the reported state of charge reaches 79%. The
ISL9538 charger driver already implements this exact hysteresis in its monitor
work. It reads `isl,hi-chg-lmt`, `isl,hi-poll-thr`, and `isl,hi-clr-thr` from
the device tree, sets `batthi_disable_charging` at or above the high limit,
clears it at or below the clear threshold, and then changes only the battery
charge current. Boot logs confirm that Meta ships the values as 99, 97, and
95. A device-tree profile of 80, 78, and 79 would therefore implement the
requested behavior inside the existing kernel driver without an Android
polling service or intentional discharge cycles.

The available data-only persistence routes cannot change those thresholds.
The device tree is covered by the locked, green AVB chain, and the driver has
no runtime sysfs attributes for its three threshold fields. The writable
`disable_charging` and `vsys_status` attributes can enact one decision but do
not retain a policy across reboot.

The boot-capable privileged services were checked as possible controller
hosts. Meta's battery-state HAL has write permission to battery sysfs but only
implements read-only HIDL getters and has no configuration or dynamic-code
hook. The Android health HAL is likewise a stock reader. Thermal Engine can
write battery sysfs, but its configuration and executable are on verified
vendor partitions. Its `ro.vendor.extension_library` hook is already assigned
to Qualcomm's `libqti-perfd-client.so`, is a non-persistent read-only property,
and the Thermal Engine domain cannot execute a replacement from `/data`.

Qualcomm's performance HAL can be called by the existing AIService helper and
can write battery-labelled sysfs, so its exact service, glue layer, and
resource library were extracted and inspected. The full
`commonresourceconfigs.xml` and `targetresourceconfigs.xml` resource maps cover
CPU, scheduler, memory, GPU, display, and storage controls; neither contains a
battery or charger node. Its writable `/data/vendor/perfd` state stores only
FPS and reset values and cannot add a resource path. The relevant extracted
SHA-256 values were:

- performance HAL service:
  `ef0731bf134709ef6019b17e0d652cdbc9ffd94a117ff2acb10c5069ea868025`
- `libqti-perfd.so`:
  `8fddfba2a547968bf2fe81ccb8628f6daaaf993a8d2a926bb83b66fa5df0b49c`
- `libperfgluelayer.so`:
  `fe8259fa286dd5c053f9986be3f6839cdda02b0643154a3e77456e77e167bad8`
- `libperfconfig.so`:
  `f152eab81ed323028a3bd7612fef0c8a23077a60fc9a35a291d7ee44df1c1990`

Meta's stock `com.facebook.aloha.chargecontrol` app runs in the one application
SELinux domain that can write the charger attributes. It is not a usable 80%
controller: its service is non-exported, it has no boot receiver or native
loader, its threshold is hard-coded at 55%, and above that value it starts a
CPU busy-wait workload to drain the battery. Modifying its APK would require
Meta's platform signature. Substituting compiled ART cache files would be
firmware-specific, subject to checksum validation and dexopt replacement, and
is not considered a durable or supportable boot mechanism.

Automatically running GhostLock after every boot is also excluded. Its
current reclaim primitive disturbs `proc_uid_lock`; leaving that boot alive
after a privileged action creates a later freeze or panic risk. The extraction
run was followed by the normal two-reboot verifier. Final boot
`c8296be6-2d0f-4e6f-9ffd-845f5387dd38` returned to enforcing SELinux with the
audio watchdog and wireless ADB healthy.

Current result: the clean implementation is a device-tree change to
`hi-chg-lmt=80`, `hi-poll-thr=78`, and `hi-clr-thr=79`. Deploying it requires
either a bootloader/AVB unlock, a signed boot or DTBO image accepted by the
Portal, or a separately verified early-boot execution hook. Until one of
those exists, the current provisioning exploit cannot safely make an 80%
charge controller survive reboot, so no battery-limit option is exposed.

157. Tested the remaining route for lowering AIService camera cost: suppressing
the 2048-by-1536 `RAW_PRIVATE` auxiliary stream while keeping its 640-by-480
analysis stream. Runtime instrumentation of
`X.0Kt.A09(Context)` confirmed that the auxiliary path is selected by
`PackageManager.hasSystemFeature("portal.software.smart_camera")`. Returning
false removed the auxiliary `ImageReader` exactly as expected. When Kiosk
Satellite opened camera 0, however, the Qualcomm provider restarted, Camera2
reported camera errors, and AIService stopped emitting `Notify people
presence`. The lower CPU reading therefore represented a failed virtual-camera
pipeline. The hook was removed and the canonical audio helper restored across
two normal boots. The earlier 1024-by-768 to 640-by-480 analysis-surface change
had no material CPU effect on its own, so `--lightweight-camera` was removed.

158. Removing the final local Meta owner account caused the launcher to enable
`com.facebook.alohacommon.login.forcedrelogin.ui.AlohaInvalidOwnerHomeActivity`,
disable its normal Home activity, and place an obsolete account-error screen in
front of Kiosk Satellite. Kiosk Satellite already has a safer device-owner
mechanism: its protected provisioning activity accepts `{"home.enabled":true}`
from ADB, enables `.HomeAlias`, and calls
`DevicePolicyManager.addPersistentPreferredActivity`. The new
`--kiosk-home` action drives and verifies that path; `--restore-kiosk-home`
releases it, and the complete kiosk profile enables it after Device Owner is
loaded. HOME resolved to `me.jxl.kiosk_satellite/.HomeAlias` on verification
boots `441ba1cc-e5fe-4f61-87ef-d97884b0354f` and
`77394ed3-943a-4351-bdb2-e38e66d1506e`. The final boot retained both AIService
streams, an active Kiosk Satellite camera client, and the audio watchdog with
AEC and NS at zero.

159. The setting-only third-party update control was not durable over longer
field use. Before a Kiosk Satellite `2026.10.11` self-update,
`package_verifier_enable` had returned from `0` to `1` while
`com.facebook.appverifier` remained enabled. Shizuku was healthy and running as
shell, but Package Manager again returned `INSTALL_FAILED_VERIFICATION_FAILURE`.

The repaired `--allow-app-updates` action now backs up both the global setting
and the verifier package's user state, writes the setting to `0`, and disables
the Meta verifier package for user 0. Existing schema-1 backups are upgraded
with the prior implementation's enabled-package state. The restore action
returns both controls to their saved values, and status treats either the
disabled package or global value `0` as sufficient to allow third-party
updates. Android's own signature-match and downgrade checks are unchanged.

The combined state survived clean boots
`f2e85940-fba4-4897-9518-51675c1a4ab8` and
`3f5b8b08-18f7-40aa-aa32-b3e08efb60b4`. The exact arm64 `2026.10.11` APK,
SHA-256 `9326f711df469e5483a77e335de3cb7b4799faef0ed51e568f33c7d7dff62c13`,
then installed successfully through shell Package Manager. The device reported
version code 309, Shizuku continued as shell, and Kiosk Satellite remained the
persistent HOME activity.

160. Attributed the remaining Meta network traffic after debloat. The native
init service `/vendor/bin/ping-service -t 60`, running as UID 1000, repeatedly
probes the local gateway, `1.1.1.1`, and `facebook.com`. Its rotating
`facebook.com` results included `57.144.162.1` and `157.240.14.35`. The service
has an unconditional `class late_start` declaration in
`/vendor/etc/init/ping-service.rc`; disabling the Java Wi-Fi diagnostics package
did not stop it and was reverted.

The `57.144.162.145` traffic correlated with the DGW realtime transport inside
`com.facebook.alohaservices.alohausers` (UID 10044). The process logged an idle
timeout and successful DGW reconnection about every 30 seconds, and its
`MqttLite` keepalive alarm remained active. The package cannot be disabled
because AIService binds its hardware-identity service, and disabling only the
MQTT component was already shown to trigger a self-enable/failure loop. Marking
the Wi-Fi network metered and applying Android's UID 10044 background blacklist
also failed because AIService keeps the process visible; both policy changes
were reverted.

The native `otad` service additionally attempted `graph.facebook.com` while
the local OTA MobileConfig override still reported the update gate false. Like
the ping daemon, it is an unconditional init `late_start` service on a verified
partition. Neither can be stopped durably by the current data-only persistence
mechanisms.

The active Wi-Fi configuration advertised `fd42::1`, `192.168.1.1`, and
`1.1.1.1` as resolvers. Android selected and validated `1.1.1.1` for
opportunistic Private DNS, which can bypass filtering configured only on the
local resolver. The safe durable controls are a source-specific router rule for
the Portal or a filtering DNS configuration with no unfiltered resolver
advertised. Domain policy should cover `facebook.com`,
`mqtt-mini.facebook.com`, and `graph.facebook.com`; fixed Meta IPs rotate and
are unsuitable for a provisioner rule.

161. Completed a read-only bootloader, OTA, and recovery survey for Portal Go
firmware `5051355900018050`. USB fastboot identifies product `terry`, current
slot B, locked and critical-locked state, green verified boot, and
`get_unlock_ability: 0`. Meta's `flashing unlock_bootloader` handler accepts an
exact 344-byte request containing a fixed header, two device-bound 32-byte
values, and a 2048-bit RSA signature. It verifies the signature before writing
the authoritative unlock permission through the secure/RPMB-backed device
state. Neither the public OTA nor the installed Meta packages contains the
private signer or an online signing endpoint.

The Qualcomm raw-`devinfo` fallback is unreachable on the retail configuration:
VerifiedBootDxe selects it only for a non-secure device or unprovisioned RPMB.
Changing raw `devinfo` offset `0x9a8` from 0 to 1 therefore left fastboot's
unlock ability at 0. The change was reversed with a full-image guard. A
post-reboot capture of the restored 4 KiB image is byte-for-byte identical to
the saved original, SHA-256
`ccc2e8089b5aae8a2e854ea25e8dc9d250f008cbf239f58931637df6baced8df`.
The ineffective provisioner mode and all device-side staging files were
removed.

The other known Qualcomm fallbacks do not apply. `toolsfv` is entirely zero,
its GUID and name are absent from Portal XBL, and XBL configuration loads the
signed embedded LinuxLoader firmware volume. The extracted ABL LinuxLoader
sets AVB mode to 2 as a compile-time constant, so hiding `vbmeta` cannot select
the older no-AVB branch. The kernel is also built without `CONFIG_KEXEC` and
without EFI runtime support.

Parsed the exact Meta full OTA using Android's documented
[`DeltaArchiveManifest`](https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto).
The manifest updates 21 partitions: `xbl`, `xbl_config`, `tz`, `aop`, `hyp`,
`keymaster`, `cmnlib`, `cmnlib64`, `modem`, `dsp`, `bluetooth`, `devcfg`,
`qupfw`, `abl`, `boot`, `dtbo`, `system`, `vendor`, `vbmeta`,
`vbmeta_system`, and `recovery`. It contains no Firehose or other EDL service
programmer. Recovery was reconstructed from 32 payload operations; its
67,108,864-byte image matches the manifest hash
`5dd937a5b04f3760f416402692716c25361bd00e1553b8f196d7bff8a4d22c68`.

The recovered Android 10 `fastbootd` checks the bootloader lock before every
download, flash, erase, slot-change, and logical-partition mutation. Its
`android.hardware.fastboot@1.0-impl-mock.so` supplies no OEM unlock path, and
the binary exposes no partition-fetch command. Static comparison against
Qualcomm's public ABL tree found several post-build fastboot hardening commits,
but the affected display-panel, GPU, hardware-fence, audio-framework, and UBI
commands are absent from Meta's compiled fastboot command table or require
unlocked flashing. No reachable locked-fastboot primitive was identified.

EDL remains recovery-grade only if a programmer signed for Meta's secure-boot
root can be obtained. Public searches found generic SDM710/QCS605 programmers
for other OEM roots, which are not interchangeable with a Meta-signed loader.
The device was not placed in EDL. Current conclusion: the supported GhostLock
route provides temporary Android kernel privilege sufficient for guarded
data-partition provisioning, but no verified bootloader/AVB unlock path is
currently available.

162. Investigated a factory-reset Portal Go provisioning failure reported in
issue 3. The production environment enabled the real `proc_uid` app sentinel
without naming its package, so `slide.c` fell back to the developer-only
`me.jxl.portalreadprobe` test APK. On a clean device, `run-as` rejected that
unknown package and the priority-inheritance sentinel could not block. The
provisioner now builds and installs its own no-permission debuggable
`dev.portal.exploitsentinel` package, verifies `run-as` before reboot, passes
the package name explicitly, and removes it after the exploit sequence. A live
Portal test installed the signed manifest-only APK, ran `/system/bin/id`
through `run-as` in the `runas_app` SELinux domain, confirmed the package's
`DEBUGGABLE` flag, and uninstalled it successfully.

The same report exposed `sched_setaffinity(...): Invalid argument` before the
slide route completed. The watcher requested logical CPU 7 even when Android's
allowed mask did not contain it, and the shared `SYSCHK` wrapper made that a
fatal process exit. Affinity handling now captures the original allowed mask
once, preserves exact pins for available CPUs, falls back to the original mask
for unavailable observer targets, and restores that saved mask instead of an
invalid all-CPU bitset. The arm64 preload rebuilt cleanly with this change.

163. The reporter's next run confirmed both portability fixes: the constrained
device mask rejected CPUs 4 and 5, the new affinity fallback kept the route
running, and attempt 9 completed root provisioning with the temporary sentinel
installed and removed as intended. The subsequent first-boot verifier found
that all 197 component disables had reverted. Root-side PackageManager calls
reported success immediately, but the host rebooted on that final marker
before system_server's asynchronous `package-restrictions.xml` write reached
disk. This also explains why removed Meta accounts could reappear: their three
authenticator component disables shared the same persistence race.

The root component batch now withholds its final marker for the same 15-second
settlement period already used for host-side package changes, followed by
`sync()`. Account-only provisioning applies that settlement directly after its
authenticator changes; combined account and debloat runs share the final
component batch's wait. The host therefore cannot initiate its immediate
verification reboot until the PackageManager state has had time to persist.

164. Issue 4 initially appeared to expose a fresh-device AIService startup
failure: the optimized settings loaded, but the camera client, analysis
frames, ROI frames, and pose pipeline all remained inactive. The reporter
later confirmed that the Portal's physical camera cover was closed. Meta's
privacy path intentionally keeps CameraService from acquiring the camera in
that state, so the live verifier was correctly rejecting an unusable presence
pipeline.

The experimental workaround that launched AIService and then directly started
its CameraService was removed. It added a camera-service permission and could
bypass PresenceManager's privacy-aware start decision without addressing the
actual hardware condition. The optional FPS helper remains limited to applying
an explicitly requested analysis cap. Presence failures now include the raw
CAMERA AppOp, observed privacy/no-user diagnostics, and a direct reminder to
open the camera cover and turn off the camera/microphone privacy control.

165. Portal connectivity diagnostics expose `defaultIPv4DNS: [8.8.4.4,
8.8.8.8]`, but that field is a firmware fallback and does not identify the
active Wi-Fi resolvers. The connected network's `LinkProperties` carries the
actual `DnsAddresses` and search domain. On the tested Portal it advertised
two local resolvers plus `1.1.1.1`; Android's default opportunistic Private DNS
mode validated the public server, allowing it to bypass local zones or DNS
filtering.

The new non-root `--dhcp-dns` action saves the original global DNS settings,
sets `private_dns_mode=off`, clears the strict resolver hostname, and verifies
the state across two reboots. Private `lan.jxl.me` records resolved after the
final boot. `--status` now reports the active servers, validated
Private DNS servers, search domain, DNS strategy, and fallback list
separately. The existing `--restore-privacy-dns` action restores the original
settings for either network DNS or strict DNS-over-TLS configuration; that
rollback also passed two clean boots.

166. Distinguished the Portal Go's camera-use LED from its physical-cover
indicator. When a Camera2 client opens camera 0, the native camera provider
calls `PrivacyStateClient::setComponentLed(true)`. The privacy HAL then writes
`1` to `/sys/module/privacy/fbp_led_state`, and its logs report the green LED
vote under the camera provider's PID. Closing the camera removes that vote and
turns the green LED off. The earlier zero-valued sysfs snapshot was taken while
camera 0 was closed, so it did not establish that the visible green camera-use
light was outside software control.

The orange closed-cover indication is a separate hardware path. Meta's kernel
driver exposes `privacy_green` plus the privacy-enter, microphone-privacy, and
camera-privacy GPIOs; it exposes no orange LED node or cover-light output. The
Silego privacy controller remains the likely source of that indication.

The software green LED can be changed with temporary root, but no durable
data-partition control was found. The camera provider maps its Smart Camera and
privacy client libraries only from AVB-protected `/vendor/lib64`, with no
executable mapping from `/data`. The HAL records component votes per caller
PID, so a helper's `disableLedComponent(Camera)` call cannot cancel the camera
provider's vote. Its global `clearLed()` operation is restricted to UID 1000,
and SELinux permits the privacy HIDL service only to selected platform and HAL
domains; shell and AIService cannot act as a replacement client. Every camera
open also reapplies the kernel's device-tree brightness of 100.

No `--disable-camera-light` action was added. A persistent implementation needs
a verified UID-1000 or early-boot execution hook, a writable camera-provider
load point, or control of the AVB-protected boot/vendor images. None is
available through the current guarded data-only provisioning path. The live
diagnostic was removed after collection, the device rebooted with SELinux
enforcing, and the production exploit artifact was rebuilt from clean source.

167. Audited the installed UID-1000 applications for a data-partition
boot-execution hook. Fifteen Meta packages share `android.uid.system`; all are
signed by Meta's production System Software certificate, SHA-256
`fd445b9e9ee310978a769762e99736d07f833e6e64b419a27894defa9b2592db`, and
none is debuggable or available through `run-as`. The persistent or
boot-received services include Platform Secure State, Platform Battery State,
Virtual Camera Manager, Platform State, Platform Mobile Config, Wi-Fi
Diagnostics, and CNS Health Monitor.

Static instruction tracing found no `DexClassLoader`,
`InMemoryDexClassLoader`, caller-selected `System.load()`, or other executable
load from writable `/data` in those boot service paths. Virtual Camera Manager
loads the fixed `vcmservice_jni` name from AVB-protected `/system/lib64`.
OtaUi contains generic SoLoader and dextricks library classes, but its boot
components do not initialize an external code source and its APK contains no
native, dex, jar, or exopackage payload outside its normal signed dex files.
FBA contains duplicate framework implementation classes with process and path
loader calls, but no FBA boot component references those copies.

Wi-Fi Diagnostics is exported, runs as UID 1000, and contains a real
`Runtime.exec(String)` helper. Its reachable callers supply only fixed `iw`
commands and `ndc resolver flushnet` followed by an integer network ID; the
service exposes no caller-selected executable or argument. It also runs in the
`network_stack` SELinux domain, which cannot find or call Meta's privacy HIDL
service. This is therefore a diagnostic interface, not an execution hook.

UID 1000 by itself is insufficient. The privacy HAL also requires an allowed
SELinux caller domain. Platform Secure State has both UID 1000 and the
`system_app` domain, but its published Binder surface contains privacy-state
operations and LED observation only; it does not expose the HAL's global
`clearLed()` operation. Replacing or updating any of these apps would require
Meta's private platform-signing key. Poisoning compiled ART cache files remains
a firmware-specific, checksum-sensitive research idea rather than a verified
or supportable persistence mechanism.

Result at this stage: the firmware already has suitable UID-1000 processes at boot,
but no writable path was found for making one execute provisioner-controlled
code. A safe persistent hook still requires a separate code-loading or
confused-deputy vulnerability, Meta's platform key, or control of the verified
system/boot chain. For camera-light control the hook would also have to react
after every camera-provider vote; a one-time boot call would be overwritten
when camera 0 opens.

168. Follow-up ART-cache testing established a guarded UID-1000 boot hook on
the exact supported Portal Go firmware. Android's `speed` compiler produces a
stable OAT v170 file for the persistent Platform Battery State application.
`PlatformBatteryStateApp.onCreate()` starts at file offset `0xb7c0`, and the
last executable page contains zero padding beginning at `0x21400`. Extending
the executable program segment from `0x1937c` to `0x194d8` maps a 213-byte
AArch64 trampoline in that padding without replacing a compiled Java method.
The installer checks all of those values, the original four-byte method
prologue, and the zero padding before writing anything.

The trampoline preserves the managed quick-ABI registers and NZCV flags,
forks, executes `/data/portal-uid1000/portal-camera-led-watch` in the child,
replays the displaced instruction, and resumes the original `onCreate()` in
the parent. The host application remains UID 1000 in `system_app`; its battery
Binder service stayed registered and functional. The watchdog inherited UID
and GID 1000 with no Linux capabilities, seccomp enabled, and SELinux
enforcing. It connected to Meta's privacy HAL on two ordinary boots,
`fd9775bf-84e5-4e5f-b8e9-90e5de17627d` and
`d82d87b3-eaaa-4cc0-bc84-b4af86874b33`.

The watchdog polls `PrivacyStateClient::getLed()` and invokes the UID-1000-only
global `clearLed()` when a green camera vote is present, plus a periodic
fallback. Meta's client library logs every query at error/info priority, so the
watchdog patches that library's own `__android_log_print` PLT slot in its
private process to suppress only `PrivacyStateClient` messages. Other clients
and the watchdog's lifecycle logs are unaffected. Steady-state watchdog CPU
was 0.1% after verification. The orange physical-cover indicator remains
outside this software path.

`--disable-camera-light` installs and verifies the helper across two enforcing
boots. `--restore-camera-light` removes it and regenerates the original ART
cache. This result does not provide persistent root: it is a constrained,
firmware-specific UID-1000 hook whose SELinux domain still limits what future
helpers can do.

169. Audited the verified UID-1000 `system_app` process as a possible common
host for other persistent features. Its package belongs to
`android.uid.system`, whose aggregate Package Manager grants include secure
settings, debugging management, package deletion, force-stop, user and device
administration, reboot, network administration, and many other signature
permissions. Platform policy also allows `system_app` to list services and
find nearly every normal framework Binder service. This makes it a capable
host for fixed Android framework operations, although the native helper would
still need explicit Binder clients or an `app_process` entry point for each
operation.

The vendor policy supplies direct access to the privacy, camera, virtual-camera,
battery-state, MobileConfig, and OTA services. It does not give `system_app`
read or write access to `sysfs_battery_supply`; the write rule remains limited
to `chargecontrol_app`. The battery-state HAL that `system_app` can call exposes
read-only state. The policy permits Binder traffic between `system_app` and the
Meta audio-manager process, but it does not permit `system_app` to find the
private `fb_audio_manager_service`, and the system shared UID does not have the
AIService package's `PLATFORM_AUDIO` grant. The current AIService-resident audio
watchdog therefore remains necessary. Application-domain isolation also blocks
the helper from Kiosk Satellite and AIService private data.

The persistent ADB route cannot move to this helper: Android labels
`service.adb.tcp.port` as `shell_prop`, and `system_app` has no property-service
set rule for that type. The original root-backed persistent property write is
still required. UID 1000 likewise has no capability, process-transition, mount,
verified-partition, or SELinux-policy authority that would turn it into root.

Upstream Shizuku 13.6.0's native starter accepts only UID 0 or UID 2000, but
that check is not what prevents a UID-1000 server here. Launching the server's
Java main class directly with the same `app_process` command works as UID 2000.
As UID 1000, AndroidRuntime logs its start and exits successfully before it
logs or invokes the Java main entry point. The Shizuku server's `main()` has no
UID rejection. Starting it through `dalvikvm64` reaches the class, but fails
while initializing Android's native `MessageQueue` because it lacks the normal
framework runtime registration. The Portal's stock runtime therefore cannot
bootstrap this standalone framework process in the `system_app` execution
context. A supervised UID-1000 Shizuku mode is not shipped.

Current allocation: keep camera-light control and the optional presence FPS
boot activation in the constrained UID-1000 helper; retain audio inside
AIService; run optional Shizuku through the proven device-local UID-2000
loopback-ADB helper; and continue using temporary root for one-time data and
property changes. If a stable non-corrupting UID-0 boot supervisor is ever
found, consolidate privileged persistent jobs there rather than maintaining
multiple general-purpose privileged services.

170. Ported the temporary-root transport to the first-generation Meta Portal+
exact build. The tested unit reports `ro.product.device=aloha`, Android 9,
fingerprint
`Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys`,
and Linux `4.4.153+`. The target was generated from the installed boot image's
kallsyms and Meta's matching 4.4 source build. This firmware needs the 4.4
ptrace waiter offset, KGSL order-2 reclaim, twenty recycled `mm_struct` slabs,
and the randomized linear-map base parsed from its own bugreport.

The first arbitrary-write test established that global SELinux mutation is not
safe on this build: the faulting arm64 copy path can zero-pad through the end
of its aligned copy block and corrupt the adjacent `file_security_cache`
pointer. The shipped Aloha path therefore never changes `selinux_enforcing`.
It creates a waiting action child, locates that exact PID in the kernel task
list, verifies the complete credential and security-object guards, writes only
the UID/GID and capability region, and copies PID 1's live SELinux `osid` and
`sid` into the child's first aligned security word. The observed child became
UID/EUID 0 with capability mask `0000003fffffffff` in `u:r:init:s0` while the
controller remained UID 2000 in `u:r:shell:s0`.

Keeping the controller in the shell domain solved cleanup. It verified the
child mutation, restored `ashmem_misc.fops`, cleared the forged-table owner,
closed the primitive, and only then released the child through shared memory.
The restore writer now accepts a verified 32-byte zero guard; the exact Aloha
image has a 56-byte zero gap after `ashmem_misc.fops`, while runtime evidence
shows the short-copy zero padding is bounded by the current 16-byte copy block.
Failure paths set an abort flag before releasing the child, so no provisioning
action runs after incomplete cleanup.

The delegated child set `persist.adb.tcp.port=5555` through Android's property
service. A confirmation run reported `action=1`, `step=0`, and
`provision actions complete ok=1 source=delegated-child`. Wireless ADB then
returned by itself on boot `2f3d2f5a-8fc1-41ca-97f1-afe471579bcb`; the
persistent property read back as `5555`, the new ADB shell was ordinary UID
2000 in `u:r:shell:s0`, and SELinux was enforcing. This is persistent wireless
ADB, not persistent root: the UID-0 action child exists only during the guarded
one-shot provisioning window. The complete Portal+ feature profile remains to
be validated separately because the test device does not have Kiosk Satellite
installed.

171. Sustained camera testing invalidated the earlier camera-light conclusion.
On a provisioned Portal Go, the UID-1000 watchdog called the privacy HAL's
global LED reset 63 ms after Kiosk Satellite opened camera 0. The native Smart
Camera provider then read the cleared state, logged `LED state is not correct.
Rejected.`, and returned `-38` from the first capture request. CameraX reported
`ERROR_CAMERA_DEVICE` as recoverable error 3, closed Kiosk Satellite's camera,
and also caused AIService's camera 1 session to restart. CameraService recorded
matching LED-policy violations.

After removing the watchdog, the same RTSP endpoint immediately supplied a
640-by-480 H.264 stream and camera service recorded no LED-policy violation.
The green indicator is therefore enforced as part of the capture contract on
the supported firmware, even though software controls its physical state.
`--disable-camera-light` is retired and rejected. The provisioner retains
`--restore-camera-light`, automatically schedules that restoration when a
legacy installation is detected, and reports whether the current state is
camera-compatible. Restoration now tolerates unrelated files in the shared
UID-1000 data directory and preserves the presence-FPS or Omni wireless-ADB
worker when either still needs the common helper. The restoration was then
verified across two reboots on the Portal+ (`aloha`) and Portal 10 second
generation (`omni`), in addition to the Portal Go capture test. On `omni`, the
shared UID-1000 process remains alive for presence and wireless ADB without
loading the privacy client or touching the camera indicator.

172. Evaluated DFReroot and the newer DFRoot implementation as a second-stage
persistent-root mechanism. DFReroot provides persistent root in the practical
sense: a durable `android.uid.system` application automatically runs Dirty Frag
after each boot, uses the resulting page-cache write primitive to execute in a
privileged process, and loads a KernelSU-supporting kernel module. Each new
kernel starts without the previous boot's UID-0 state, but DFReroot
automatically re-establishes it. The initial UID-1000 installation is compatible
in principle with the Portal's existing GhostLock and ART-cache capabilities,
but the Dirty Frag root stage is not.

Dirty Frag's xfrm-ESP variant depends on the optimization introduced by
upstream commit `cac2661c53f3`, which allows ESP input decryption to skip
`skb_cow_data()` for some nonlinear skbs. Meta's published Portal 4.4 and 4.9
trees retain the older implementation that unconditionally calls
`skb_cow_data(skb, 0, &trailer)` before constructing the in-place decrypt
scatterlist. Static disassembly of the exact installed Aloha, Omni, and Cipher
kernels independently confirmed a direct call from `esp_input` to
`skb_cow_data`. The Portal kernels therefore do not contain the vulnerable
Dirty Frag data path; this is an absence of the vulnerable optimization, not a
later vendor patch that a variant could bypass.

The released DFReroot application also declares `minSdk=32` and selects only
Android 12-or-newer GKI module payloads for kernels 5.10 through 6.18. Supported
Portals run Android 9 or 10 on non-GKI kernels 4.4 or 4.9. Lowering the APK's
minimum SDK would not supply the missing kernel primitive or a compatible
module. The Portal Go's running configuration additionally has
`CONFIG_MODULE_SIG_FORCE=y`, SHA-512 module signing, modversions enabled, and
Kprobes disabled. A custom 4.4/4.9 module would consequently require Meta's
trusted module-signing key or a fresh live kernel bypass on every boot, which
would defeat the purpose of replacing GhostLock.

No DFReroot or Dirty Frag payload was run on a Portal, because source and exact
binary evidence establish that the required primitive is absent. No device
behavior changed. Reusable pieces are limited to its general architecture and
packages.xml tooling; this project already has the useful persistent UID-1000
portion without gaining persistent root from it.

173. Added and completed a strict port for the Meta Portal Mini. The remote
unit identifies as `ro.product.model=PortalMini`, `ro.product.device=omni`,
Android 10, fingerprint
`Facebook/omni_prod/omni:10/QKQ1.210213.001/3051355900018050:user/prod-keys`,
and Linux `4.9.227-perf+`. Its live `/proc/version` matched the version embedded
in the previously extracted exact Omni kernel, and its `/proc/config.gz`
SHA-256 was the same
`30369f47b9298393de5f87ccc55a487cce3a82e7d438d046f5b46f9d9f6fd252` as
the tested second-generation Portal 10-inch. It has the required packages and
two camera providers. A separate `PortalMini` product-model target reuses that
exact verified kernel build and exploit configuration while preventing an
unknown `omni` form factor from matching by device name alone.

The second exploit attempt completed the arbitrary kernel read/write chain,
ran the delegated UID-0 action child, restored the primitive, and installed the
full kiosk profile. Two clean verification boots,
`ab299145-7463-44d6-8307-17fde6cae741` and
`b533abc4-b0d7-4cf1-8626-2eaeac6fb8d4`, passed with SELinux enforcing. Final
status confirmed Kiosk Satellite as Device Owner and HOME, persistent audio
processing disablement, blocked firmware updates, zero remaining Meta
accounts, all 196 safe component disables, full-scene presence at the optional
2 FPS analysis cap, DHCP-provided DNS, device-local Shizuku running as shell,
third-party application updates, and UID-1000 wireless ADB persistence. The
physical camera cover had to be open for the live presence preflight, as on
the other camera-equipped models.

174. The first live Portal Go test of `--system-theme-control dark` installed
the controller marker and patched the expected ART cache, but the requested
theme remained light and no UID-1000 helper or theme log appeared. Binary
inspection found that the generic 265-byte boot-hook artifact embedded a stale
`/data/app/dev.portal.uid1000runtime-...` private-library path from the
APK-hosted Aloha variant. The installed standalone helper was correct; the ART
hook simply exited after `execve` could not find that unrelated device-specific
path. A normal timestamp-based `make all` had treated the contaminated
untracked output as current.

UID-1000 builds are now forced rather than relying on output mtimes, and the
provisioner validates that every non-embedded hook contains the exact target
helper path before staging it. The corrected hook names
`/data/portal-uid1000/portal-camera-led-watch`. Replacing only that payload and
restarting its persistent host immediately produced
`system theme request mode=dark uid=1000 status=0` and changed UiMode from
`mNightMode=1 (no)` to `mNightMode=2 (yes)`.

Clean Portal Go boots `45f66268-5e99-441e-87ad-d240988d7393` and
`8f0c4800-a55c-4247-86de-87171c9dca34` both retained the helper and dark mode
with SELinux enforcing and no temporary root ADB listener. Subsequent live
requests switched dark to light and back to dark, each from UID 1000 with
status `0`. Re-running the ordinary provisioner then verified the existing
controller and completed without an exploit or reboot.

175. Investigated issue #28, where every Portal Go provisioning run reported
`firmware_gate_false=0` and re-ran the exploit. Three Portal Go devices on
5051355900018050 kept the override across boots: Meta's client logged
`latestBoolean: false, source: OVERRIDE` for parameter 36 after 3, 10 and 20
days of uptime. The terry `alohausers` override parser only reloads
`mc_overrides.json`. The only code that deletes overrides is the MobileConfig
debug screen. The failing check was the preflight itself. It read
`dumpsys facebook.aloha.otaservice` once with a 10 second timeout. While otad
is starting, that dump stops before its config section, and a timeout aborted
the run. The preflight now retries for 30 seconds, treats a dump without
`Dump OtaConfig` as incomplete and survives a `dumpsys` timeout.

The same work found that the OTA block did not stop otad from contacting Meta.
`OtaUpdater::doUpdate` uses `firmware_ota_update_enable` to pick endpoints:
true selects `jsonnewqueryurl` (`graph.facebook.com/firmware_ota_update`) and
false selects `jsonqueryurl` (`graph.facebook.com/mobile_release_updates`) with
`jsonbackupqueryurl` (`portalupdates.facebook.com`) as the second entry. With
the gate off, otad still sent its device type, signature, build and access
token to `mobile_release_updates` every 6 minutes. Unit 5014 only defines
`jsonqueryurl` among the three URLs, so redirecting URLs would push otad to
the backup server, whose query format also carries `device_serial`.

The override now also sets `1: updateintervalfromserver: false`,
`15: updateintervalinitial: 1000000` and `26: updateintervalnonetw: 1000000`.
otad multiplies the interval by 60 into a signed 32-bit second count and
`OtaService::waitForCaller` skips the wait for values below 1, so the value
must stay below 35791394. All five archived firmwares (aloha, ripley, omni,
cipher and terry) use the same unit 5014 indexes and their otad reads the
same four keys. The installer upgrades the exact gate-only file from earlier
versions in place and still refuses any other existing override.

On Portal Go 192.168.1.76 the install logged `existed=1 upgraded=1 ok=1` and
both verification boots, `c7f13aef-b1ee-49aa-bf9c-e3a30eb9807c` and
`1ac3f65d-af6d-4f0a-9d96-d3a6614deacb`, reported
`poll_interval_minutes=1000000 source=OVERRIDE`. otad logged
`Sleeping for 1000000 minutes` and made no update request in 15 minutes, while
the control device on the gate-only override made one every 6 minutes. A
second `--disable-updates` run skipped with
`poll_interval_minutes=1000000 dump=complete action=skip` and no exploit.

On a cold boot otad can start before the MobileConfig service. That instance
logs `Can't connect to service` and sleeps for its compiled default of 241
minutes, then checks once before it reads the override and sleeps for
1,000,000 minutes. The override therefore also sets `21: jsonqueryurl` to
`https://127.0.0.1:9/`. `OtaUpdater::doUpdate` builds the check URL from the
effective `jsonqueryurl` whenever the gate is false, so that single check goes
to a closed local port. The gate's fallback endpoint,
`portalupdates.facebook.com`, returns NXDOMAIN from public resolvers and from
the Portal, and unit 5014 has no parameter for it. The true-gate endpoint,
`graph.facebook.com/firmware_ota_update`, is never selected while the gate
stays false.

`--enable-updates` on 192.168.1.76 removed the file (`backup=0 absent=1
ok=1`) and otad returned to `kUpdateIntervalInitialMinutes=241` with Meta's
URL, so the restore path works against the extended override. The following
`--disable-updates` run installed the five-line override on a fresh file
(`existed=0 upgraded=0 ok=1`, exploit attempt 5). Both verification boots,
`52988d4e-d3b3-4488-b444-7ae43c36bf93` and
`a74a01de-241b-4afd-82dc-a8239f9710bc`, reported
`poll_interval_minutes=1000000 update_url=https://127.0.0.1:9/ source=OVERRIDE`.
On the second boot otad started before MobileConfig and slept for 241
minutes, while its effective config already read `kOtaJsonUrl` as
`https://127.0.0.1:9/`. The wake-up check at the end of that sleep is the
remaining observation.

The Portal Mini 192.168.1.74 (omni 3051355900018050) confirmed the fix on a
second model. Its preflight reported the earlier gate-only file as
`poll_interval_minutes=6 update_url_blocked=0 action=install`. The installer
upgraded that file in place under omni's own provider UID 10041
(`existed=1 upgraded=1 ok=1`, exploit attempt 2). Boots
`fd19bbb5-93ae-46e2-8f72-05a45cb1fece` and
`da99e7cc-d6e1-41fd-8e3c-878d8861bfef` both reported
`poll_interval_minutes=1000000 update_url=https://127.0.0.1:9/ source=OVERRIDE`.
On the second boot otad again started before MobileConfig and slept for 241
minutes with `kOtaJsonUrl` already read as `https://127.0.0.1:9/`. A further
`--disable-updates` run skipped with `update_url_blocked=1 action=skip` and no
exploit. The otad binaries from the aloha, ripley, omni and cipher firmware
archives all read `jsonqueryurl` and carry the same 241 minute default, so
the override and the preflight apply to every supported model.
