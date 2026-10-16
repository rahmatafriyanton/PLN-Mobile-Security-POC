# PLN Mobile / Zimperium Frida Handoff

## Current standalone patch — 2026-10-16

The current Zimpe-only result is `build/pln-zimpe-standalone.apk` (SHA-256
`e1abb204381fea57b5af766f20a525aabda3b6e0bd93d92dfde6b1b66d985896`).
It was built from `eK1tY8mL4w.apk` and verified on the currently available
`emulator-5554`.

### What the patch changes

The patch makes exactly one functional change: it removes this auto-start
provider from `AndroidManifest.xml`:

```xml
<provider
    android:authorities="com.app.plnmobile.sapphire.enterprises.integrated"
    android:exported="false"
    android:name="com.app.plnmobile.kuvakkvnefqkhbjgcavpyekackbucbqbxbkxgmircpcvlb" />
```

That provider initializes the protected Zimperium component before the
activity starts. Removing its manifest registration prevents that automatic
startup path while leaving the application code available in the APK.

Nothing else is patched:

- No DEX, smali, Java class, or `MainActivity` modification.
- No `oeoiwhpiav.Loader.l(...)` call is removed.
- No native library or `liboutlookinvolve.so` instruction is modified.
- No Appdome/reference class or library is donated.
- The earlier 19 native runtime patches are not used by this build.

Rebuilding changes the APK signature, so the output is signed with the local
Android debug keystore.

### Verified behavior

- The patched APK reached the PLN phone/PIN UI without Frida.
- The same PID remained alive for 60 seconds.
- Touch, keyboard display, and text input were acknowledged.
- Frida 16.5.2 was then attached manually to that already-running PID.
- `frida-injected.js` emitted `frida-injected`, and the same PID remained
  responsive to touch afterward.

The validated Frida sequence is a normal launch followed by attach, not
spawn-time `frida -f`:

```sh
adb -s emulator-5554 shell am start -n com.app.plnmobile/.MainActivity
sleep 3
PID="$(adb -s emulator-5554 shell pidof com.app.plnmobile)"
frida -D emulator-5554 -p "$PID" -l frida-injected.js
```

`run.sh` automates this exact validated sequence and selects
the first ready ADB device when `ANDROID_SERIAL` is not set. It was finalized
only after the standalone patch and manual Frida attach both passed.

The sections below document the previous physical-device and failed
experiments; they are retained as historical investigation notes.

## Verified working state — 2026-10-13

The application is past the splash screen, usable with Frida 16.5.2 attached, and the user confirmed that it now works. The verified device is **Pixel 5 `0A091FDD4009ZQ`**, not the earlier emulator.

The successful route is **early native bootstrap, followed by delayed Frida attach**. Direct early attach remains unreliable. This distinction is essential: do not describe a plain `frida -U -f ...` or an early attach as the working command.

### Evidence

- `diagnostics/staged45-neutral.console`: cold/cleared launch PID **7998**, original core instructions verified and patched at elapsed **2.583 seconds**, Frida attached at **48.473 seconds**, same PID alive past **220 seconds**.
- `diagnostics/staged45-neutral-postattach.png`: a keyboard tap appended `4` to `8123` more than 30 seconds after attach.
- `diagnostics/final-delete.png`: backspace removed the final digit while the current Frida session was active; the digit was subsequently restored.
- `diagnostics/final-current.png`: responsive phone input and enabled Masuk button, with no root/tamper/ANR dialog. Login/OTP was not submitted.
- `diagnostics/final-attached.console`: the final `pln-test.js` loaded successfully, emitted `root-enforcement-patches-verified` for all **19** shared native patches, emitted `target-patched`, and remained attached. A persistent runner keeps this session open.
- Clear was independently verified in the previous responsive run (`neutral-clear.png`). Repeated taps several seconds apart completed normally. The user additionally confirmed the UI works.
- APK and `reference/` were not modified. Native writes target `/proc/PID/mem` only and disappear with process exit.

### Working mechanism and limits

The bootstrap applies the same 17 callback NOPs and two enforcement stubs used by the reference **before enforcement executes**, then allows startup to settle for 45 seconds before injecting Frida. The final Frida script verifies those bytes and installs the existing device-status filter. This replaces the original early-injection approach; it does not make early injection safe. No `root-threats-filtered` event was observed in the successful run: the demonstrated bypass is the verified shared native enforcement patches plus the live, responsive run.

The phone field rejects an initial `1`: testing only `123` in an empty field can falsely look like keyboard failure. Use an initial `8`, then test appending/deleting digits. A live PID and keyboard screenshot alone are insufficient evidence.

### Files and rerun

- `pln-test.js`: single source of the native patch definitions and Frida device-status filter. `node pln-test.js --patch-plan` exports the bootstrap definitions; already-patched bytes are verified and accepted.
- `run-pln.py`: consolidated launcher using that exported plan, verifying original bytes and writeback, waiting 45 seconds, then keeping Frida attached. After correcting exec-out quoting, the consolidated launcher was cold-run successfully: `diagnostics/launcher-fixed.jsonl` records bootstrap verification at 2.531 seconds and Frida attach at 48.812 seconds (PID 12480). No additional UI testing was performed.
- `diagnostics/staged45-neutral.py`: the exact diagnostic sequence that produced the verified PID 7998 run.
- Server used by the verified run: `/data/local/tmp/androidd-labels`, Frida **16.5.2**, port **27043**, preload disabled (`-P`). Its original binary is preserved at `diagnostics/androidd-original` and `/data/local/tmp/androidd`. Neutral labels alone do not fix early attach.

Only run one Frida server at a time. With the validated server already running:

```sh
adb -s 0A091FDD4009ZQ forward tcp:27043 tcp:27043
pyenv shell frida-16.5.2
python run-pln.py --clear
```

`--clear` erases PLN application data; omit it to retain data. The launcher needs the rooted test device, ADB, Node, and the existing APK. It does not rebuild or reinstall the APK. The current live session is already running; no restart is needed to use it.

## Historical investigation (failed candidates retained for handoff)

The findings below describe earlier runs. Their “not achieved” notes refer to those earlier experiments, not the verified working state above.

## Latest verified findings — continuation on 2026-10-13

- The currently connected device is **Pixel 5 `0A091FDD4009ZQ`, Android 14**. The earlier emulator experiments in the chat are not evidence for this device. Continue with the acceptance criteria above, including an in-memory fix in `pln-test.js`; do not use component disabling or APK changes as a substitute.
- Verified the device libc directly by pulling `/apex/com.android.runtime/lib64/bionic/libc.so`. Its symbols confirm `g_thread_list_lock = libc + 0x528e20`, `g_thread_list = libc + 0x528e58`, and `__pthread_internal_find = libc + 0xbeb40`.
- Disassembly of `__pthread_internal_find` shows the actual reader-lock path: it calls the read lock, scans the linked list, then unlocks on both the found and not-found paths. A lock hang must therefore be traced to a specific interrupted/stuck path; it is not evidence that every reader acquisition is unbalanced.
- A fresh early attach using **only a lock-observer script**, without `pln-test.js`, reproduced a non-progressing app main thread (`/proc/20359/task/20359/wchan = futex_wait_queue_me`). Frida attached at elapsed 2.969 seconds and installed the observer at 3.643 seconds.
- The observer recorded **40 completed lock calls** through elapsed 4.424 seconds. Observed normal states were `0` (unlocked), `4` (one reader), and `2147483648` (writer). All recorded calls were balanced; this trace has **not identified the stale reader**. Earlier `0x0000000a` must not be described as an identified owner or repaired state.
- JavaScript lock-event output stopped after 4.424 seconds, while the external Python runner still found the PID through 44.124 seconds. This again proves that a live PID is insufficient. It does **not** prove the observer was neutral: calling JavaScript from libc lock hooks can perturb timing or re-enter runtime locks.
- The CModule observer was subsequently validated (`native-and-target.jsonl`, PID 20841). It recorded balanced calls until 5.433 seconds; the process died at 39.328 seconds despite remaining listed earlier.
- **Key finding:** `native-lock-stacks.txt` shows libc readers interrupted inside Frida's exception handler: agent offsets `0xa26164` (`gum_exceptor_handle_exception`) and `0xa31570` (POSIX signal handler) wait on a mutex. The gum-js-loop also waits on that mutex in `_gum_exceptor_prepare_try` (`0xa26340`). The libc writer hang is downstream of this exception/signal conflict; resetting the libc lock is not a justified fix.
- Verified against the exact Frida 16.5.2 agent and upstream sources: singleton pointer `agent + 0x1838e30`, reset function `+0xa260ec`, inverted unavailable flag `+0x1838e18`, handler `+0xa26138`. These are private, build-specific offsets, not portable API.
- `restore-signals.js` disabled/released the Frida exception backend with signature checks. Early attach and `target-patched` succeeded, but the app crashed at 4.725 seconds with SIGBUS at protector offset `0x1c922a`. **Failed candidate; not in pln-test.js.**
- `filter-exceptions.js` routed non-JS-thread exceptions to the existing signal chain while retaining Frida's exception handling on the JS thread. The app still terminated at 3.999 seconds (Zygote reported SIGSEGV). **Failed candidate; not in pln-test.js.**
- `reference/` and the original `pln-test.js` remain unchanged. No libc lock was reset. Goal remains unachieved.

- Further tests: changing script runtime to V8 did not resolve the hang. Attach delays 2.8 and 4 seconds lost the process during injection; neither is a successful timing workaround.
- A native signal-entry recorder (`signal-gate.js`, `gated3.jsonl`, `signals.bin`) established positive kernel fault codes: `SIGSEGV` codes 1/2 and `SIGBUS` code 1. These are real memory/alignment faults, not user-generated signals safe to discard. Repeated misaligned addresses map into `liboeoiwhpiav.so` (e.g. offsets `0x10d1f6`, `0x107a35`, `0x1c922a`). Ignoring user-generated signals did not fix the freeze. This diagnostic is not part of the final script.

- **First responsive attached run:** PID 5187 was cold-launched and received the existing core patches via rooted `/proc/PID/mem` at elapsed 2.557 seconds, then attached substantially later through an experimental server with neutral library/thread labels. `existing-neutral.console` recorded `target-patched` and a live Frida session; `neutral-clear.png` proves clear emptied the field, `neutral-123.png` proves keyboard taps appended `123`, and `neutral-backspace.png` records the deletion check. This is promising but not yet the final reproducible route: bootstrap patching was external, and the exact long attach delay was not controlled.
- The neutral-name server still deadlocked with early attach (`neutral-early.jsonl`). Plain late attach without preparatory core patches lost the process before injection (`neutral-late.jsonl`). Do not claim renaming alone fixes the application.
- Running two Frida servers simultaneously disturbed Android process creation (`ProcessStartResult.pid` null). Both were stopped; Android services restarted. Use one server only. `-P` disables server preload and is available in this exact 16.5.2 binary. Original server binary remains `/data/local/tmp/androidd`; temporary neutral-name binary is `/data/local/tmp/androidd-labels` on port 27043.
- Current experiment isolates startup timing: existing shared-core patches before enforcement, **45-second** startup settling period, then the **original** Frida server and `pln-test.js` (`staged45.py` / `staged45.console`). It must be verified before being called successful.

### Investigation evidence

`diagnostics/attach-run.py` records normal launch, delayed attach, script events, and detach/crash reports. It now detects empty PID and waits briefly after force-stop. `native-and-target.jsonl`, `native-lock-stacks.txt`, `restored-early.jsonl`, and `filtered.jsonl` contain the findings above. The two signal experiments are diagnostic failures and must not be described as working fixes.

### Immediate next action

Check the narrower attach timing between early signal conflict and late root enforcement. If it still fails, trace the protector's triggering path; do not reset libc locks or repeat the failed broad exception-backend removal.

## Environment

- Device: Pixel 5/5a, serial `0A091FDD4009ZQ`, Android 14
- Frida Python environment: `pyenv shell frida-16.5.2`
- Target APK: `eK1tY8mL4w.apk`
- Target package: `com.app.plnmobile`, version `1.0.2` (`versionCode 3`)
- Reference package: `id.co.bankraya.apps`, version `2.37.1`
- Target script: `pln-test.js`
- Working reference: `reference/test.js`

The Frida server binary was copied to `/data/local/tmp/androidd` and is currently run under the neutral process name `androidd`. The original `frida-server-16.5.2` process was killed. Verify with:

```sh
adb -s 0A091FDD4009ZQ shell "ps -A | grep -E 'androidd|frida'"
```

## Reference context: Bank Raya

The `reference/` directory is the known-working implementation used to understand Zimperium's real root-enforcement flow. It is not a generic Frida template and must not be modified for PLN.

Reference components:

- APK/package: Bank Raya, `id.co.bankraya.apps`, version `2.37.1`
- Script: `reference/test.js`
- Zimperium core: `libplansassure.so`
- Startup protector: `libayjkanofae.so`
- Decompiled and runtime investigation artifacts: `reference/diagnostics/`

### What the reference script does

`reference/test.js` observes the linker constructor path and patches `libplansassure.so` as soon as it is mapped:

1. It verifies and NOPs 17 indirect callback instructions at shared core offsets. Each expected instruction is `0xd63f0100` (`blr x8`).
2. It replaces the function at `0x761f40` with `return 0`.
3. It redirects `0x761fe0` to the replacement stub.
4. It waits for the native task-post function through the pointer at module offset `0x840070`.
5. It recognizes the Zimperium Dart event by:
   - Native invoke offset `0x7797a0`
   - Channel name `com.zimperium.device.status`
6. It parses the event envelope, base64-decodes `device_status_base64`, removes only root/Jailbreak/Magisk threats, re-encodes the status, and rewrites the existing C++ `std::string`.

The reference was validated end to end:

- It emitted `root-threats-filtered`.
- Three root-related threats were removed in the successful run.
- Observed indicators included `rooted_files`, `magisk_groupid`, and `DEVICE_ROOTED`.
- Bank Raya remained alive and did not show the root/tamper dialog.
- The root-matcher self-check and script syntax check passed.

This is why the PLN work reuses the core offsets and status sanitizer instead of creating another root bypass. The unresolved difference is outside that shared Zimperium core: PLN's startup protector behaves differently under Frida.

## Static comparison

- Bank Raya core: `libplansassure.so`
- PLN core: `liboutlookinvolve.so`
- Both are 8,609,568 bytes and differ by only about 0.22%; core callbacks and device-status flow match.
- The callback instructions, task-post pointer, invoke offset, and two stub offsets used by the reference are present at the same offsets in the PLN core.
- `libcode.so` has the same code; only its 20-byte build ID differs.
- Bank Raya startup protector: `libayjkanofae.so`
- PLN startup protector: `liboeoiwhpiav.so`
- The Zimperium core is equivalent, but the startup protectors are not behaviorally equivalent under Frida.

Extracted binaries are under:

- `_cmp/ref/`
- `_cmp/tgt/`

Target JADX output is under `_cmp/tgt-jadx/`.

## Investigation inventory: already checked

Read this section before running another experiment. These checks have already been performed.

### APK, package, and device

- Installed and launched `eK1tY8mL4w.apk`.
- Confirmed package `com.app.plnmobile`, version `1.0.2`, version code `3`.
- Confirmed the target can reach the PLN login screen when launched normally.
- Confirmed test device `0A091FDD4009ZQ`, Android 14, and Frida 16.5.2.
- Renamed the server process from `frida-server-16.5.2` to `androidd`.
- Confirmed hiding only the server process name does not solve the in-process attach issue.

### Shared Zimperium core

- Extracted and compared `libplansassure.so` and `liboutlookinvolve.so`.
- Verified equal file size and approximately 0.22% byte difference.
- Verified all 17 callback offsets contain the expected ARM64 `blr x8`.
- Verified the task-post pointer, invoke offset, and stub offsets shared with the reference.
- Confirmed the PLN core can be patched and emits `target-patched`.
- Confirmed `pln-test.js` handles the module loading before or after script installation.
- Confirmed the root matcher excludes a non-root threat such as `network_anomaly`.
- Confirmed `pln-test.js` passes `node --check` and IDE linting.

### Startup protector

- Identified PLN protector `liboeoiwhpiav.so` and reference protector `libayjkanofae.so`.
- Compared relevant dynamic imports. Both use the same broad libc/pthread surface, including `pthread_create`, `pthread_join`, `pthread_exit`, `open`, `read`, `mmap`, `mprotect`, `dl_iterate_phdr`, `syscall`, and `abort`.
- Opened `liboeoiwhpiav.so` in IDA. JNI exports are named, but their on-disk entry bytes are zero/packed, so their runtime implementation cannot be recovered by direct static decompilation.
- Located target JNI exports:
  - `Java_oeoiwhpiav_Loader_l` at `0x4a68d4`
  - `Java_oeoiwhpiav_SD_d` at `0x469fc4`
- Decompiled target Java classes under `_cmp/tgt-jadx/sources/oeoiwhpiav/`.
- Confirmed `oeoiwhpiav.Loader` loads the protector and exposes native `l(int)`.
- Confirmed `oeoiwhpiav.SD` loads the protector and exposes native string decoder `d(int)`.

### Spawn and preload paths

- Frida spawn with no script terminates during startup.
- Frida spawn with `pln-test.js` also terminates during startup.
- Observed failures include SIGSEGV with PC/register values around `0x3c0`.
- `Process.setExceptionHandler` did not receive the terminating fault.
- Loading `liboutlookinvolve.so` by simple name failed because it is not extracted into a normal filesystem path.
- Loading it from `base.apk!/lib/arm64-v8a/liboutlookinvolve.so` succeeds, but does not prevent the startup protector crash.
- Hooking `Application.attach` is too late in spawn mode.
- Calling `Java.performNow` for `oeoiwhpiav.Loader` during spawn was too early because the class was not yet available.

### Attach timing and UI

- Empty attach at about 2 seconds reproduces the freeze without loading `pln-test.js`.
- Early attach with `pln-test.js` emits `target-patched`, but later input times out.
- Keeping Frida attached does not prevent the ANR.
- Detaching after the lock is stuck does not restore responsiveness.
- Empty attach at about 7 seconds remains clickable.
- Late attach with `pln-test.js` patches the core and initially accepts touch input, but the process is then killed because root enforcement has already run.
- A live PID and valid screenshot are insufficient; both were observed while the input channel was already non-responsive.

### ANR and libc lock

- Confirmed input-dispatch ANRs using `dumpsys input` and logcat.
- Captured the main-thread native stack showing the block in `pthread_create`.
- Located libc symbols:
  - `_ZL18g_thread_list_lock` at libc offset `0x528e20`
  - `_ZL13g_thread_list` at libc offset `0x528e58`
  - `__pthread_internal_add` at libc offset `0xbe9f8`
  - `pthread_create` at libc offset `0xbe144`
- Read `g_thread_list_lock` directly through `/proc/<pid>/mem`.
- Observed all-zero lock state immediately after attach and `0x0000000a` after the freeze.
- The exact stale reader/owner has not yet been identified.

### Java workarounds

- Hooked `ProfileInstallerInitializer.writeInBackground(Context)` using both `Java.perform` and `Java.performNow`.
- Hook installation succeeded, but the bypass event was not emitted and touch still timed out.
- Hooked `ProfileInstallerInitializer$$ExternalSyntheticLambda1.run()`.
- `profile-hook-installed` and `target-patched` were emitted for PID `19929`, but `profile-runnable-skipped` was not emitted and touch still timed out.
- These failed experimental hooks were not added to `pln-test.js`.

## Current `pln-test.js`

`pln-test.js` is copied from `reference/test.js` and adapted to `liboutlookinvolve.so`. It:

- Patches the same native callback offsets as the reference.
- Filters root/Magisk threats from `com.zimperium.device.status`.
- Can patch `liboutlookinvolve.so` whether it loads after the script or was already loaded before attach.
- Emits `target-patched` when the target core is patched.
- Passes `node --check pln-test.js` and has no IDE linter errors.

Do not overwrite `reference/test.js`; it remains Bank Raya-specific.

## Current blocker: early attach deadlocks Android's pthread list

Attaching Frida around 2 seconds after normal launch patches the core before root handling, but the UI becomes unresponsive. This happens with an empty Frida session too, so it is not caused by `pln-test.js`.

The blocker is a timing conflict:

- Attach early (about 2 seconds): the root-status window is still open, but a libc lock becomes stuck and the app ANRs.
- Attach late (about 7 seconds): Android startup thread creation is already finished and the UI stays clickable, but Zimperium/root enforcement has already run and the process is subsequently killed.

There is currently no timing value that provides both early root interception and a responsive UI.

### Reproduction

1. Clear and launch PLN normally.
2. Wait about 2 seconds.
3. Attach even an empty Frida session.
4. Wait until AndroidX Profile Installer runs its delayed task.
5. Tap the PLN window.
6. The tap waits for input dispatch and eventually triggers an ANR.

This isolates the failure from the root filter and native callback patches: an empty attach reproduces it.

The ANR main-thread stack is:

```text
ProfileInstallerInitializer.writeInBackground
ThreadPoolExecutor.execute
Thread.start
pthread_create
__pthread_internal_add
pthread_rwlock_timedwrlock
```

The main thread is trying to create the AndroidX Profile Installer worker. `pthread_create()` calls `__pthread_internal_add()`, which needs a write lock on libc's global thread list.

`g_thread_list_lock` in Android libc was inspected directly:

```text
libc symbol: _ZL18g_thread_list_lock
libc offset: 0x528e20
observed state after freeze: 0x0000000a
writer_tid: 0
```

The lock is initially all zero immediately after attach, then becomes `0x0000000a` after the freeze. `writer_tid` remains zero. This is consistent with reader-side ownership/contention rather than a normal active writer, but the exact reader thread responsible has not yet been identified.

Once stuck, subsequent `pthread_create` calls cannot register a new thread. The delayed Profile Installer call happens on Android's main thread, so the main looper stops dispatching touch events. CPU usage can remain low and the process can remain alive, which is why `pidof` and screenshots previously produced a false positive.

The authoritative usability check is:

```sh
adb -s 0A091FDD4009ZQ shell input tap 300 1000
```

If it hangs/times out, the UI is not usable even if the process is still alive and screenshots look correct.

### Important distinction

AndroidX Profile Installer is the first observed caller blocked by the lock, but it is not proven to be the root cause. Attempts to suppress its Java method did not prevent the freeze. The actual root cause is earlier: an early Frida attach plus the PLN startup protector leaves libc's thread-list lock in a state that prevents later thread creation.

## Timing results

- Frida spawn/attach before startup: protector terminates the process, commonly SIGSEGV at `0x3c0`.
- Normal launch, attach at about 2 seconds:
  - `target-patched` succeeds.
  - Root handling is reached early enough.
  - Empty Frida attach alone reproduces the freeze.
  - Around the delayed Profile Installer execution, the main thread waits in `pthread_create`.
  - Touch input becomes non-responsive and Android records an input-dispatch ANR.
- Normal launch, attach at about 7 seconds:
  - Empty attach remains clickable; `adb input tap` returns normally.
  - With `pln-test.js`, `target-patched` succeeds and the first tap returns.
  - The process is then killed with `SIGKILL` because root handling has already occurred before the filter was installed.

Therefore, timing alone cannot satisfy both requirements: early attach catches root status but deadlocks startup; late attach preserves UI but misses root handling.

## Experiments already rejected

- Spawning under Frida, with or without a script: early protector crash.
- Preloading `liboutlookinvolve.so` from the APK zip path: library maps, but startup protector still crashes.
- `Process.setExceptionHandler` for low-address faults: handler does not receive the terminating event.
- Hooking `Application.attach`: protector terminates too early in spawn mode.
- Hooking `ProfileInstallerInitializer.writeInBackground(Context)` with `Java.perform` or `Java.performNow`: hook installation succeeds, but the call was not intercepted and the UI still freezes.
- Hooking `ProfileInstallerInitializer$$ExternalSyntheticLambda1.run()`: hook installation succeeds, but `profile-runnable-skipped` is never emitted and the tap still times out.
- Keeping Frida attached does not itself fix the ANR.
- Detaching Frida does not restore a process after the lock is stuck.

## Previous handoff experiment: Profile Installer Runnable

The latest experiment hooked the already-posted synthetic Runnable instead of `writeInBackground`:

```js
Java.performNow(function () {
  const runnable = Java.use(
    'androidx.profileinstaller.ProfileInstallerInitializer$$ExternalSyntheticLambda1'
  );
  runnable.run.implementation = function () {
    send({event: 'profile-runnable-skipped'});
  };
  send({event: 'profile-hook-installed'});
});
```

For PID `19929`, `profile-hook-installed` and `target-patched` were emitted, but `profile-runnable-skipped` was not emitted and the input tap timed out. This failed hook was not added to `pln-test.js`.

## Recommended next step

The next agent should work at the libc/protector boundary, not add more UI or root-detection hooks.

1. Reproduce with an empty early attach and record `g_thread_list_lock` transitions without calling `Process.enumerateThreads()` during the observation, because thread enumeration may itself touch the same lock.
2. Identify which thread/function obtains the reader lock and does not release it. Compare the early failing attach with the 7-second clickable attach.
3. Determine whether the stale reader originates from Frida's thread inspection or a deliberate path in `liboeoiwhpiav.so`.
4. Test one minimal intervention:
   - Prevent the specific stale reader acquisition, or
   - Ensure the responsible path releases its read lock.
5. Do **not** blindly write zero to `g_thread_list_lock`. Resetting a live pthread rwlock can corrupt libc state when the original reader later unlocks it.
6. If a safe lock-level fix works, add only that fix to `pln-test.js`, then verify:
   - `target-patched` emitted.
   - Root status is filtered or root enforcement is otherwise demonstrably bypassed.
   - Process alive for at least 30 seconds.
   - Two or more input taps return without timeout after attach.
   - Text entry and button interaction work.
   - No root/tamper dialog.
   - No input-dispatch ANR appears in `dumpsys input` or logcat.

### Avoid repeating

- Do not use Frida spawn mode; it crashes in the startup protector before the core bypass is useful.
- Do not treat a visible login screenshot or live PID as success.
- Do not retry the two Profile Installer Java hooks; both installed but did not intercept the delayed call.
- Do not add more Zimperium root matchers until the pthread deadlock is resolved.
- Do not modify `reference/test.js`.

## Useful launch pattern

Launch normally, then attach. Do not use Frida spawn mode:

```sh
adb -s 0A091FDD4009ZQ shell \
  "am force-stop com.app.plnmobile; pm clear com.app.plnmobile >/dev/null; monkey -p com.app.plnmobile 1 >/dev/null"
```

For early-root testing, wait about 2 seconds before attaching. For isolated UI/deadlock testing, wait about 7 seconds.


## Launcher correction — 2026-10-13

`Target core mapping was not found` in the consolidated launcher was caused by extra `shlex.quote()` around the command passed to `adb exec-out su -c`. On this device it executed the quoted command as a literal executable name and printed `inaccessible or not found` to stdout despite exit status 0. Removed the extra quoting, matching the working diagnostic launcher. Invalid mapping output now produces an explicit read error instead of pretending the module is absent.

Correction verified by running `python run-pln.py`: PID 12480 emitted `bootstrap-verified` (19 patches), `target-patched`, and `attached` with Frida 16.5.2. Evidence: `diagnostics/launcher-fixed.jsonl`.


adb -s 0A091FDD4009ZQ forward tcp:27043 tcp:27043
pyenv shell frida-16.5.2
python run-pln.py