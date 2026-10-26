# Source audit fixes (2026-10-26)

Baseline: `dd70e44f63b4a2931231662cc525133e1a95df94`. No version bump or signing-key changes.

| Finding | Change | Regression / validation |
|---|---|---|
| A01 | Complete successful local DNS lookups and reject empty/multiple questions | Go lookup success test |
| A02 | Persist only atomic traffic deltas; serialize selector/stop saves and own the polling scope | Room metadata-preservation regression |
| A03 | Parse/validate the entire backup first; wait for service stop; restore both rollback-journal databases in one attached SQLite transaction | Room cross-database constraint-failure rollback test |
| A04 | Use `specialUse` for root/local proxy, keep VPN `systemExempted`; propagate foreground startup failure | Android compilation; Android 14/15 device regression required |
| A05 | Run service teardown on IO and bound the entire su process wait | Lifecycle review; device stop/lock-contention test required |
| A06 | Require IPv6 rules to succeed and roll back failed setup | Generated scripts compile and pass shell syntax checks; device leak test required |
| A07 | Root watcher supervises both core and hev; tunnel failure stops the Java service | PID/start-time and generation checks; device process-death test required |
| A08 | Filter disabled address families and use the requested preference | JVM IPv4/IPv6 regression |
| A09 | Preserve AnyTLS/TUIC TLS server names before replacing the dial address | Code-path review; TLS server integration test required |
| A10 | Preserve individual hopping ports and validate ranges | JVM single/mixed/invalid port tests |
| A11 | Remove external plugin configuration logs | Release-path inspection |
| A12 | Persist a random per-install control secret outside backups; authenticate the built-in panel without forwarding the secret to remote URLs | API configuration/panel review; on-device unauthorized-request test required |
| A13 | Bound HTTP dialing, SOCKS handshake, headers and body; close failed SOCKS connections; propagate subscription cancellation | Go cancellation/response lifetime tests |
| A14 | Cancel racing HTTP transports, retain the winner until body close, always return an error on cancellation | Go cancelled-H3 and close-once regressions |
| A15 | Validate STUN headers/address lengths, preserve attribute lengths and recover at JNI boundary | STUN round-trip, malformed packet and fuzz tests |
| A16 | Restrict imported asset paths, write through bounded temporary files and check replacement | JVM traversal/size tests |
| A17 | Limit subscription/backup/ZIP/decompression sizes and collection lengths; reject incomplete compressed/serialized data | JVM decompression/read-bound tests |
| A18 | Delete only owned full routing rules; restore sysctls; keep retry state on failure; serialize root scripts and identify each run | Generated scripts checked; module coexistence and crash tests required |

Root scripts use Android's `flock` to serialize setup/cleanup. Every detached process closes the lock descriptor; cleanup scripts are immutable per generation, so a late old watcher cannot remove a new run's rules. Unsupported root environments fail before installing routes. The watcher removes failed routes and stops the service rather than silently claiming a working connection.

## Upstream issue review

- [#1220](https://github.com/MatsuriDayo/NekoBoxForAndroid/issues/1220): removed Android download manager/service from the bundled automatic proxy preset. Existing user selections are preserved and manual selection remains available.
- [#1130](https://github.com/MatsuriDayo/NekoBoxForAndroid/issues/1130): this fork already skips malformed individual links. Added a 650-node-plus-one-invalid-link regression instead of another parser workaround.
- [#1093](https://github.com/MatsuriDayo/NekoBoxForAndroid/issues/1093): this fork already displays usage without negative remaining traffic when total is zero; no duplicate patch.
- [#1072](https://github.com/MatsuriDayo/NekoBoxForAndroid/issues/1072): the reported certificate itself lacks the necessary SAN. Preserve TLS verification; do not bypass validation to hide a server certificate error. A09 separately fixes losing a valid hostname during address rewriting.
- [#731](https://github.com/MatsuriDayo/NekoBoxForAndroid/issues/731): Sleep/Wake already have state checks and panic guards in the baseline; no duplicate patch.
- [#1223](https://github.com/MatsuriDayo/NekoBoxForAndroid/issues/1223): newly reported Xray VLESS compatibility issue has no configuration, trace or confirmed root cause. No speculative protocol change in this patch.

## Checks

Locally passed: all Go tests with `-race` except the Unix protect-socket test excluded by the sandbox and the automatically skipped interface test; STUN tests and 5 seconds of fuzzing (about 180,000 inputs); compilation/execution of the actual address/port/bounded-input helpers; Kotlin compilation of the actual root script generator with Android stubs; shell syntax of all generated IPv6/LAN variants; XML/YAML and shell syntax checks. Also verified attached-file SQLite rollback after a second-file constraint failure, coroutine cancellation/response close in the request adapter, and a stale cleanup process waiting for a real file lock without changing the new generation state. These host checks do not execute Android networking or substitute for the pending Room/Robolectric integration tests.

The local sandbox cannot open the Unix protect socket used by the existing full-core concurrency test. A new Source checks workflow runs full Go tests, Android unit tests (including Room rollback), and signed debug APK assembly on GitHub's runner. Device-specific root/Doze/network transitions are still required before release. CI results must be checked on the final commit; local helper checks are not a substitute for an APK build or device testing.

## Publication status

GitHub App repository access was authorized after the initial 403. The fix branch is being published for CI. The workflow builds a signed debug test APK with a separate application ID so it can be installed alongside the release. Android assembly, Robolectric integration tests and device regressions remain pending until the corresponding checks complete.
