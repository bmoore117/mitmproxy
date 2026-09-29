# Redirector process error analysis
_Exported on 3/10/2026 at 15:08:26 EDT from Cursor (2.6.18)_

---

**User**

@analysis.md contains an analysis of a recent error experience in this project where the redirector process hit some error and exited unexpectedly. Can you go through the code and give me your opinion as to whether it would be practical to simply restart the redirector process in this event, or whether the entire mitmdump.exe host process should be modified to exit cleanly and then simply restarted?

---

**Cursor**


Exploring the codebase to map the redirector architecture and how its exit is handled.



Checking how the Windows redirector is launched and whether we can relaunch it:



Here’s an analysis of both options based on the codebase.

---

## Architecture Summary

**Flow when the redirector exits:**

1. **`forward_packets`** in `src/packet_sources/mod.rs` reads from the IPC pipe; an empty read means the redirector disconnected.
2. It returns `Err(anyhow!("redirect daemon exited prematurely."))` (around line 84).
3. **`WindowsTask::run`** propagates this error.
4. **`shutdown_task`** in `src/shutdown.rs` sees the failure, logs `"Task failed: redirect daemon exited prematurely"`, calls `tasks.shutdown()`, and signals `shutdown_done`.
5. The Server is effectively shut down; traffic stops and the process may keep running in a broken state if nothing awaits `wait_closed()`.

---

## Option 1: Restart Only the Redirector Process

**Feasibility: Yes, but non-trivial.**

### What’s needed

1. **Restart loop in `WindowsTask::run`**  
   Catch `"redirect daemon exited prematurely"`, create a new pipe server, relaunch the redirector, and retry instead of returning an error.

2. **Preserve data for relaunch**  
   `WindowsTask` does not keep `executable_path`; it’s only used in `build()`. You’d need to add it to `WindowsTask` so it can relaunch the redirector.

3. **Recreate the pipe server**  
   The current pipe connection is dead. You must create a new `NamedPipeServer` (same pipe name is fine; the old instance is dropped). The redirector is started with the pipe name as an argument, so no change there.

4. **Channel ownership**  
   `forward_packets` takes ownership of `transport_commands_rx` and `conf_rx`. To retry, you need to either:
   - Change `forward_packets` to take `&mut` references, or
   - Introduce a relay so you can create new receivers for each retry.

5. **Intercept config on reconnect**  
   The new redirector must receive the current `InterceptConf`. You’d need to cache it and resend it when reconnecting.

6. **Restart limits**  
   Add backoff and/or max retries to avoid tight restart loops if the redirector keeps crashing.

### State considerations

- Each `forward_packets` call creates a new network layer via `add_network_layer` (around line 57 in `mod.rs`).
- Old TCP connections are effectively dead when the redirector exits.
- The Python side will see connection errors for those flows; mitmproxy may already handle that.
- New connections after restart would use the new network layer and should work.

### Complexity

Moderate: changes in `WindowsTask`, `forward_packets`, and possibly the `PacketSourceTask` trait. Linux and macOS also use `forward_packets`, so any signature changes affect them.

---

## Option 2: Exit mitmdump Cleanly and Restart the Whole Process

**Feasibility: Yes, and simpler.**

### Current behavior

- When the redirector exits, `shutdown_task` already:
  - Logs the error
  - Shuts down remaining tasks
  - Signals `shutdown_done`

So the Rust side already performs a controlled shutdown. The remaining question is whether the Python process actually exits.

### What to verify

- Whether mitmdump (or its parent) awaits `wait_closed()` and exits when the server shuts down.
- If not, you’d need to ensure that when `shutdown_done` is signaled, the Python process exits (e.g. by awaiting `wait_closed()` or explicitly exiting).

### External supervision

- Use a supervisor (systemd, Windows Service, NSSM, etc.) to restart mitmdump when it exits.
- No changes to the Rust packet source or redirector logic.
- Recovery is slower (full process restart) but simpler and more robust.

---

## Recommendation

**Prefer Option 2 (exit and restart the whole process)** unless you need very fast recovery.

Reasons:

1. **Lower implementation cost**  
   No changes to packet sources, channels, or `forward_packets`. You mainly need to confirm that mitmdump exits when the server shuts down.

2. **Cleaner state**  
   A full restart avoids stale Python/Rust state and broken connections.

3. **Matches the analysis**  
   The analysis already suggests restarting mitmdump.

4. **Redirector runs elevated**  
   On Windows the redirector is started with `ShellExecuteW` and `runas`. Restarting only the redirector would require re-running UAC each time, which is awkward for automatic recovery.

5. **Option 1 is still available later**  
   If you later need sub-second recovery, you can add redirector-only restart on top of the current design.

**If you choose Option 1**, the main work is:

- Add a restart loop in `WindowsTask::run` that catches the premature-exit error.
- Store `executable_path` in `WindowsTask` for relaunch.
- Adjust `forward_packets` (or add a relay) so `transport_commands_rx` and `conf_rx` can be reused across retries.
- Cache and resend `InterceptConf` on reconnect.
- Add backoff and retry limits.

---

**User**

I can confirm that the python process does not shut down and instead continues on in a zombie state; is the code that we'd need to modify for option 2 even in this repo or would it be over in the mitmproxy repo itself?

---

**Cursor**


The fix belongs in the **mitmproxy repo**, not in mitmproxy_rs.

## Where the gap is

In `mitmproxy/proxy/mode_servers.py`, `LocalRedirectorInstance` starts the local redirector but never waits for it to close:

```python
class LocalRedirectorInstance(ServerInstance[mode_specs.LocalMode]):
    ...
    async def _stop(self) -> None:
        assert self._instance
        assert self._server
        self.__class__._instance = None
        # We're not shutting down the server because we want to avoid additional UAC prompts.
        self._server.set_intercept("")
```

On stop, it only clears the intercept and does not call `close()` or `wait_closed()`. That’s intentional to avoid UAC prompts when the user stops the mode.

By contrast, `TunInstance` does shut down correctly:

```python
async def _stop(self) -> None:
    assert self._server is not None
    try:
        self._server.close()
        await self._server.wait_closed()
    finally:
        self._server = None
```

## What happens when the redirector dies

1. The Rust packet source task fails with `"redirect daemon exited prematurely"`.
2. `shutdown_task` in mitmproxy_rs runs and signals `shutdown_done`.
3. `LocalRedirector.wait_closed()` would unblock if anyone were awaiting it.
4. No Python code awaits `wait_closed()` for the LocalRedirector, so nothing reacts and the process keeps running.

## What to change (in mitmproxy)

In the mitmproxy repo, `LocalRedirectorInstance` (or the code that runs it) should:

1. Start a background task that awaits `_server.wait_closed()` once the local redirector is running.
2. When that future completes (either from a normal close or from the redirector dying), treat it as a fatal error and trigger process shutdown (e.g. call the master’s shutdown logic or `sys.exit()`).

That way, when the redirector exits unexpectedly, the process will exit instead of staying in a zombie state.

## Summary

| Repo        | Role                                                                 |
|------------|----------------------------------------------------------------------|
| **mitmproxy_rs** | Already signals shutdown via `shutdown_done` when the redirector fails. |
| **mitmproxy**    | Needs to await `LocalRedirector.wait_closed()` and exit the process when it completes. |

