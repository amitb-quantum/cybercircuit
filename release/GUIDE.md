# Cyber-Circuit guide (evaluation release, DRAFT)

The short path is `QUICKSTART.md`. This guide explains each step, covers WSL2 and AppArmor, shows how to run a real agent, and lists the limits.

What the demo shows: a demo agent makes three tool calls against a two-call limit. The third is denied and the breaker **trips**: the agent's process is killed. A relaunch is refused. A person resets it with a reason. Then you export an evidence bundle and check it with an independent verifier.

> **Licence.** `circuitbreaker` is licensed under the PolyForm Internal Use License 1.0.0 (`LICENSE.md` in the package): free use for your organisation's internal business operations, no redistribution, no warranty. `cybercircuit-verify` is Apache-2.0. This is an early release: try it on a test machine or VM first.

## 1. Check your machine

You need x86_64 Linux with systemd, cgroup v2, and a normal login session (not `sudo su`).

Tested on 2026-10-23 (releases `0.1.0-eval.1` and `0.1.0-eval.3`):
- **Ubuntu 26.04** (VM, kernel 7.0);
- **Ubuntu 24.04 under WSL2** (fresh instance);
- **Debian 13** (VM).

Anything else, including Ubuntu 24.04 outside WSL, is untested.

**Ubuntu or Debian:**

```bash
sudo apt-get update
sudo apt-get install -y bubblewrap python3 systemd dbus-user-session openssh-client wget
```

**WSL2 (Ubuntu):**
- Turn on systemd: put these two lines in `/etc/wsl.conf`:

  ```ini
  [boot]
  systemd=true
  ```

- Run `wsl --shutdown` from Windows, then reopen the distro.
- Install the packages above.

**Over SSH**, or if you want runs to survive logout:

```bash
loginctl enable-linger $USER
```

## 2. Download and verify

The exact commands are in `QUICKSTART.md`, step 2. They do four things:
1. Download the release from `github.com/amitb-quantum/cybercircuit/releases`: the tarball, `SHA256SUMS` and `SHA256SUMS.sig`.
2. Download the release key, `allowed_signers`, from the same repository.
3. Show its fingerprint. Compare it with the one on https://cybercircuit.ai/get.html: two independent places should agree before you trust the key.
4. Check the signature on `SHA256SUMS`, then the tarball's hash.

If any check fails, stop and tell us; do not run the binary. The signature says the release key's holder approved these exact bytes.

## 3. Install

```bash
tar -xzf cybercircuit-*-x86_64-linux-musl.tar.gz
cd cybercircuit-*-x86_64-linux-musl
mkdir -p ~/.local/bin && install -m 0755 circuitbreaker cybercircuit-verify ~/.local/bin/
export PATH=$HOME/.local/bin:$PATH
```

Both binaries are static: they need no shared libraries.

`circuitbreaker` uses these host tools, from step 1: `bwrap`, `systemd-run`, `systemctl`, `python3`. It uses whichever `python3` is first on your PATH, so a conda or virtualenv Python works too.

## 4. Check the machine is ready

```bash
circuitbreaker doctor
```

Every required check should say `ok`, ending with `doctor: ready`. Any failed check prints a `fix:` line.

**Ubuntu AppArmor.** Ubuntu restricts the unprivileged user namespaces that bubblewrap needs.
- **Ubuntu 26.04:** Ubuntu's own packaged bubblewrap profile already allows it, and nothing extra was needed in our test.
- **Other releases:** if the `sandbox` check fails with an AppArmor message, `doctor` prints a small profile that allows bubblewrap only. Install it as shown, then run `doctor` again. Only do this if `doctor` asks for it, and do **not** turn the restriction off for the whole system.

## 5. Run the demo

```bash
circuitbreaker init --demo ~/cc-demo
circuitbreaker run --project ~/cc-demo
```

`run` prints one JSON summary per session. In this first one, look for:
- calls 1 and 2 `allowed`, call 3 `denied`;
- an alarm `"event":"tripped"` with `"trigger":"quota_exhausted:mark"` and `"kill":"confirmed"`;
- `"expected_trip_exit":true`. The agent was killed, so its nonzero exit is the expected outcome here.

Relaunch it:

```bash
circuitbreaker run --project ~/cc-demo
```

The breaker is still tripped. The first call is refused (`"reason":"QUARANTINED"`), and nothing reaches the tool. The two calls already used are not refunded.

Reset it, as the person responsible, with a reason:

```bash
circuitbreaker reset --project ~/cc-demo "reviewed the demo trip"
circuitbreaker run --project ~/cc-demo --calls 0
```

The reset reply shows `"applied":true` and `"epoch_after":2`. The last run starts and shuts down cleanly, which seals the record. (The reset line also prints `"forced":true` for its short-lived helper process; that is expected.)

## 6. Export and check the evidence

```bash
circuitbreaker evidence --project ~/cc-demo
```

Look for `"verdict":"VALID"`, `"keys":"trusted"`, `"sealed":true`. The last line prints a `cybercircuit-verify ...` command: run it as printed. It should end with `RESULT: VALID`.

`cybercircuit-verify` is the open-source Apache-2.0 verifier from `github.com/amitb-quantum/cybercircuit`, written from the public bundle format and not from our code. You or anyone else can build it from source and get the same result.

To see the verifier catch tampering, copy the bundle, change one byte of `decision.jsonl` in the copy, and run the same command on the copy. It reports `RESULT: INVALID` with the first failing check.

You are done with the demo.

## 7. Next: a real agent

Presets exist for Claude Code, Codex CLI and Gemini CLI. Each runs the agent inside the same containment, with one host-side MCP server (GitHub's).

```bash
circuitbreaker init --preset claude-code ~/cc-agent      # or: codex, gemini
```

This creates a **template**. `run` refuses to start until you fill the `<SET:...>` fields in `~/cc-agent/cybercircuit.json`:
- **`agent.binary`:** the agent's executable.
  - Claude Code: its installed path, e.g. `/usr/bin/claude`.
  - Codex: the native `codex` binary inside its npm package.
  - Gemini: the `node` executable, plus `agent.package` set to the `@google/gemini-cli` package directory.
- **`tool_server.program`:** the `github-mcp-server` v2.0.2 Linux x86_64 release binary. The template pins its SHA-256. If you use another version, check it and replace the pin yourself.
- **`model.key_file` and `tool_server.secret_env_files.GITHUB_PERSONAL_ACCESS_TOKEN`:** paths to files holding your API key and a GitHub token.
  - Each file must be one line, owned by you, mode `0600`.
  - Keep them outside the project and the workspace. Keys never go in the JSON itself.
- **Workspace:** put a **disposable** checkout in `~/cc-agent/workspace`. The agent can change anything there.

Then:

```bash
circuitbreaker run --project ~/cc-agent --prompt-file my-prompt.txt
```

The agent gets only a placeholder key; the real one is added outside the sandbox. Use a GitHub token limited to a test repository.

**Gemini:**
- The default model is `gemini-3.6-flash`. Change it with `init --preset gemini --model NAME` or by editing `agent.model`; the allowed endpoints follow automatically.
- Gemini CLI may switch to another model by itself when Google reports one as unavailable. The gateway refuses any model you did not configure, and the run then fails. Pick a model that is currently up and start a new project.

## Limits you should know

- **Linux x86_64 only.** Only the targets listed in step 1 are tested.
- **Receipts are kept on the same host** in this release. Off-host and public-log anchoring exist but are not set up by these commands.
- **Grant expiry** uses the gateway's process clock, not wall-clock time across restarts. Quota does persist across restarts.
- **Model request budgets** reset each time the gateway restarts. Tool quotas do not.
- **The secret scan** after each session is a bounded canary check, not a guarantee.
- **Post-quantum signing** uses a pinned pre-release SLH-DSA library that has not been independently audited. Treat it as evaluation-grade.
- **What the evidence bundle shows:** what the gateway recorded and signed. It is not proof of compliance, and deleting whole trailing records before export is not detected.

## Remove

```bash
rm -rf ~/cc-demo ~/cc-agent
rm -f ~/.local/bin/circuitbreaker ~/.local/bin/cybercircuit-verify
```

## Help

Send the output of `circuitbreaker doctor` and the last `run` summary. Never send key files.
