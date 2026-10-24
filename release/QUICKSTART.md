# Cyber-Circuit quickstart

Ubuntu 26.04, Ubuntu 24.04 under WSL2, or Debian 13; x86_64; about 10 minutes. Run each block in order and check the line under it. Details are in `GUIDE.md`. Licence: PolyForm Internal Use 1.0.0 (`LICENSE.md`).

The demo agent may make two tool calls. It tries three, so the breaker trips and kills it.

## 1. Install packages

```bash
sudo apt-get update && sudo apt-get install -y bubblewrap python3 systemd dbus-user-session openssh-client wget
```

**WSL2 only:** if `ps -p 1 -o comm=` does not print `systemd`, see `GUIDE.md`, step 1.

## 2. Download and verify

```bash
mkdir -p ~/cybercircuit && cd ~/cybercircuit
V=0.1.0-eval.4; R=https://github.com/amitb-quantum/cybercircuit/releases/download/v$V
wget -q $R/cybercircuit-$V-x86_64-linux-musl.tar.gz $R/SHA256SUMS $R/SHA256SUMS.sig
wget -q https://raw.githubusercontent.com/amitb-quantum/cybercircuit/main/allowed_signers
cut -d' ' -f3,4 allowed_signers | ssh-keygen -lf -
```

✅ `SHA256:yp+kIpuLgQ9ENakbk0Sm0y3uSf2WYW4NhtaqT+BRcT4`. Check that it matches the fingerprint published on https://cybercircuit.ai/get.html, which is a separate source. If it differs, stop.

```bash
ssh-keygen -Y verify -f allowed_signers -I release@cybercircuit.ai -n cybercircuit-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS
```

✅ `Good "cybercircuit-release" signature` and `...tar.gz: OK`. If not, stop.

## 3. Install

```bash
tar -xzf cybercircuit-*.tar.gz && mkdir -p ~/.local/bin
install -m 0755 cybercircuit-*/circuitbreaker cybercircuit-*/cybercircuit-verify ~/.local/bin/
export PATH=$HOME/.local/bin:$PATH
```

## 4. Check the machine

```bash
circuitbreaker doctor
```

✅ Last line before the JSON: `doctor: ready`. If a check fails, do what its `fix:` line says, then run this step again.

## 5. Trip the breaker

```bash
circuitbreaker init --demo ~/cc-demo
circuitbreaker run --project ~/cc-demo
```

✅ The output contains `"result":"denied"` and `"kill":"confirmed"`. The third call was blocked and the agent was killed.

## 6. Try to restart it

```bash
circuitbreaker run --project ~/cc-demo
```

✅ The output contains `"reason":"QUARANTINED"`. The breaker stays tripped.

## 7. Reset it, as the person responsible

```bash
circuitbreaker reset --project ~/cc-demo "reviewed the demo trip"
circuitbreaker run --project ~/cc-demo --calls 0
```

✅ `"applied":true`. The second command finishes without errors.

## 8. Export the evidence

```bash
circuitbreaker evidence --project ~/cc-demo
```

✅ `"verdict":"VALID"` and `"sealed":true`. This is Cyber-Circuit checking its own record.

## 9. Check it independently

The last line of step 8's output starts with `third-party check:`. Copy everything after that label: it is a `cybercircuit-verify ...` command. Paste it and run it.

✅ `RESULT: VALID`. The open-source verifier, written from the public bundle format, agrees. You are done.

Next: run a real agent (Claude Code, Codex or Gemini CLI). See `GUIDE.md`, step 7.
