# Format v2 bundles from real agent runs

Three evidence bundles from 2026-11-05, one per coding agent, each run under the CircuitBreaker gateway with incident-hardening increment 1 on Linux:

| Directory | Agent | Model provider |
| --- | --- | --- |
| `claude/` | Claude Code 2.1.311 | Anthropic |
| `codex/` | Codex CLI 0.142.5 | OpenAI |
| `gemini/` | Gemini CLI 0.65.0, `gemini-3.6-flash` | Google |

Each run did the same five sessions against a sandbox GitHub repository: a dry run; a normal task (read files, list issues, create one issue); a deliberate trip, where the agent asked for a second issue write beyond its quota of one, so the gateway quarantined it, killed it and refused its next model call; a relaunch that was refused while quarantined; and, after an operator reset, a relaunch that worked. No normal task tripped, and no boundary violation was recorded: these agents did not try to leave the sandbox.

Each directory holds the bundle, the gateway's public keys and the alarm receipts written as the run went. In these runs the receipts were kept on the same machine, so they show consistency, not off-host durability. The keys are also inside the bundle; treat the separate copy as the one you trust. Model prompts, responses, credentials and file contents are never in a bundle.

`tests/real_agents.rs` checks that this verifier, written without the gateway's code, gets the gateway's own verdicts and counts: all three VALID and sealed, with complete security counts. Codex's totals (20 requests, 7 refused) include four retries made while it was quarantined, which the gateway recorded as one suppression record with a count of 4.
