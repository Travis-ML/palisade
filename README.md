# Palisade

Palisade is the reference harness built across *Engineering an Agentic AI Security Harness* (Travis Lelle, Edition 1.0, October 2026). It is pedagogical: error handling is thin, there are no retries, and each chapter says what production would add. The control plane is not thin.

This folder is the Python package the book's code imports from. This README gets you set up and walks you through **Lab 1**, the first hands-on step in the book, where you map one of your own automations against the harness layers and classify what it does using the shared types.

## What is in this folder

```text
palisade/
  __init__.py
  core/
    __init__.py
    types.py        # the shared vocabulary; already written; import it, never redefine it
```

`core/types.py` is the only module that ships complete. Everything else in Palisade (the governed loop, router, gateway, ledger, policy engine, and the rest) is built chapter by chapter from the code in the book, one module per chapter, in the sections titled "Palisade build thread." Appendix H.2 shows the full layout the package grows into and Appendix H.4 maps each module to the chapter that builds it.

Every snippet in the book imports its types from `palisade/core/types.py`, so a snippet dropped next to this folder will find the names it expects.

## Set up

Palisade targets Python 3.12. Run these from the directory that contains the `palisade/` folder (the repository root).

```bash
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install pydantic               # all that types.py needs (pydantic v2)
python -c "import palisade.core.types as t; print(t.ActionClass)"
```

If the last line prints a class, you are ready. Later chapters need more packages and, for the policy engine and the range, Docker. Appendix H.6 lists the packages and Appendix I sets up the lab environment; you do not need either for Lab 1.

## About `core/types.py`

Read it, import from it, do not edit it. Appendix H.3 reproduces it verbatim and every later chapter assumes the names are exactly as written, so a local change makes the book's code stop lining up with your copy. Your own notes belong in your own files, as described below.

## Lab 1: Find the harness you already run

The full lab is at the end of Chapter 1. This is the same procedure with the repository details filled in.

Most security teams already run an ungoverned harness without calling it one: a SOAR playbook that disables accounts, a cron job that blocks indicators, a Slack bot that runs EDR commands. You pick one and see which of the book's eight layers it has and which it lacks.

**1. Pick the automation.** Choose one that takes an action in a production system without a human in the immediate path. If nothing qualifies, pick the closest. In one sentence each, write down what triggers it, what it reads, and what it changes.

**2. Create `lab1-inventory.md`.** Copy the template below. Fill the eight-row table literally. "Guardrail and policy: an if-statement checking that the hostname does not start with `dc-`" is a real answer, and so is "nothing."

**3. Find the credential.** Record what the automation authenticates with, who else uses it, what it can do beyond what this automation needs, and when it was last rotated. If you cannot find out, write that down; it is a finding. Record where the credential lives and its properties, never its value.

**4. Run the replay test.** Take the most recent action the automation performed and reconstruct, from logs alone, what input it saw, what it decided, and why it was permitted. Time yourself and note what you could not recover.

**5. Record the human side.** Who would be told if the automation did something wrong, how, and how long after? Who can stop it, and how?

**6. Classify the action and record the key.** Use the three axes in `palisade/core/types.py` (details below), compute the `ActionClass.key()` string, and write it at the bottom of `lab1-inventory.md`. The key goes in your inventory file, not in `types.py`.

**What you end up with** is a one-page inventory of one real automation. For most teams the identity, accounting, and governance rows are mostly empty, the credential is shared and over-privileged, and the replay test fails or takes more than an hour. That is the expected result. Keep the file: Lab 11 asks you to write the Rules of Engagement this automation should have been running under, and Lab 26 asks what rung of the autonomy ladder it is on and what evidence would justify the next one.

> **Keep the inventory private.** It describes a real production system, its credentials, and its gaps. Do not commit it to a public repository or a public fork, and do not paste secrets into it.

### Inventory template

````markdown
# Lab 1 inventory: <name of the automation>

**Triggered by:** <one sentence>
**Reads:** <one sentence>
**Changes:** <one sentence>

| Layer | What exists today? | What is absent? |
|---|---|---|
| Orchestration | | |
| Model | | |
| Tool | | |
| Context and knowledge | | |
| Guardrail and policy | | |
| Identity and permission | | |
| Observability and accounting | | |
| Human interaction | | |

## Credential
- What it is:
- Who else uses it:
- Permissions beyond what this automation needs:
- Last rotated:

## Replay test
- Action replayed:
- Time taken:
- Recovered from logs: input seen / decision made / why it was permitted
- Could not recover:

## Human interaction
- Told if it goes wrong (who, how, how long after):
- Can stop it (who, how):

## Action class
- Domain:
- Reversibility:
- Blast radius:

Action class key: `domain:reversibility:blast_radius`
````

### Classifying the action

Chapter 11 develops the action taxonomy in full; this is enough for Lab 1. Classify the most consequential thing the automation does, with the arguments it normally runs with. Classify by effect, not by the tool's name.

| Axis | Value | Meaning |
|---|---|---|
| Domain | `observe` | Reads telemetry, queries, lists |
| | `enrich` | Looks up, correlates, analyzes |
| | `internal_change` | Changes the security function's own systems: a ticket, a draft rule, a pull request, a comment |
| | `production_control` | Changes the state of a production system or a principal: isolate, block, reset, revoke, quarantine |
| | `offense` | Range-only emulation and probing; a production automation will not be this |
| Reversibility | `reversible` | Undoing it leaves nothing behind: a query, an enrichment, a draft |
| | `semi_reversible` | Can be undone but leaves a trace or a cost: a ticket, a quarantine that can be released |
| | `irreversible` | Cannot be undone: a reset credential, a reimaged host, a sent message |
| Blast radius | `single` | One object: one token, one host, one mailbox |
| | `group` | A set: an OU, a subnet, a team |
| | `enterprise` | The whole tenant, or something whose failure is felt everywhere: a domain controller, a global block rule |

Two refinements from Chapter 11 matter. Blast radius is about impact, not count: isolating one domain controller is one object with an enterprise-wide effect, so criticality raises the radius. Reversibility is about the effect on the world, not on your systems: a lookup against an external threat-intel provider is reversible from your side and irreversible for the indicator, which has now been disclosed to a third party.

If the same automation can land in different cells depending on its arguments (a soft delete versus a hard delete of the same mailboxes, for example), record the class for the usual case and note the other one in your inventory. That variation is itself a finding.

### Compute the key

Run from the repository root. Pydantic accepts the plain string values, and rejects anything that is not one of them, listing what is allowed.

```bash
python -c "
from palisade.core.types import ActionClass
print(ActionClass(domain='production_control',
                  reversibility='semi_reversible',
                  blast_radius='single').key())"
# production_control:semi_reversible:single
```

To list the allowed values for each axis straight from the source:

```bash
python -c "
from palisade.core.types import ActionDomain, Reversibility, BlastRadius
for axis in (ActionDomain, Reversibility, BlastRadius):
    print(axis.__name__, [m.value for m in axis])"
```

Three worked classifications, taken from the twenty-action exercise in Section 11.2.1:

| Automation does | Key |
|---|---|
| Isolates `host-4471` from the network for a fixed 60 minutes, then releases it | `production_control:semi_reversible:single` |
| Resets one user's credential | `production_control:irreversible:single` |
| Queries the SIEM for one user's sign-ins over 14 days | `observe:reversible:single` |

Paste your own key at the bottom of `lab1-inventory.md`.

## The shared types

`core/types.py` is the book's central idea written as types: an agent proposes a `ProposedAction`; the harness classifies it with an `ActionClass`; a policy engine disposes of it with a `PolicyDecision` against an active `RulesOfEngagement`; a human gates what the `AutonomyTier` does not cover with an `ApprovalRecord`; and every step is written to the ledger as a `DecisionRecord` before anything touches the world.

| Types | What they are for | Chapter |
|---|---|---|
| `ActionDomain`, `Reversibility`, `BlastRadius`, `ActionClass` | The action taxonomy; `key()` is what policy, ceilings, and rate limits all key on | 11 |
| `ProposedAction`, `FiveQuestionIntent` | What the agent asks for, and the justification required before high-impact actions | 1, 5, 13 |
| `PolicyDecision`, `ApprovalRecord`, `ExecutionRecord` | The verdict, the human's decision with what they saw, and what the tool layer did | 12, 13, 14 |
| `DecisionRecord`, `ModelCallRecord`, `RetrievedItem`, `GlassBoxVerdict` | One governed step, fully accounted for, hash-chained into the ledger | 6, 8, 10 |
| `RulesOfEngagement`, `ScopeList`, `ActionCeiling` | The signed, time-boxed authorization that bounds what an agent may do | 11 |
| `AgentIdentity`, `ScopedCredential` | A governed non-human identity and short-lived, single-purpose credentials | 12 |
| `AutonomyTier`, `Plane`, `TrustTier` | The autonomy ladder, the two planes, and where context came from | 26, 6, 8 |
| `RunBudget`, `RunState` | Ceilings on a run and its running state | 5 |

## Where to go next

- **Chapter 1**, Lab 1: the lab this README supports.
- **Chapter 11**: the full action taxonomy, with the twenty-action classification exercise, and Lab 11, where you write the Rules of Engagement for the automation from Lab 1.
- **Chapter 26**: the autonomy ladder, and Lab 26, where you place that automation on it.
- **Appendix H**: the repository layout, `types.py` reproduced in full, the module-by-module map, canonical names, and installation.
- **Appendix I**: the lab environment (Docker Compose, the policy engine, the trace collector, and the isolated range).

To build Palisade along with the book, start at Chapter 4, where the first skeleton goes in, and follow each chapter's Palisade build thread. Each lab runs with `python -m palisade.labs.chNN`.
