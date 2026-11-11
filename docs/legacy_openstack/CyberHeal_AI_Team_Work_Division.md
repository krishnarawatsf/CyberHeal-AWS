# CyberHeal AI: Team Work Division

Members: A, B, C
Based on: CyberHeal AI Open Source Cloud Project Document

---

## 1. Overview

| Member | Owned VM | Primary module | DevOps ownership | Individual demo |
|---|---|---|---|---|
| A | VM-1 | Detect and Monitor | Gitea, Woodpecker CI, Podman/Buildah, Prometheus, Grafana, Alertmanager | Generate a controlled anomaly and produce a threat alert |
| B | VM-2 | Investigate and Respond | FastAPI service contracts, OPA policy repository | Investigate an alert and execute one allowed containment action |
| C | VM-3 | Recover and Verify | OpenTofu, Ansible, OpenStack Senlin scaling | Restore a workload and produce a SAFE, REVIEW, or UNSAFE decision |

Each member is the single owner of their module. Others may review and contribute through pull requests, but the owner makes the final design decision for their module.

---

## 2. Member A: Detect and Monitor (VM-1)

**Responsibility:** Build the detection pipeline from telemetry to a threat alert.

A owns:

- The test workload on VM-1 and its Wazuh agent.
- Wazuh server and agent configuration, including file-integrity monitoring on the sample-data directory.
- The ransomware-like simulator, which safely transforms and renames sample files, and the credential-anomaly simulator, which generates controlled failed logins and privilege changes.
- Feature extraction: file entropy change, modification and rename frequency, hash changes, failed authentication patterns, privilege or account changes, and abnormal administrative API actions.
- The scikit-learn detector, including training, threshold tuning, and evaluation on labelled simulations.
- The threat alert output in the agreed schema (see Section 6).
- Observability: Prometheus, Grafana dashboards, and Alertmanager rules, including CriticalThreatCount, InvestigationFailed, RecoveryFailed, RecoveryConfidenceScore below 85, and CPU, memory, disk, and VM health alarms.
- DevOps: Gitea repository and access rules, Woodpecker CI pipelines (lint, tests, scans, build, deploy), and Podman/Buildah image builds.

A does not own the LLM, OPA policies, or recovery logic.

**Start here (week 1):** Set up Gitea and the Woodpecker pipeline skeleton, then install the Wazuh agent on VM-1 and confirm it reports file-integrity events.

---

## 3. Member B: Investigate and Respond (VM-2)

**Responsibility:** Turn an alert into an explained incident and a policy-approved action.

B owns:

- The FastAPI backend, including the investigation endpoint, the response endpoint, and the incident store.
- Local LLM integration using llama.cpp or vLLM, with a small quantized model and structured prompts. The LLM is advisory only.
- Evidence sanitisation before anything reaches the LLM, and the structured incident schema covering timeline, probable root cause, affected resources, and risk score.
- The OPA policy repository: allow-list of actions, deny-by-default behaviour, and policy tests.
- OpenStack SDK containment actions limited to the allow-listed set: network isolation or quarantine security group for the test VM, and disabling or restricting the test credential.
- The response audit trail: every decision logged with incident ID, resource, policy decision, and result.

B has the heaviest workload. If B falls more than one phase behind, the team re-plans (see Section 8).

B's response service must not hold broader OpenStack permissions than the allow-listed actions require.

**Start here (week 1):** Stand up a FastAPI skeleton with a health endpoint, and write the first OPA allow-list policy with tests.

---

## 4. Member C: Recover and Verify (VM-3)

**Responsibility:** Restore a workload from a trusted state and decide whether it is safe to return to service.

C owns:

- The Cinder volume for sample data and the procedure for capturing clean snapshots.
- Trusted recovery-point selection: choose a snapshot by timestamp and validation status, not simply the most recent one.
- Restore automation for the affected volume and workload.
- Verification checks:
  - Identity: test account disabled, expected roles only.
  - File and integrity: hashes, entropy, integrity checks.
  - Network: expected Neutron rules, no unwanted exposure.
  - Configuration: known-good baseline restored.
  - Application health: API and functional check.
- Recovery Confidence Score: RCS = 0.25I + 0.25F + 0.20N + 0.15C + 0.15H, with SAFE at 85 to 100, REVIEW at 70 to 84, and UNSAFE at 0 to 69. These thresholds are project-defined and should be presented as an experimental policy.
- DevOps: OpenTofu provisioning of the OpenStack project, network, VMs, and volumes; Ansible playbooks for repeatable configuration; and the Senlin scaling cluster for the stateless worker tier.

C's verification output is the final gate. Recovery is complete only when C's policy passes.

**Start here (week 1):** Confirm the OpenStack project, network, and three VMs are reachable, then take the first clean Cinder snapshot of the sample-data volume.

---

## 5. Shared Responsibilities

| Work item | Lead | Support | Notes |
|---|---|---|---|
| Project requirements and this document | All | All | Reviewed together at each review |
| Incident JSON schema | B | A, C | Agreed in Phase 3 before detection output is finalised |
| Snapshot and restore contract | C | B | Defines what B's response may request |
| Evaluation metrics and results tables | A | B, C | Each member supplies metrics for their module |
| Final report sections | Each module owner | A (integrator) | Consistent terminology throughout |
| Demo rehearsal | All | All | Full end-to-end run at least twice before review |

---

## 6. Interfaces Between Modules

Each handoff is a written contract stored in the repository under `docs/contracts`.

**Handoff 1, A to B: Threat alert.** Contains incident ID, timestamp, resource identifier (VM and volume), alert type, confidence score, the feature values that triggered the alert, and sanitised evidence references. No raw credentials or secrets.

**Handoff 2, B to C: Containment and recovery request.** After OPA approves an action, B records the decision and sends C a recovery request with the incident ID, affected resource, and the requested time window for a trusted snapshot. C does not accept a request without an OPA decision reference.

**Handoff 3, C to B and A: Verification result.** Contains the RCS, per-factor scores, the decision (SAFE, REVIEW, or UNSAFE), and the snapshot used. A's dashboard displays the result, and the RecoveryConfidenceScore alarm fires when the score falls below 85.

---

## 7. Phase Plan

| Phase | Target work | Lead | Support | Output |
|---|---|---|---|---|
| 1. Cloud foundation | OpenStack project and network, three VMs, Cinder volumes | C | A, B | Reachable, isolated lab |
| 2. DevOps foundation | Gitea, Woodpecker, Ansible, container workflow | A | C | Repeatable pipeline |
| 3. Detection | Wazuh, simulators, ML features and model | A | B | Threat alert output |
| 4. Investigation | FastAPI, local LLM, incident schema | B | A | Timeline and root-cause report |
| 5. Response | OPA policies, OpenStack SDK actions | B | C | Audited containment |
| 6. Recovery | Cinder snapshots, restore automation | C | B | Trusted recovery workflow |
| 7. Verification | Integrity, IAM, network, config, and health checks, RCS | C | A | SAFE, REVIEW, or UNSAFE decision |
| 8. Observability and scaling | Prometheus, Grafana, Alertmanager, Senlin | A | C | Alarms and scale-out and scale-in demo |
| 9. Evaluation | Repeated scenario runs and metrics | A | B, C | Results tables for final review |

Phase 9 is shared: each member runs the scenarios for their own module and reports the numbers.

---

## 8. Working Rules

**Branches and reviews.** Work on feature branches named by module, for example `detect/entropy-features` or `respond/opa-allowlist`. The main branch is protected. Every change reaches main through a pull request reviewed by one other member and passing the Woodpecker pipeline. The module owner approves changes to their module.

**Commit messages.** Start each message with the module tag: `[detect]`, `[investigate]`, `[respond]`, `[recover]`, or `[devops]`.

**Weekly integration.** Meet once a week to merge completed work, check handoff contracts, and review phase status. Raise any blocker lasting more than two working days at this meeting.

**Workload guardrail.** If one member falls more than one phase behind, re-plan. Options include moving a non-core task to another member or dropping an optional component. Do not add optional components until the core loop works end to end.

**Scope freeze.** Infrastructure scope is frozen at the end of Phase 2. Later changes need agreement from all three members and must be recorded in the decision log.

---

## 9. Scope Priorities

**Core (required for Review 2):** OpenStack Nova, Neutron, Cinder, and Keystone; Wazuh; Python, scikit-learn, and FastAPI; a local LLM; OPA; Prometheus, Grafana, and Alertmanager; OpenTofu and Ansible; Gitea and Woodpecker; Podman and Buildah; Senlin if the lab supports it.

**Optional (only after the core demo is stable):** Ceph if the lab does not provide storage, Harbor, OpenBao, Falco, model fine-tuning, and additional attack scenarios.

**Senlin fallback:** If Senlin is unavailable, use a scripted scaling demonstration or a Heat-based alternative, approved by the instructor first.

---

## 10. Review Deliverables

**Review 1 (initial review)**
- A: Problem statement, base paper, research gap, detection design, monitoring plan.
- B: Four-module architecture with data and control flow, LLM and OPA design, security model.
- C: OpenStack architecture, storage and recovery design, scaling design, verification model.
- All: DevOps architecture, individual contribution plan, roadmap, planned evaluation metrics.

**Review 2 (final demonstration)**
- Team: Three working VMs in an isolated network, centralised telemetry, alarms and dashboard, scaling demo, and live runs of the ransomware-like and compromised-credential scenarios.
- Each member: Individual technical demo of their module, with audit evidence and CI/CD and IaC history.

---

## 11. Individual Contribution Evidence

Keep the following throughout the project:

- Git and Gitea commits, pull requests authored, and reviews given, tagged by module.
- The OpenStack resources you own, listed in your section of the repository.
- CI/CD run history for pipelines you own.
- Test results for your module: labelled simulation results for A and B, verification test cases for C.
- A recorded individual live demonstration prepared for Review 2.

---

## 12. Risks and Owners

| Risk | Owner | Mitigation |
|---|---|---|
| OpenStack deployment complexity | C | Use the existing lab OpenStack; freeze infrastructure scope at Phase 2 |
| LLM hardware limits | B | Small quantized model and structured prompts |
| Too many tools for three members | Lead of each phase | Core stack first; optional tools only after end-to-end flow works |
| Unsafe automation | B | OPA allow-list, least privilege, controlled test resources only |
| False positives in detection | A | Labelled simulations, threshold tuning, precision and recall reporting |
| Recovery point is not clean | C | Track trusted snapshot timestamp; run full post-restore verification |
| Scaling service unavailable | C | Senlin where deployed; otherwise an instructor-approved fallback |
| Uneven workload on B | All | Workload guardrail in Section 8 |

---

## 13. Decision Log

| Date | Decision | Agreed by |
|---|---|---|
| | | |

---

## 14. Open Items for the Supervisor

- Whether the lab provides OpenStack with Senlin and Cinder, or whether the scaling fallback is needed.
- Whether LLM hardware is available for vLLM, or whether llama.cpp with a small model will be used.
- Whether Ceph is provided by the lab or left as an optional enhancement.
- The format and location required for individual contribution evidence.
