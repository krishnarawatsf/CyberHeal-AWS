# FOR MEMBER A — Integration and infrastructure readiness

C's recovery module is independently runnable with MOCK adapters and a local
unit test suite. A's supplied `cyberheal_detect` files were left unchanged.
There is **no Member B implementation** in the received ZIP. Please distribute
only C's patch to the master project copy; avoid overwriting each other's files.

## A must answer before any real cloud code runs

1. Is there a live OpenStack deployment, and who administers it?
2. Does it expose Keystone, Nova, Neutron, Cinder? Is Senlin installed?
3. Does C have a least-privilege, isolated project with volume/snapshot
   quotas, an approved test VM, and secure credentials?
4. What image/flavor/network/security-group scheme will VM-1/2/3 use?
5. Which workload data is actually on Cinder, and how is it quiesced for a
   consistent snapshot? A's current source tree is a *detection module* and
   does not supply a persistent cloud test application's health endpoint.
6. Is Senlin compulsory? If unavailable, approve Heat/scripted fallback with
   the instructor before the demonstration.
7. Who owns the definitive shared ZIP and publishes versioned releases?

## A's required integration work

- Alert JSON stays as in `docs/contracts/alert.md`; `incident_id`, timestamps,
  resource IDs and `schema_version` must be preserved.
- Continue owning Wazuh, the detector, Gitea/Woodpecker and monitoring.
- Consume C verification result and expose:
  `cyberheal_recover_rcs`, `cyberheal_recover_decision_total`,
  `cyberheal_recover_failed_total` when C's exporter is implemented.
- Alert also on `decision != SAFE` because an RCS score alone is insufficient.
- CI should run C's tests after C's files are merged, then mocked E2E tests.
- Agree on a trusted first-suspicious timestamp and B -> C authorization
  before any production-like containment/recovery integration.

## Current technical gaps

The live OpenStack driver, recovery volume attachment/mount, actual identity
and network probes, independent clean-snapshot verification registry,
Prometheus exporter, durable audit job store and Senlin implementation remain
to be integrated and cloud-tested. Do not report them as completed.
