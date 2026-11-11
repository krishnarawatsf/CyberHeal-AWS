# AWS redesign — scope, cost and safety decisions

## AWS service mapping

| Old OpenStack service | AWS replacement | Student-lab choice |
|---|---|---|
| Nova | EC2 | One test workload, optional verifier only during demo |
| Cinder | EBS | Encrypted sample-data volume + trusted snapshots |
| Neutron | VPC, Security Groups | Existing default VPC; baseline SG and no-egress quarantine SG |
| Keystone | AWS IAM | SSO/federated users and minimum IAM roles |
| Senlin | EC2 Auto Scaling | Optional controlled scale-out proof if still required by supervisor |
| OpenStack SDK | boto3 | C EBS adapter, B quarantine code |
| OpenTofu OpenStack provider | OpenTofu AWS provider | `infra/tofu/` |
| VM direct SSH | Systems Manager | No inbound ports; requires SSM IAM and network connectivity |

**Architecture decision:** A, B, C application services can run on team laptops (or a local Docker host) to reduce AWS charges. One EC2 instance hosts a *test workload and EBS data volume*. A separate verifier EC2 is enabled only for isolated verification. This is a change from the original 3-cloud-VM specification and should be captured in the supervisor-approved decision log. AWS approval does not automatically waive requirements for Wazuh, CI/CD, Ansible or scaling; confirm those individually.

## Billing and account safeguards

1. Choose one dedicated AWS test account, one Region, and confirm pricing. New-account credits vary by account and plan; credits are not a blanket free-use guarantee.
2. Set AWS Budgets alerts and billing notifications **before provisioning**. Assign one operator for provisioning and cleanup.
3. Public IPv4, EBS provisioned storage, snapshot storage and EC2 usage can be charged even when you are not actively testing. Stopping EC2 does **not** remove EBS/snapshot charges. Check pricing pages before each demo.
4. `infra/tofu` defaults to one `t3.small` EC2 instance, 8 GiB encrypted data volume, 12 GiB encrypted root volume, public IPv4 and an SSM profile. It may not be sufficient to run Wazuh manager or LLM; those run locally.
5. No NAT Gateway, GPU, managed database, load balancer or multiple always-on application VMs. Use the default VPC; this simplifies initial deployment at the expense of account/network isolation compared with a custom VPC.
6. Data volume has `prevent_destroy = true` to avoid accidental destruction. That means cleanup requires an **explicitly reviewed** Terraform change plus confirmation that all snapshots needed for evidence are retained. Do not leave expensive resources indefinitely.
7. The `enable_verifier` switch defaults `false` to avoid a continuously running second instance.

## Protection requirements

- AWS IAM and session/account restrictions are primary authorization; application tag/ID guards are additional controls, **not a substitute** for IAM.
- B authorizes cloud containment via OPA, logs policy and action results, and only acts on explicitly approved EC2/SG IDs.
- C does not accept user-supplied `TrustedRecoveryDecision` objects or unverified snapshot labels. The decision is fetched from B's protected audit store; C's trust record is signed after independent baseline validation.
- The C adapter is opt-in for mutations and creates detached recovery volumes. It does **not** automatically attach/mount, delete anything, or switch traffic.
- A quarantine Security Group with no egress disconnects SSM too. Restore the original SG through the AWS Console when authorized. SG quarantine is not a forensic guarantee and does not control all traffic (e.g., certain AWS-reserved DNS services).
- Recover from a known-good point created before suspicious activity. Snapshots of running volumes may not contain unflushed application data. For the lab baseline, flush/unmount and detach the test data volume before creating a snapshot.
- Audit all operations, refuse duplicates, stop on uncertain state, and require manual supervisor/operator approval for final return to service in the first live version.

## Official references

- https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-volume.html
- https://docs.aws.amazon.com/en_en/ebs/latest/userguide/ebs-attaching-volume.html
- https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-for-amazon-ec2.html
- https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
- https://aws.amazon.com/free/
