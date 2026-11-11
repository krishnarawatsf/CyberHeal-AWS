# Member B integration — AWS edition

**Read `../aws/01_MEMBER_B_BUILD_GUIDE.md` and `../contracts/recovery-request.md`.** The original OpenStack B handoff has been superseded. C requires an authenticated and incident-specific OPA `recover_volume` decision for an exact EC2/EBS pair in the correct AWS account, and a trustworthy first suspicious timestamp. Returned `snapshot_id` is now EBS `snap-*`. B does not write C's recovery implementation.
