"""Optional read-only AWS discovery. No mutations are performed."""

import argparse

from .openstack_cinder import connect_to_lab


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only AWS lab preflight")
    parser.add_argument("--cloud", required=True, help="name in uncommitted clouds.yaml")
    args = parser.parse_args()
    conn = connect_to_lab(args.cloud)
    project = conn.session.get_account_id()
    print("Authenticated project ID:", project)
    print("Compute instances:", len(list(conn.compute.servers())))
    print("Networks:", len(list(conn.network.networks())))
    print("EBS volumes:", len(list(conn.block_storage.volumes())))
    print("EBS snapshots:", len(list(conn.block_storage.snapshots())))
    print("Preflight completed; no resources were changed.")


if __name__ == "__main__":
    main()
