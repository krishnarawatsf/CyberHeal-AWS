"""Conservative Cinder SDK adapter. No implicit deletion or production switch.

This module is importable without the optional openstacksdk dependency. No live
cloud validation has yet been performed. Authenticate using an uncommitted
clouds.yaml or an approved environment configuration.
"""

from typing import Any


class CinderLabGateway:
    """Cloud adapter restricted to a known project and one approved data volume.

    The service account must be scoped to the same test project. The adapter
    intentionally fails closed if project ownership cannot be established.
    """

    def __init__(
        self,
        connection: Any,
        *,
        expected_project_id: str,
        approved_source_volume_id: str,
    ) -> None:
        if not expected_project_id or not approved_source_volume_id:
            raise ValueError("test project and approved source volume are required")
        self.conn = connection
        self.project_id = expected_project_id
        self.source_volume_id = approved_source_volume_id
        actual_project = self.conn.session.get_project_id()
        if actual_project != expected_project_id:
            raise PermissionError("OpenStack session is not scoped to the approved project")

    def _source_volume(self) -> Any:
        volume = self.conn.block_storage.get_volume(self.source_volume_id)
        if volume is None or getattr(volume, "project_id", None) != self.project_id:
            raise PermissionError("source volume ownership cannot be verified")
        return volume

    def create_snapshot_of_clean_stopped_volume(self, *, name: str) -> str:
        """Capture a snapshot of an available data volume.

        NOT a trusted snapshot until independently verified, and not usable for
        an attached/in-use volume (quiescing must be dealt with separately).
        """
        source = self._source_volume()
        if getattr(source, "status", None) != "available":
            raise RuntimeError("source volume must be detached/available")
        if not name or not name.startswith("cyberheal-"):
            raise ValueError("snapshot name must use the approved lab prefix")
        snapshot = self.conn.block_storage.create_snapshot(
            volume_id=self.source_volume_id,
            name=name,
            force=False,
        )
        return str(snapshot.id)

    def create_recovery_volume(
        self, *, source_volume_id: str, snapshot_id: str, incident_id: str
    ) -> str:
        """Clone to a NEW volume; does not attach, detach, delete or route it."""
        if source_volume_id != self.source_volume_id:
            raise PermissionError("volume outside the approved lab allow-list")
        source = self._source_volume()
        snapshot = self.conn.block_storage.get_snapshot(snapshot_id)
        if snapshot is None:
            raise LookupError("snapshot does not exist")
        snap_project = getattr(snapshot, "project_id", None)
        if snap_project != self.project_id:
            raise PermissionError("snapshot ownership cannot be verified")
        if str(getattr(snapshot, "volume_id", "")) != source_volume_id:
            raise PermissionError("snapshot belongs to another source volume")
        if getattr(snapshot, "status", None) != "available":
            raise RuntimeError("snapshot not available")
        if not incident_id or len(incident_id) > 64:
            raise ValueError("incident ID is required")
        volume = self.conn.block_storage.create_volume(
            name=f"cyberheal-recovery-{incident_id}",
            size=int(source.size),
            snapshot_id=snapshot_id,
        )
        if not getattr(volume, "id", None):
            raise RuntimeError("Cinder did not report a recovered volume ID")
        return str(volume.id)


def connect_to_lab(cloud_name: str) -> Any:
    """Obtain an SDK connection; requires `pip install openstacksdk`."""
    if not cloud_name:
        raise ValueError("cloud_name required")
    try:
        import openstack
    except ImportError as exc:
        raise RuntimeError("install optional openstacksdk for real cloud use") from exc
    return openstack.connect(cloud=cloud_name)
