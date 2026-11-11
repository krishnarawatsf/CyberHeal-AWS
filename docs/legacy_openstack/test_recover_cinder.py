"""Offline Cinder SDK-adapter tests using simple fakes; never contact OpenStack."""

from types import SimpleNamespace as NS

import pytest

from cyberheal_recover.openstack_cinder import CinderLabGateway


class BlockStorage:
    def __init__(self):
        self.volume = NS(id="data-vol", project_id="testproject", status="available", size=1)
        self.snapshot = NS(id="snap1", project_id="testproject", status="available", volume_id="data-vol")
        self.created = []

    def get_volume(self, volume_id):
        assert volume_id == "data-vol"
        return self.volume

    def get_snapshot(self, snapshot_id):
        assert snapshot_id == "snap1"
        return self.snapshot

    def create_volume(self, **attrs):
        self.created.append(("volume", attrs))
        return NS(id="new-volume")

    def create_snapshot(self, **attrs):
        self.created.append(("snapshot", attrs))
        return NS(id="created-snapshot")


def gateway():
    bs = BlockStorage()
    connection = NS(session=NS(get_project_id=lambda: "testproject"), block_storage=bs)
    return CinderLabGateway(connection, expected_project_id="testproject", approved_source_volume_id="data-vol"), bs


def test_lab_project_must_match():
    bs = BlockStorage()
    connection = NS(session=NS(get_project_id=lambda: "other-project"), block_storage=bs)
    with pytest.raises(PermissionError):
        CinderLabGateway(connection, expected_project_id="testproject", approved_source_volume_id="data-vol")


def test_create_snapshot_requires_available_volume():
    g, bs = gateway()
    bs.volume.status = "in-use"
    with pytest.raises(RuntimeError):
        g.create_snapshot_of_clean_stopped_volume(name="cyberheal-snapshot")
    assert not bs.created


def test_create_available_snapshot():
    g, bs = gateway()
    assert g.create_snapshot_of_clean_stopped_volume(name="cyberheal-clean-1") == "created-snapshot"
    assert bs.created[0][1]["force"] is False


def test_clone_creates_new_volume_without_deleting_original():
    g, bs = gateway()
    assert g.create_recovery_volume(source_volume_id="data-vol", snapshot_id="snap1", incident_id="abc") == "new-volume"
    assert bs.created == [("volume", {"name": "cyberheal-recovery-abc", "size": 1, "snapshot_id": "snap1"})]


def test_clone_refuses_other_volume():
    g, bs = gateway()
    with pytest.raises(PermissionError):
        g.create_recovery_volume(source_volume_id="other", snapshot_id="snap1", incident_id="abc")
    assert not bs.created


def test_clone_refuses_snapshot_from_other_project():
    g, bs = gateway()
    bs.snapshot.project_id = "wrong"
    with pytest.raises(PermissionError):
        g.create_recovery_volume(source_volume_id="data-vol", snapshot_id="snap1", incident_id="abc")
    assert not bs.created


def test_missing_project_metadata_fails_closed():
    g, bs = gateway()
    bs.snapshot.project_id = None
    with pytest.raises(PermissionError):
        g.create_recovery_volume(source_volume_id="data-vol", snapshot_id="snap1", incident_id="abc")
    assert not bs.created
