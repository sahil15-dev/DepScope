"""Create the scan history and advisory snapshot schema."""

import sqlalchemy as sa
from alembic import op

revision = "0001_scan_history"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("provenance", sa.String(16), nullable=False),
        sa.Column("sample_id", sa.String(32)),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("requested_at", sa.String(32), nullable=False),
        sa.Column("started_at", sa.String(32)),
        sa.Column("finished_at", sa.String(32)),
        sa.Column("observed_at", sa.String(32)),
        sa.Column("error_code", sa.String(48)),
        sa.Column("result_version", sa.Integer()),
        sa.Column("lockfile_version", sa.Integer()),
        sa.Column("risk_index", sa.Integer()),
        sa.Column("scoring_revision", sa.String(16)),
        sa.Column("coverage", sa.JSON(none_as_null=True)),
        sa.Column("severity_counts", sa.JSON(none_as_null=True)),
        sa.Column("limitations", sa.JSON(none_as_null=True)),
        sa.CheckConstraint("format IN ('requirements','npm-lock')", name="ck_scan_format"),
        sa.CheckConstraint("source IN ('paste','upload','sample')", name="ck_scan_source"),
        sa.CheckConstraint(
            "(source = 'sample' AND provenance = 'offline_fixture' AND sample_id IS NOT NULL) OR "
            "(source IN ('paste','upload') AND provenance = 'live_osv' AND sample_id IS NULL)",
            name="ck_scan_provenance",
        ),
        sa.CheckConstraint(
            "(status = 'queued' AND started_at IS NULL AND finished_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL) OR "
            "(status IN ('complete','partial') AND started_at IS NOT NULL "
            "AND finished_at IS NOT NULL) OR "
            "(status = 'failed' AND finished_at IS NOT NULL)",
            name="ck_scan_lifecycle",
        ),
        sa.CheckConstraint("risk_index BETWEEN 0 AND 100", name="ck_scan_risk"),
    )
    op.create_index("ix_scans_requested", "scans", ["requested_at", "id"])
    op.create_index("ix_scans_provenance_requested", "scans", ["provenance", "requested_at", "id"])
    op.create_table(
        "scanned_coordinates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("ecosystem", sa.String(8), nullable=False),
        sa.Column("name", sa.String(214), nullable=False),
        sa.Column("version", sa.String(128), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("diagnostics", sa.JSON(), nullable=False),
        sa.UniqueConstraint(
            "scan_id", "ecosystem", "name", "version", name="uq_coordinate_identity"
        ),
        sa.UniqueConstraint("scan_id", "id", name="uq_coordinate_scan_id"),
        sa.CheckConstraint("ecosystem IN ('PyPI','npm')", name="ck_coordinate_ecosystem"),
        sa.CheckConstraint(
            "status IN ('complete','partial','failed')", name="ck_coordinate_lookup"
        ),
    )
    op.create_table(
        "dependency_occurrences",
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id"), primary_key=True),
        sa.Column("position", sa.Integer(), primary_key=True),
        sa.Column("coordinate_id", sa.Integer()),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ("scan_id", "coordinate_id"),
            ("scanned_coordinates.scan_id", "scanned_coordinates.id"),
            name="fk_occurrence_coordinate_scan",
        ),
    )
    op.create_table(
        "advisory_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provenance", sa.String(16), nullable=False),
        sa.Column("advisory_id", sa.String(128), nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("captured_at", sa.String(32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.UniqueConstraint(
            "provenance", "advisory_id", "level", "content_hash", name="uq_advisory_snapshot"
        ),
        sa.CheckConstraint("level IN ('hydrated','discovery_only')", name="ck_advisory_level"),
        sa.CheckConstraint(
            "provenance IN ('live_osv','offline_fixture')", name="ck_advisory_provenance"
        ),
    )
    op.create_table(
        "advisory_observations",
        sa.Column(
            "coordinate_id", sa.Integer(), sa.ForeignKey("scanned_coordinates.id"), primary_key=True
        ),
        sa.Column("advisory_id", sa.String(128), primary_key=True),
        sa.Column(
            "snapshot_id", sa.Integer(), sa.ForeignKey("advisory_snapshots.id"), nullable=False
        ),
        sa.Column("discovery", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(48)),
    )
    op.create_index("ix_observations_snapshot", "advisory_observations", ["snapshot_id"])
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("coordinate_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("advisory_id", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(8), nullable=False),
        sa.Column(
            "fix_available",
            sa.Boolean(create_constraint=True, name="ck_finding_fix_available"),
            nullable=False,
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ("scan_id", "coordinate_id"),
            ("scanned_coordinates.scan_id", "scanned_coordinates.id"),
            name="fk_finding_coordinate_scan",
        ),
        sa.UniqueConstraint("coordinate_id", "advisory_id", name="uq_finding_identity"),
        sa.UniqueConstraint("scan_id", "position", name="uq_finding_position"),
        sa.UniqueConstraint("coordinate_id", "id", name="uq_finding_coordinate_id"),
        sa.CheckConstraint(
            "severity IN ('critical','high','medium','low','none','unknown')",
            name="ck_finding_severity",
        ),
    )
    op.create_index("ix_findings_scan_severity", "findings", ["scan_id", "severity", "position"])
    op.create_table(
        "finding_advisories",
        sa.Column("finding_id", sa.Integer(), primary_key=True),
        sa.Column("advisory_id", sa.String(128), primary_key=True),
        sa.Column("coordinate_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ("coordinate_id", "finding_id"),
            ("findings.coordinate_id", "findings.id"),
            name="fk_link_finding_coordinate",
        ),
        sa.ForeignKeyConstraint(
            ("coordinate_id", "advisory_id"),
            ("advisory_observations.coordinate_id", "advisory_observations.advisory_id"),
            name="fk_link_observation",
        ),
    )
    op.create_index(
        "ix_finding_links_observation", "finding_advisories", ["coordinate_id", "advisory_id"]
    )


def downgrade() -> None:
    op.drop_table("finding_advisories")
    op.drop_table("findings")
    op.drop_table("advisory_observations")
    op.drop_table("advisory_snapshots")
    op.drop_table("dependency_occurrences")
    op.drop_table("scanned_coordinates")
    op.drop_table("scans")
