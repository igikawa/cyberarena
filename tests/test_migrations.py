import importlib

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text


def test_legacy_lab_url_migration_clears_only_known_lab_paths(monkeypatch):
    migration = importlib.import_module(
        "migrations.versions.0006_clear_lab_urls"
    )
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE challenges "
                    "(seed_key VARCHAR(40), resource_url VARCHAR(500))"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO challenges (seed_key, resource_url) VALUES "
                    "('web-01', '/lab/'), "
                    "('pwn-01', '/lab/pwn/'), "
                    "('web-03-sqli', '/materials/guide.pdf'), "
                    "('custom-challenge', '/lab/custom/'), "
                    "('crypto-01', '/tasks/crypto01/download')"
                )
            )
            monkeypatch.setattr(
                migration,
                "op",
                Operations(MigrationContext.configure(connection)),
            )

            migration.upgrade()

            rows = dict(
                connection.execute(
                    text("SELECT seed_key, resource_url FROM challenges")
                ).all()
            )

        assert rows == {
            "web-01": None,
            "pwn-01": None,
            "web-03-sqli": "/materials/guide.pdf",
            "custom-challenge": "/lab/custom/",
            "crypto-01": "/tasks/crypto01/download",
        }
    finally:
        engine.dispose()
