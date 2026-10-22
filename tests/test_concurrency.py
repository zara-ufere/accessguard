import os
import threading

import pytest
from sqlalchemy.orm import Session

from accessguard import audit, service

pytestmark = pytest.mark.skipif(
    not os.environ.get("TEST_DATABASE_URL", "").startswith("postgresql"),
    reason="needs a database with real row locking (PostgreSQL)")


def test_parallel_writers_never_fork_the_audit_chain(engine):
    errors = []

    def worker(n):
        try:
            for i in range(5):
                with Session(engine) as s:
                    service.create_user(s, f"worker{n}", f"user-{n}-{i}", "Worker")
                    s.commit()
        except Exception as exc:  # noqa: BLE001 - any failure fails the test below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    with Session(engine) as s:
        result = audit.verify(s)
    assert result.ok and result.checked == 40
