import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from accessguard import audit, cli, reports
from accessguard.config import load_tokens
from accessguard.models import User
from accessguard.seed import seed


def test_seed_loads_a_realistic_demo_and_refuses_to_run_twice(session):
    assert seed(session) is True
    assert seed(session) is False
    assert audit.verify(session).ok
    report = reports.risk_report(session)
    assert report["totals"] == {"open": 5, "accepted": 1, "remediated": 0}
    flagged = {u["username"] for u in report["users"]}
    assert flagged == {"carol", "dave", "erin", "grace", "mona", "frank"}  # judy is disabled; the rest are clean
    carol = next(u for u in report["users"] if u["username"] == "carol")
    assert carol["rating"] == "High"
    judy = session.query(User).filter_by(username="judy").one()
    assert judy.status == "disabled"


def test_load_tokens_parses_and_validates():
    tokens = load_tokens("secret-token-1:alice:admin, secret-token-2:bob:auditor")
    assert tokens["secret-token-1"].role == "admin" and tokens["secret-token-2"].name == "bob"
    assert load_tokens("") == {}
    for bad in ("nocolons", "tok:alice", "short:alice:admin", "longenough:alice:root"):
        with pytest.raises(ValueError):
            load_tokens(bad)


def test_cli_seed_scan_and_audit_verification(tmp_path, monkeypatch, capsys):
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    assert cli.main(["seed"]) == 0
    assert "Demo data loaded" in capsys.readouterr().out
    assert cli.main(["seed"]) == 0
    assert "nothing changed" in capsys.readouterr().out
    assert cli.main(["scan"]) == 0
    assert "Scan complete" in capsys.readouterr().out
    assert cli.main(["verify-audit"]) == 0
    assert "Audit chain intact" in capsys.readouterr().out

    engine = create_engine(url)
    with Session(engine) as s:  # tamper directly in the database
        s.execute(text("DROP TRIGGER audit_log_no_update"))
        s.execute(text("UPDATE audit_log SET actor = 'mallory' WHERE seq = 10"))
        s.commit()
    engine.dispose()
    assert cli.main(["verify-audit"]) == 1
    assert "BROKEN at entry 10" in capsys.readouterr().err
