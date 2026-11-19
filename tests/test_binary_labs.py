from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.lab import main as lab


@pytest.mark.parametrize(
    ("challenge_key", "page", "other_page"),
    [
        ("reverse-01", "/reverse/", "/pwn/"),
        ("pwn-01", "/pwn/", "/reverse/"),
    ],
)
def test_binary_lab_pages_are_scoped_to_the_active_challenge(
    monkeypatch,
    challenge_key: str,
    page: str,
    other_page: str,
):
    monkeypatch.setattr(lab.app.state, "challenge_key", challenge_key, raising=False)

    with TestClient(lab.app) as client:
        page_response = client.get(page)
        assert page_response.status_code == 200
        assert page_response.text.index("<form") < page_response.text.index("<details class=\"hint\">")
        if challenge_key == "reverse-01":
            assert "<summary>Подсказка</summary>" in page_response.text
            assert "objdump -s -j .rodata ./revcheck" in page_response.text
            assert "примените XOR с той же константой" in page_response.text
            assert "Сложность: сложная" in page_response.text
            assert "Категория: Reverse Engineering" in page_response.text
        else:
            assert "<summary>Подсказка</summary>" in page_response.text
            assert "objdump -d -M intel ./safevm" in page_response.text
            assert "целевое состояние <code>0x2a</code>" in page_response.text
            assert "Сложность: сложная" in page_response.text
            assert "Категория: Pwn / Binary" in page_response.text
        assert client.get(other_page).status_code == 404
        assert client.get("/reverse/download" if challenge_key == "pwn-01" else "/pwn/download").status_code == 404


@pytest.mark.parametrize(
    ("challenge_key", "endpoint", "field", "binary_name", "answer", "flag"),
    [
        ("reverse-01", "/reverse/submit", "answer", "revcheck", "candidate", "CTF{reverse_flag}"),
        ("pwn-01", "/pwn/submit", "program", "safevm", "200100fe", "CTF{safevm_flag}"),
    ],
)
def test_binary_submission_runs_only_its_fixed_checker_and_returns_its_flag(
    monkeypatch,
    challenge_key: str,
    endpoint: str,
    field: str,
    binary_name: str,
    answer: str,
    flag: str,
):
    invoked = []
    monkeypatch.setattr(lab.app.state, "challenge_key", challenge_key, raising=False)
    monkeypatch.setitem(lab.LAB_MATERIALS, challenge_key, flag)
    monkeypatch.setattr(
        lab,
        "run_binary",
        lambda binary, value: invoked.append((binary, value)) or True,
    )

    with TestClient(lab.app) as client:
        response = client.post(endpoint, data={field: answer})

    assert response.status_code == 200
    assert flag in response.text
    assert invoked == [(binary_name, answer)]


def test_binary_submission_does_not_disclose_flag_when_checker_rejects(monkeypatch):
    monkeypatch.setattr(lab.app.state, "challenge_key", "reverse-01", raising=False)
    monkeypatch.setitem(lab.LAB_MATERIALS, "reverse-01", "CTF{secret_flag}")
    monkeypatch.setattr(lab, "run_binary", lambda *_: False)

    with TestClient(lab.app) as client:
        response = client.post("/reverse/submit", data={"answer": "wrong"})

    assert response.status_code == 200
    assert "CTF{secret_flag}" not in response.text
    assert "Продолжайте анализ" in response.text


def test_binary_runner_uses_fixed_executable_timeout_and_no_shell(monkeypatch):
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(lab.subprocess, "run", fake_run)

    assert lab.run_binary("revcheck", "short input") is True
    args, kwargs = calls[0]
    assert args == (["/usr/local/bin/revcheck", "short input"],)
    assert kwargs["timeout"] == 1
    assert kwargs["check"] is False
    assert "shell" not in kwargs
    assert "LAB_CHALLENGE_FLAG" not in kwargs["env"]


def test_binary_runner_reports_nul_input_and_timeout(monkeypatch):
    with pytest.raises(HTTPException) as invalid:
        lab.run_binary("safevm", "bad\x00input")
    assert invalid.value.status_code == 422

    def timeout(*args, **kwargs):
        raise lab.subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(lab.subprocess, "run", timeout)
    with pytest.raises(HTTPException) as timed_out:
        lab.run_binary("safevm", "00")
    assert timed_out.value.status_code == 503
