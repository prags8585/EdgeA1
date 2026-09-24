import pytest

from chameleon import config


def test_assert_local_allows_localhost():
    config.assert_local("http://127.0.0.1:8080/v1/chat/completions")
    config.assert_local("http://localhost:8010/check")


def test_assert_local_rejects_remote_host():
    with pytest.raises(ValueError):
        config.assert_local("https://api.example.com/v1/chat/completions")


def test_assert_local_allows_remote_when_cloud_flag_set():
    config.assert_local("https://api.example.com/v1/chat/completions", allow_cloud=True)
