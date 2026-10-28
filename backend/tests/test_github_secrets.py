import pytest

from app.config import settings
from collectors.base import CollectorConfigurationError
from collectors.identity.github_secrets import GitHubSecretsCollector


def test_github_repo_normalization_uses_ui_contract():
    finding = GitHubSecretsCollector().normalize({
        "type": "repo_found",
        "repo_name": "acme/platform",
        "repo_url": "https://github.com/acme/platform",
        "description": "Public platform repository",
        "language": "Python",
        "stars": 12,
        "target_brand": "acme",
    })

    assert finding["entity_type"] == "GITHUB_REPO"
    assert finding["normalized_data"]["repo_name"] == "acme/platform"
    assert finding["normalized_data"]["repo_url"] == "https://github.com/acme/platform"
    assert "search-strategy:exact-domain-v2" in finding["tags"]
    assert finding["normalized_data"]["search_strategy"] == "exact_domain_v2"


def test_github_secret_normalization_is_metadata_only():
    finding = GitHubSecretsCollector().normalize({
        "type": "code_match",
        "repo_name": "acme/platform",
        "repo_url": "https://github.com/acme/platform",
        "file_path": "config/example.env",
        "file_url": "https://github.com/acme/platform/blob/main/config/example.env",
        "secret_type": "API_KEY",
        "target_brand": "acme",
        "target_domain": "acme.example",
        "domain_proximity": "near",
        "publisher_email": "developer@acme.example",
        "auto_generated": False,
    })

    assert finding["entity_type"] == "LEAKED_SECRET"
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == 0.95
    assert "potential-secret" in finding["tags"]
    assert finding["normalized_data"]["classifier_version"] == 2
    serialized = str(finding["normalized_data"]).lower()
    assert "snippet" not in serialized
    assert "secret_value" not in serialized
    assert "content" not in serialized


def test_github_collector_requires_token(monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_TOKEN", None)

    with pytest.raises(CollectorConfigurationError, match="configure GITHUB_TOKEN"):
        GitHubSecretsCollector()._get_github()


def test_github_unauthorized_search_is_a_configuration_failure():
    from github import GithubException

    class UnauthorizedGithub:
        def search_repositories(self, **_kwargs):
            raise GithubException(401, {"message": "Bad credentials"}, {})

    with pytest.raises(CollectorConfigurationError, match="authentication failed"):
        GitHubSecretsCollector()._search_repos(
            UnauthorizedGithub(), "acme", "acme.example"
        )


def test_short_brand_requires_token_boundaries_for_proximity():
    collector = GitHubSecretsCollector()
    unrelated = "cutmvalue = true\napi_key = 'abcdefghijklmnop'"
    related = "service = utm\napi_key = 'abcdefghijklmnop'"

    assert collector._measure_proximity(unrelated, "utm.tn", "utm") == "far"
    assert collector._measure_proximity(related, "utm.tn", "utm") == "near"


def test_specific_secret_far_from_target_is_not_high_severity():
    finding = GitHubSecretsCollector().normalize({
        "type": "code_match",
        "repo_name": "acme/platform",
        "repo_url": "https://github.com/acme/platform",
        "file_path": "README.md",
        "file_url": "https://github.com/acme/platform/blob/main/README.md",
        "secret_type": "API_KEY",
        "target_brand": "acme",
        "target_domain": "acme.example",
        "domain_proximity": "far",
        "publisher_email": "",
        "auto_generated": False,
    })

    assert finding["severity"] == "MEDIUM"
    assert finding["confidence"] == 0.55


def test_configuration_errors_are_not_retried(monkeypatch):
    import asyncio

    collector = GitHubSecretsCollector()
    calls = 0

    async def fail(_target):
        nonlocal calls
        calls += 1
        raise CollectorConfigurationError("bad token")

    monkeypatch.setattr(collector, "collect", fail)
    monkeypatch.setattr("collectors.base.asyncio.sleep", lambda _delay: _no_sleep())

    async def execute():
        with pytest.raises(CollectorConfigurationError, match="bad token"):
            await collector.execute("acme.example")

    asyncio.run(execute())
    assert calls == 1


async def _no_sleep():
    return None
