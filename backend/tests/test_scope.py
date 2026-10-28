from app.services.scope import ScopeEvaluator, normalized_scope_manifest


def test_domain_scope_uses_boundary_matching_and_explicit_exclusions():
    manifest = normalized_scope_manifest(
        {
            "allowed_domains": ["example.com"],
            "excluded_domains": ["admin.example.com"],
        },
        "domain",
        "example.com",
    )
    scope = ScopeEvaluator(manifest, target_type="domain", target="example.com")

    assert scope.evaluate_hostname("api.example.com").allowed
    assert not scope.evaluate_hostname("example.com.attacker.test").allowed
    blocked = scope.evaluate_hostname("admin.example.com")
    assert not blocked.allowed
    assert blocked.reason == "matches excluded domain"


def test_url_paths_and_ports_are_enforced():
    scope = ScopeEvaluator(
        {
            "allowed_domains": ["example.com"],
            "excluded_url_paths": ["/logout", "/delete/*"],
            "allowed_ports": [80, 443],
        },
        target_type="domain",
        target="example.com",
    )

    assert scope.evaluate_url("https://app.example.com/").allowed
    assert not scope.evaluate_url("https://app.example.com/logout").allowed
    assert not scope.evaluate_url("https://app.example.com/delete/account").allowed
    assert not scope.evaluate_url("https://app.example.com:8443/").allowed


def test_cidr_scope_blocks_private_space_and_allows_derived_public_ips():
    scope = ScopeEvaluator(
        {"allowed_cidrs": ["8.8.8.0/24"]},
        target_type="ip",
        target="8.8.8.8",
    )

    assert scope.evaluate_ip("8.8.8.8").allowed
    assert not scope.evaluate_ip("1.1.1.1").allowed
    assert not scope.evaluate_ip("127.0.0.1", derived_from_allowed_host=True).allowed

    domain_scope = ScopeEvaluator(None, target_type="domain", target="example.com")
    assert domain_scope.evaluate_ip("1.1.1.1", derived_from_allowed_host=True).allowed


def test_manual_inclusion_is_exact_and_does_not_broaden_domain_scope():
    scope = ScopeEvaluator(
        {
            "allowed_domains": ["example.com"],
            "excluded_domains": ["admin.example.com"],
            "included_assets": ["SUBDOMAIN:admin.example.com"],
        },
        target_type="domain",
        target="example.com",
    )

    decision = scope.evaluate_asset("SUBDOMAIN", "admin.example.com")
    assert decision.allowed
    assert decision.reason == "manually included"
    assert not scope.evaluate_hostname("child.admin.example.com").allowed
