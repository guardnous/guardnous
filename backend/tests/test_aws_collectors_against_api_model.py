"""Every AWS collector, run against botocore's API definitions (see tests/aws_model.py).

This proves the calls exist, the arguments are valid and the response fields
the collectors read are real. It does not prove behaviour against a live
account (permissions, throttling, unusual resources).
"""
import asyncio
import logging

import pytest

pytest.importorskip("boto3")

from app.services.cloud_connectors import aws_extra  # noqa: E402
from app.services.cloud_connectors.aws_connector import AWSConnector  # noqa: E402
from tests.aws_model import AwsError, ModelSession  # noqa: E402

ACCOUNT = "111122223333"
REGION = "eu-west-1"


def _empty(value) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _assert_fully_read(resource, allow_empty: tuple[str, ...] = ()):
    """With every response field present, every config field must have a value."""
    assert "_unreadable" not in resource.config, (resource.resource_type, resource.config["_unreadable"])
    empty = [k for k, v in resource.config.items() if _empty(v) and k not in allow_empty]
    assert not empty, f"{resource.resource_type}: fields read nothing from the API response: {empty}"
    assert resource.resource_id and resource.resource_name and resource.account_id == ACCOUNT


def _customer_key(response, kwargs):
    response["KeyMetadata"].update(KeyManager="CUSTOMER", KeyState="Enabled", KeySpec="SYMMETRIC_DEFAULT")


def _application_lb(response, kwargs):
    for lb in response["LoadBalancers"]:
        lb.update(Type="application", Scheme="internet-facing",
                  LoadBalancerArn=f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/web/abc")


def _redirecting_listener(response, kwargs):
    for listener in response["Listeners"]:
        listener["Protocol"] = "HTTP"
        for action in listener["DefaultActions"]:
            action["RedirectConfig"]["Protocol"] = "HTTPS"


def _lb_attributes(response, kwargs):
    response["Attributes"] = [
        {"Key": "access_logs.s3.enabled", "Value": "true"}, {"Key": "deletion_protection.enabled", "Value": "true"},
        {"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "true"},
    ]


def _enabled_detector(response, kwargs):
    response["Status"] = "ENABLED"


def _active_flow_log(response, kwargs):
    for log in response["FlowLogs"]:
        log.update(FlowLogStatus="ACTIVE", ResourceId="sample")      # the generated VpcId is "sample"


def _eks(response, kwargs):
    for entry in response["cluster"]["logging"]["clusterLogging"]:
        entry.update(enabled=True, types=["audit"])
    for entry in response["cluster"]["encryptionConfig"]:
        entry["resources"] = ["secrets"]


def _cname_record(response, kwargs):
    for record in response["ResourceRecordSets"]:
        record["Type"] = "CNAME"


OVERRIDES = {
    ("kms", "describe_key"): _customer_key,
    ("elbv2", "describe_load_balancers"): _application_lb,
    ("elbv2", "describe_listeners"): _redirecting_listener,
    ("elbv2", "describe_load_balancer_attributes"): _lb_attributes,
    ("guardduty", "get_detector"): _enabled_detector,
    ("ec2", "describe_flow_logs"): _active_flow_log,
    ("eks", "describe_cluster"): _eks,
    ("route53", "list_resource_record_sets"): _cname_record,
}


@pytest.mark.parametrize("rtype", sorted(aws_extra.GLOBAL_COLLECTORS))
def test_global_collector_matches_the_aws_api(rtype):
    session = ModelSession(dict(OVERRIDES))
    found = aws_extra.GLOBAL_COLLECTORS[rtype](session, ACCOUNT)
    assert found and all(r.resource_type == rtype for r in found)
    for resource in found:
        _assert_fully_read(resource)


@pytest.mark.parametrize("rtype", sorted(aws_extra.REGIONAL_COLLECTORS))
def test_regional_collector_matches_the_aws_api(rtype):
    session = ModelSession(dict(OVERRIDES))
    found = aws_extra.REGIONAL_COLLECTORS[rtype](session, ACCOUNT, REGION)
    assert found and all(r.resource_type == rtype for r in found)
    for resource in found:
        _assert_fully_read(resource)
    assert all(kwargs is not None for _, _, kwargs in session.calls)


def test_values_from_the_api_reach_the_config():
    """Spot checks that fields mean what the rules assume."""
    session = ModelSession(dict(OVERRIDES))
    (lb,) = aws_extra.discover_load_balancers(session, ACCOUNT, REGION)
    assert lb.config["internet_facing"] is True and lb.config["waf_web_acl"] == "sample"
    assert lb.config["listeners"][0]["redirects_to_https"] is True
    assert lb.config["attributes"] == {"access_logs_enabled": True, "deletion_protection": True, "drop_invalid_headers": True}
    (vpc,) = aws_extra.discover_vpcs(session, ACCOUNT, REGION)
    assert vpc.config["flow_logs_enabled"] is True
    (settings,) = aws_extra.discover_region_settings(session, ACCOUNT, REGION)
    assert settings.config == {"region": REGION, "ebs_encryption_by_default": True, "guardduty_enabled": True,
                               "config_recorder_enabled": True}
    (cluster,) = aws_extra.discover_eks_clusters(session, ACCOUNT, REGION)
    assert cluster.config["enabled_log_types"] == ["audit"] and cluster.config["secrets_encrypted"] is True
    (zone,) = aws_extra.discover_route53_zones(session, ACCOUNT)
    assert zone.config["pointer_records"] == [{"name": "sample", "type": "CNAME", "target": "sample"}]
    (key,) = aws_extra.discover_kms_keys(session, ACCOUNT, REGION)
    assert key.config["rotation_enabled"] is True


def test_access_denied_is_recorded_as_unreadable_not_as_disabled():
    denied = AwsError("AccessDeniedException")
    session = ModelSession({
        **OVERRIDES, ("guardduty", "list_detectors"): denied, ("kms", "get_key_rotation_status"): denied,
        ("wafv2", "get_web_acl_for_resource"): denied, ("ec2", "describe_flow_logs"): denied,
    })
    (settings,) = aws_extra.discover_region_settings(session, ACCOUNT, REGION)
    assert "guardduty_enabled" not in settings.config and settings.config["_unreadable"] == ["guardduty_enabled"]
    (key,) = aws_extra.discover_kms_keys(session, ACCOUNT, REGION)
    assert "rotation_enabled" not in key.config and key.config["_unreadable"] == ["rotation_enabled"]
    (lb,) = aws_extra.discover_load_balancers(session, ACCOUNT, REGION)
    assert "waf_web_acl" not in lb.config and lb.config["_unreadable"] == ["waf_web_acl"]
    (vpc,) = aws_extra.discover_vpcs(session, ACCOUNT, REGION)
    assert "flow_logs_enabled" not in vpc.config and vpc.config["_unreadable"] == ["flow_logs_enabled"]


def test_the_whole_connector_runs_against_the_aws_api(monkeypatch, caplog):
    """Includes the eight original collectors, which had no test of this kind."""
    session = ModelSession(dict(OVERRIDES))
    connector = AWSConnector({}, regions=[REGION])
    monkeypatch.setattr(connector, "_get_session", lambda: session)
    monkeypatch.setattr(connector, "_get_account_id", lambda s: ACCOUNT)

    def _bucket_in_region(response, kwargs):
        response["LocationConstraint"] = REGION
    session.overrides[("s3", "get_bucket_location")] = _bucket_in_region

    with caplog.at_level(logging.WARNING):
        found = asyncio.run(connector.discover())

    problems = [r.getMessage() for r in caplog.records if "fail" in r.getMessage().lower() or "error" in r.getMessage().lower()]
    assert not problems, problems
    assert {r.resource_type for r in found} == set(AWSConnector.SUPPORTED_RESOURCE_TYPES)


def test_every_enabled_region_is_scanned_when_none_is_chosen(monkeypatch):
    from app.services.cloud_connectors.aws_connector import DEFAULT_AWS_REGIONS

    enabled = ["ap-south-1", "eu-north-1", "sa-east-1", "us-east-1", "us-west-2"]

    def _regions(response, kwargs):
        assert kwargs == {"AllRegions": False}                    # enabled regions only
        response["Regions"] = [{"RegionName": name} for name in reversed(enabled)]
    session = ModelSession({**OVERRIDES, ("ec2", "describe_regions"): _regions})
    connector = AWSConnector({})                                   # no regions chosen for the account
    monkeypatch.setattr(connector, "_get_session", lambda: session)
    monkeypatch.setattr(connector, "_get_account_id", lambda s: ACCOUNT)

    found = asyncio.run(connector.discover(resource_types=["aws_vpc", "aws_security_group"]))

    assert connector.scanned_regions == enabled
    asked = {region for service, region in session._clients if service == "ec2" and region}
    assert asked == set(enabled)                                   # each region was really read
    regions_in_order = [r.region for r in found if r.resource_type == "aws_vpc"]
    assert regions_in_order == sorted(regions_in_order)            # same order every sync, despite the threads

    # Not allowed to list regions: the default set, not a failure and not zero regions.
    denied = ModelSession({**OVERRIDES, ("ec2", "describe_regions"): AwsError("UnauthorizedOperation")})
    monkeypatch.setattr(connector, "_get_session", lambda: denied)
    asyncio.run(connector.discover(resource_types=["aws_vpc"]))
    assert connector.scanned_regions == DEFAULT_AWS_REGIONS

    # Regions chosen for the account are respected and regions are not listed at all.
    chosen = AWSConnector({}, regions=[REGION])
    only = ModelSession(dict(OVERRIDES))
    monkeypatch.setattr(chosen, "_get_session", lambda: only)
    monkeypatch.setattr(chosen, "_get_account_id", lambda s: ACCOUNT)
    asyncio.run(chosen.discover(resource_types=["aws_vpc"]))
    assert chosen.scanned_regions == [REGION] and not [c for c in only.calls if c[1] == "describe_regions"]


def test_one_account_is_synced_by_one_worker_at_a_time(monkeypatch):
    import sys
    import types

    from app.tasks import cloud_sync

    store: dict[str, bytes] = {}

    class FakeRedis:
        @classmethod
        def from_url(cls, *a, **kw):
            return cls()

        def set(self, key, value, nx=False, ex=None):
            if nx and key in store:
                return None
            store[key] = value.encode()
            return True

        def get(self, key):
            return store.get(key)

        def delete(self, key):
            store.pop(key, None)

    monkeypatch.setitem(sys.modules, "redis", types.SimpleNamespace(Redis=FakeRedis))

    first = cloud_sync._claim_sync(7)
    assert first is not None and cloud_sync._claim_sync(7) is None   # second request for the same account is refused
    assert cloud_sync._claim_sync(8) is not None                     # another account is not affected
    first()
    assert cloud_sync._claim_sync(7) is not None                     # free again once the sync has finished

    class Broken:
        @classmethod
        def from_url(cls, *a, **kw):
            raise ConnectionError("redis is down")
    monkeypatch.setitem(sys.modules, "redis", types.SimpleNamespace(Redis=Broken))
    assert cloud_sync._claim_sync(9) is not None                     # no lock service: sync still runs
