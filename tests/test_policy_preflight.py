"""A policy preflight must never grant automatic production deployment."""
import pytest
from benchmarks.policy_preflight import assess


def test_isolated_clear_branch_only_permits_read_only_lab_preflight():
    result=assess("junlin20011207/test",
                  "research/ref-cas-remote-positive-20261011",
                  {"protected":False},[])
    assert result["status"]=="LAB_READ_ONLY_PRECHECK_PASSED"
    assert result["production_deployment_authorized"] is False


@pytest.mark.parametrize("branch",[
    "main","production","release/v2","research/other-study",
    "research/ref-cas-remote-../main",
    "research/ref-cas-remote-/../../main",
])
def test_non_lab_ref_rejected_even_if_unprotected(branch):
    result=assess("junlin20011207/test",branch,{"protected":False},[])
    assert result["status"]=="DEPLOYMENT_NOT_VERIFIED"
    assert not result["production_deployment_authorized"]


@pytest.mark.parametrize("branch_info,rulesets,error",[
    ({"protected":True},[],None),
    ({"protected":False},[{"name":"review-required"}],None),
    ({"protected":False},None,None),
    ({"protected":False},[], "403 rules invisible"),
    (None,[],None),
    ({},[],None),
])
def test_unknown_or_protected_policy_fails_closed(branch_info,rulesets,error):
    result=assess("junlin20011207/test",
                  "research/ref-cas-remote-strict-20261011",
                  branch_info,rulesets,error)
    assert result["status"]=="DEPLOYMENT_NOT_VERIFIED"
    assert not result["production_deployment_authorized"]



@pytest.mark.parametrize("foreign_repo",[
    "other-owner/test",
    "junlin20011207/another-repository",
])
def test_matching_lab_name_in_another_repo_never_authorized(foreign_repo):
    result=assess(foreign_repo,"research/ref-cas-remote-positive-20261011",
                  {"protected":False},[])
    assert result["status"]=="DEPLOYMENT_NOT_VERIFIED"
    assert result["production_deployment_authorized"] is False
