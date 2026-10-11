"""Independent guard-logic oracle, bounded and mutation-based.

The 32-value truth table is an additional check. Safety acceptance is based
on structural MUST-atom evidence, not on this finite input sample alone.
"""
from itertools import product
import pytest
from benchmarks.guard_semantics import parse,evaluate,require_on_every_branch
from benchmarks.contract_semantics import consumer_auth_is_guarded,producer_actor_is_guarded,artifact_change_is_guarded
from test_repair_invariants import prepared


def good_guard():
    return prepared()[1]["jobs"]["commit"]["if"]


def context_case(repo,actor,branch,event,conclusion):
    return {
        "github.repository":"org/repo",
        "github.event.workflow_run.head_repository.full_name":repo,
        "github.event.workflow_run.actor.login":actor,
        "github.event.workflow_run.head_branch":branch,
        "github.event.workflow_run.event":event,
        "github.event.workflow_run.conclusion":conclusion,
    }


@pytest.mark.parametrize("switches",list(product((False,True),repeat=5)))
def test_32_event_context_cases(switches):
    repo,actor,branch,event,conclusion=switches
    context=context_case(
        "org/repo" if repo else "outsider/fork",
        "dependabot[bot]" if actor else "outsider",
        "dependabot/npm/pkg1" if branch else "special-branch",
        "pull_request" if event else "push",
        "success" if conclusion else "failure",
    )
    assert bool(evaluate(parse(good_guard()),context))==all(switches)


@pytest.mark.parametrize("wrapper",[
    "{}",
    "({})",
    "({}) && true",
    "false || ({})",
    "({}) || false",
    "(({})) && (true || false)",
])
def test_safe_equivalent_parenthesization_accepted(wrapper):
    assert consumer_auth_is_guarded(wrapper.format(good_guard()))


@pytest.mark.parametrize(("mutator","required"),[
    (lambda g:g+" || github.event.workflow_run.head_branch == 'emergency'",False),
    (lambda g:g+" || github.event.workflow_run.actor.login == 'unlisted'",False),
    (lambda g:g+" || github.event.workflow_run.head_repository.full_name == 'hidden/fork'",False),
    (lambda g:g+" || false",True),
    (lambda g:"false || ("+g+")",True),
    (lambda g:"true || ("+g+")",False),
    (lambda g:g+" && (true || false)",True),
])
def test_symbolic_all_or_branches(mutator,required):
    assert consumer_auth_is_guarded(mutator(good_guard())) is required


@pytest.mark.parametrize("invalid",[
    'github.actor == "dependabot[bot]"',
    "contains(github.actor, 'dependabot')",
    "github.actor =~ 'dependabot'",
    "github.actor == 'dependabot[bot]' ||",
    "github.actor == 'dependabot[bot]' # comment",
    "",
    "true",
])
def test_unknown_or_invalid_authorization_fails_closed(invalid):
    assert not producer_actor_is_guarded(invalid)


@pytest.mark.parametrize("expression,expected",[
    ("steps.diff.outputs.changed == 'true'",True),
    ("(steps.diff.outputs.changed == 'true') && true",True),
    ("steps.diff.outputs.changed == 'true' || false",True),
    ("steps.diff.outputs.changed == 'true' || steps.diff.outputs.changed == 'urgent'",False),
    ("steps.diff.outputs.changed == 'true' || true",False),
])
def test_upload_guard_compositional_semantics(expression,expected):
    assert artifact_change_is_guarded(expression) is expected
