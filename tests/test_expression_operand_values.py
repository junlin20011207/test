"""GitHub && / || return operand values; they are not Boolean-only ops."""
import pytest
from benchmarks.guard_semantics import evaluate,parse


@pytest.mark.parametrize(("source","expect"),[
    ("'hit' && 'value'","value"),
    ("'' || 'fallback'","fallback"),
    ("'already' || 'fallback'","already"),
    ("false || 'lowercase'","lowercase"),
    ("true && 'kept'","kept"),
    ("false && 'unreachable'",False),
    ("startsWith(false || 'Dependabot/pkg','dependabot/')",True),
    ("startsWith('x' && 'Dependabot/pkg','dependabot/')",True),
])
def test_operand_preserving_logical_operators(source,expect):
    assert evaluate(parse(source),{})==expect
