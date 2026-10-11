"""GitHub mixed scalar comparison coercion and startsWith string casting."""
import pytest
from benchmarks.guard_semantics import evaluate,parse


@pytest.mark.parametrize("expression,expected",[
    ("'' == false",True),
    ("'0' == false",True),
    ("'1' == true",True),
    ("'hello' == true",False),
    ("'2' == true",False),
    ("'' != false",False),
    ("startsWith(true, 't')",True),
    ("startsWith(false, 'f')",True),
    ("startsWith(false, 't')",False),
])
def test_documented_github_coercion(expression,expected):
    assert evaluate(parse(expression),{}) is expected
