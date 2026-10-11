"""Differential specification tests against documented GitHub expression rules.

GitHub compares strings without case sensitivity, also for startsWith and !=.
A single quote within single-quoted string is escaped as two adjacent quotes.
"""
import pytest
from benchmarks.guard_semantics import evaluate,parse


@pytest.mark.parametrize(("expression","expected"),[
    ("'Main' == 'main'", True),
    ("'MAIN' != 'main'", False),
    ("'DePeNdAbOt/patch' == 'dependabot/patch'", True),
    ("startsWith('Dependabot/npm/pkg', 'dependabot/')",True),
    ("startsWith('RELEASE/main', 'dependabot/')",False),
    ("'It''s safe' == 'it''s safe'",True),
    ("'Alice' != 'bob'",True),
    ("startsWith('HELLO world','hello') && 'PR' == 'pr'",True),
    ("'main' == 'MAIN' && !startsWith('RELEASE','dependabot/')",True),
])
def test_documented_casefold_and_escaped_quotes(expression,expected):
    assert bool(evaluate(parse(expression),{})) is expected
