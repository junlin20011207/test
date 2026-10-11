"""Fail-closed restricted GitHub Actions expression evaluator.

Not GitHub's complete expression language. Unsupported symbols or functions
remain unknown and are never accepted as authorization evidence.
"""
import re

TOKEN=re.compile(r"""\s*(?:(&&|\|\||==|!=|[(),!])|('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")|([a-zA-Z_][\w.]*))""")


def tokenize(source):
    value=str(source or "").strip()
    if value.startswith(chr(36)+"{{") and value.endswith("}}"):
        value=value[3:-2].strip()
    if not value:
        raise ValueError("empty expression")
    tokens=[]
    at=0
    while at<len(value):
        m=TOKEN.match(value,at)
        if not m:
            if not value[at:].strip():
                break
            raise ValueError("unsupported expression at "+repr(value[at:at+25]))
        tokens.append(m.group(1) or m.group(2) or m.group(3))
        at=m.end()
    return tokens


def parse(source):
    stream=tokenize(source)
    at=0
    def peek():
        return stream[at] if at<len(stream) else None
    def take(token=None):
        nonlocal at
        result=peek()
        if result is None or (token is not None and token!=result):
            raise ValueError("unexpected token "+repr(result)+", wanted "+repr(token))
        at+=1
        return result
    def primary():
        token=peek()
        if token=="(":
            take("(")
            value=disjunction()
            take(")")
            return value
        if token in ("true","false"):
            take()
            return ("bool",token=="true")
        if token and token[0] in ("'",'"'):
            take()
            if len(token)<2 or token[-1]!=token[0]:
                raise ValueError("invalid literal")
            return ("literal",token[1:-1])
        if token and re.fullmatch(r"[a-zA-Z_][\w.]*",token):
            take()
            if peek()=="(":
                if token!="startsWith":
                    raise ValueError("unmodeled function "+token)
                take("(")
                first=disjunction()
                take(",")
                second=disjunction()
                take(")")
                return ("startsWith",first,second)
            return ("var",token)
        raise ValueError("invalid primary "+repr(token))
    def unary():
        if peek()=="!":
            take("!")
            return ("not",unary())
        return primary()
    def comparison():
        node=unary()
        if peek() in ("==","!="):
            op=take()
            node=(op,node,unary())
        return node
    def conjunction():
        node=comparison()
        while peek()=="&&":
            take("&&")
            node=("and",node,comparison())
        return node
    def disjunction():
        node=conjunction()
        while peek()=="||":
            take("||")
            node=("or",node,conjunction())
        return node
    result=disjunction()
    if at<len(stream):
        raise ValueError("trailing tokens "+repr(stream[at:]))
    return result


def evaluate(tree,values):
    kind=tree[0]
    if kind in ("bool","literal"):
        return tree[1]
    if kind=="var":
        if tree[1] not in values:
            raise ValueError("unknown reference "+tree[1])
        return values[tree[1]]
    if kind=="startsWith":
        left=evaluate(tree[1],values)
        right=evaluate(tree[2],values)
        if not isinstance(left,str) or not isinstance(right,str):
            raise ValueError("startsWith expects strings")
        return left.startswith(right)
    if kind=="not":
        return not bool(evaluate(tree[1],values))
    if kind=="and":
        return bool(evaluate(tree[1],values)) and bool(evaluate(tree[2],values))
    if kind=="or":
        return bool(evaluate(tree[1],values)) or bool(evaluate(tree[2],values))
    if kind in ("==","!="):
        left=evaluate(tree[1],values)
        right=evaluate(tree[2],values)
        return (left==right) if kind=="==" else (left!=right)
    raise ValueError("unknown operation "+kind)


def guard_samples(condition,accepted,denied):
    """Bounded counterexample tests; not logical implication over all inputs."""
    try:
        syntax=parse(condition)
        return bool(evaluate(syntax,accepted)) and all(
            not bool(evaluate(syntax,case)) for case in denied)
    except (ValueError,TypeError,IndexError,KeyError):
        return False
