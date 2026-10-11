"""Fail-closed restricted GitHub Actions expression evaluator.

Not GitHub's complete expression language. Unsupported symbols or functions
remain unknown and are never accepted as authorization evidence.
"""
import re
import json
import math

TOKEN=re.compile(r"""\s*(?:(&&|\|\||==|!=|[(),!])|('(?:''|[^'])*'|"(?:\\.|[^"\\])*")|([a-zA-Z_][\w.]*))""")


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
            # GitHub Actions expressions require single-quoted string literals.
            # A double-quoted token is invalid in this context, even if it
            # would mean the same value in Python.
            if token[0] != "'":
                raise ValueError("GitHub expression string must use single quotes")
            if len(token)<2 or token[-1]!=token[0]:
                raise ValueError("invalid literal")
            return ("literal",token[1:-1].replace("''","'"))
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


def _numeric_for_loose_equality(value):
    """GitHub mixed Boolean/string equality: JSON numeric strings or NaN."""
    if isinstance(value,bool):
        return int(value)
    if isinstance(value,str):
        if not value:
            return 0
        try:
            parsed=json.loads(value)
        except (ValueError,TypeError):
            return math.nan
        if isinstance(parsed,(int,float)) and not isinstance(parsed,bool):
            return parsed
        return math.nan
    raise ValueError("unsupported loose comparison value type")


def _string_for_prefix(value):
    if isinstance(value,bool):
        return "true" if value else "false"
    if isinstance(value,str):
        return value
    raise ValueError("unmodeled startsWith coercion")


def _truthy(value):
    """Subset of GitHub truthiness: documented Boolean and string values."""
    if isinstance(value,bool):
        return value
    if isinstance(value,str):
        return len(value)>0
    raise ValueError("unmodeled expression value type")


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
        left=_string_for_prefix(left)
        right=_string_for_prefix(right)
        return left.casefold().startswith(right.casefold())
    if kind=="not":
        return not _truthy(evaluate(tree[1],values))
    if kind=="and":
        left=evaluate(tree[1],values)
        return evaluate(tree[2],values) if _truthy(left) else left
    if kind=="or":
        left=evaluate(tree[1],values)
        return left if _truthy(left) else evaluate(tree[2],values)
    if kind in ("==","!="):
        left=evaluate(tree[1],values)
        right=evaluate(tree[2],values)
        if isinstance(left,str) and isinstance(right,str):
            same=left.casefold()==right.casefold()
        elif isinstance(left,str)!=isinstance(right,str):
            same=_numeric_for_loose_equality(left)==_numeric_for_loose_equality(right)
        else:
            same=left==right
        return same if kind=="==" else not same
    raise ValueError("unknown operation "+kind)


def guard_samples(condition,accepted,denied):
    """Bounded counterexample tests; not logical implication over all inputs."""
    try:
        syntax=parse(condition)
        return bool(evaluate(syntax,accepted)) and all(
            not bool(evaluate(syntax,case)) for case in denied)
    except (ValueError,TypeError,IndexError,KeyError):
        return False



def _atomic_fact(node):
    """Return only direct, modeled authorization atoms (sufficient, not complete)."""
    kind=node[0]
    if kind=="==":
        a,b=node[1],node[2]
        if a[0]=="var" and b[0]=="literal":
            return ("eq",a[1],b[1].casefold() if isinstance(b[1],str) else b[1])
        if b[0]=="var" and a[0]=="literal":
            return ("eq",b[1],a[1].casefold() if isinstance(a[1],str) else a[1])
        if a[0]=="var" and b[0]=="var":
            return ("same",tuple(sorted((a[1],b[1]))))
    if kind=="startsWith":
        a,b=node[1],node[2]
        if a[0]=="var" and b[0]=="literal":
            return ("prefix",a[1],b[1].casefold() if isinstance(b[1],str) else b[1])
    return None


def guaranteed_atoms(tree):
    """Conservative conjunction facts true on EVERY satisfiable OR branch.

    None indicates a provably impossible Boolean branch; an empty set means
    the expression can be true without proving any modeled atomic facts.
    This is deliberately a sufficient-condition checker rather than a
    complete theorem prover of GitHub Actions expression semantics.
    """
    kind=tree[0]
    if kind=="bool":
        return set() if tree[1] else None
    if kind=="and":
        left,right=guaranteed_atoms(tree[1]),guaranteed_atoms(tree[2])
        return None if left is None or right is None else left|right
    if kind=="or":
        left,right=guaranteed_atoms(tree[1]),guaranteed_atoms(tree[2])
        if left is None:return right
        if right is None:return left
        return left&right
    atom=_atomic_fact(tree)
    return {atom} if atom is not None else set()


def require_on_every_branch(condition,required):
    """Prove specific authorization predicates appear in all viable branches.

    Unmodeled syntax and semantic equivalents are rejected rather than guessed.
    No claim of full symbolic execution, satisfiability or GitHub equivalence.
    """
    try:
        atoms=guaranteed_atoms(parse(condition))
        return atoms is not None and set(required).issubset(atoms)
    except (ValueError,TypeError,IndexError):
        return False
