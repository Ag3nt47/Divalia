"""Fail-closed policy for small, side-effect-free Python telemetry detectors.

An accepted AST is eligibility for container testing, not a sandbox or a proof
that a detector is useful. Untrusted source must never execute in this process.
"""

from __future__ import annotations

import ast
import hashlib
import math
from dataclasses import asdict, dataclass

POLICY_VERSION = "divalia-python-detector-v1"
MAX_SOURCE_BYTES = 32_768
MAX_NODES = 2_000
MAX_DEPTH = 40
SAFE_BUILTINS = frozenset(
    {"len", "str", "int", "float", "bool", "abs", "min", "max", "round", "any", "all"}
)
SAFE_METHODS = frozenset(
    {
        "get",
        "keys",
        "values",
        "items",
        "lower",
        "upper",
        "casefold",
        "strip",
        "lstrip",
        "rstrip",
        "startswith",
        "endswith",
        "find",
        "count",
        "split",
        "rsplit",
        "replace",
        "isdigit",
        "isalpha",
        "isalnum",
        "isspace",
    }
)
_ANNOTATION_NAMES = frozenset(
    {"dict", "list", "tuple", "str", "int", "float", "bool", "Any", "None"}
)
_ALLOWED = (
    ast.Module,
    ast.FunctionDef,
    ast.arguments,
    ast.arg,
    ast.Return,
    ast.Assign,
    ast.AnnAssign,
    ast.If,
    ast.Expr,
    ast.Pass,
    ast.Name,
    ast.Load,
    ast.Store,
    ast.Constant,
    ast.Dict,
    ast.List,
    ast.Tuple,
    ast.Set,
    ast.Subscript,
    ast.Slice,
    ast.Call,
    ast.Attribute,
    ast.keyword,
    ast.Compare,
    ast.BoolOp,
    ast.UnaryOp,
    ast.BinOp,
    ast.IfExp,
    ast.And,
    ast.Or,
    ast.Not,
    ast.USub,
    ast.UAdd,
    ast.Add,
    ast.Sub,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.Is,
    ast.IsNot,
    ast.In,
    ast.NotIn,
)


@dataclass(frozen=True)
class AuditResult:
    passed: bool
    score: int
    issues: list[str]
    source_sha256: str
    language: str = "python"
    policy_version: str = POLICY_VERSION

    def to_dict(self) -> dict:
        return asdict(self)


def _private(name: str) -> bool:
    return name.startswith("_") or "__" in name


class _Policy(ast.NodeVisitor):
    def __init__(self, tree: ast.Module) -> None:
        self.issues: list[str] = []
        self.locals = {"event"}
        self.parents: list[ast.AST] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.locals.add(target.id)

    def reject(self, node: ast.AST, message: str) -> None:
        issue = f"line {getattr(node, 'lineno', 1)}: {message}"
        if issue not in self.issues and len(self.issues) < 40:
            self.issues.append(issue)

    def visit(self, node: ast.AST) -> None:
        if not isinstance(node, _ALLOWED):
            self.reject(node, f"{type(node).__name__} is outside the detector allowlist")
            return
        parent = self.parents[-1] if self.parents else None
        if isinstance(node, ast.Attribute):
            if not isinstance(parent, ast.Call) or parent.func is not node:
                self.reject(node, "method references and attribute reads are forbidden")
            if node.attr not in SAFE_METHODS or _private(node.attr):
                self.reject(node, f"method {node.attr!r} is forbidden")
        self.parents.append(node)
        super().visit(node)
        self.parents.pop()

    def visit_Module(self, node: ast.Module) -> None:
        body = list(node.body)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body.pop(0)
        if len(body) != 1 or not isinstance(body[0], ast.FunctionDef) or body[0].name != "detect":
            self.reject(node, "module must contain exactly one detect(event) function")
        for item in body:
            self.visit(item)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if len(self.parents) != 2 or node.name != "detect":
            self.reject(node, "nested functions and additional functions are forbidden")
        args = node.args
        if (
            args.posonlyargs
            or len(args.args) != 1
            or args.args[0].arg != "event"
            or args.vararg
            or args.kwarg
            or args.kwonlyargs
            or args.defaults
            or args.kw_defaults
        ):
            self.reject(
                node, "signature must be detect(event), without defaults or extra arguments"
            )
        if node.decorator_list or getattr(node, "type_params", []):
            self.reject(node, "decorators and type parameters are forbidden")
        if len(node.body) > 256:
            self.reject(node, "too many detector statements")
        for arg in args.args:
            self._annotation(arg.annotation)
        self._annotation(node.returns)
        for statement in node.body:
            self.visit(statement)

    def _annotation(self, node: ast.AST | None) -> None:
        if node is None:
            return
        # The container compiles with future annotations, so these never execute.
        for item in ast.walk(node):
            if isinstance(item, ast.Name) and item.id in _ANNOTATION_NAMES:
                continue
            if isinstance(item, (ast.Load, ast.Subscript, ast.Tuple, ast.BinOp, ast.BitOr)):
                continue
            if isinstance(item, ast.Constant) and (
                item.value is None or isinstance(item.value, str)
            ):
                continue
            self.reject(item, "only inert primitive type annotations are allowed")

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            self.reject(node, "assignments may bind one local name; mutation is forbidden")
        for target in node.targets:
            self.visit(target)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if not isinstance(node.target, ast.Name):
            self.reject(node, "annotated assignment may bind only a local name")
        self.visit(node.target)
        self._annotation(node.annotation)
        if node.value is not None:
            self.visit(node.value)

    def visit_Name(self, node: ast.Name) -> None:
        if _private(node.id):
            self.reject(node, "private names and reflection are forbidden")
        if isinstance(node.ctx, ast.Store) and (
            node.id in SAFE_BUILTINS or node.id in {"detect", "event"}
        ):
            self.reject(node, "detector input and builtins cannot be rebound")
        if isinstance(node.ctx, ast.Load) and node.id not in self.locals | SAFE_BUILTINS:
            self.reject(node, f"unknown name {node.id!r}")

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            if node.func.id not in SAFE_BUILTINS:
                self.reject(node, f"call to {node.func.id!r} is forbidden")
        elif not isinstance(node.func, ast.Attribute):
            self.reject(node, "indirect calls are forbidden")
        if len(node.args) > 8 or len(node.keywords) > 4:
            self.reject(node, "too many call arguments")
        if any(keyword.arg is None for keyword in node.keywords):
            self.reject(node, "keyword unpacking is forbidden")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if value is None or isinstance(value, bool):
            return
        if isinstance(value, str) and len(value) <= 4_096:
            return
        if isinstance(value, (int, float)) and math.isfinite(value) and abs(value) <= 10**12:
            return
        self.reject(node, "literal type or size exceeds the detector policy")

    def visit_Dict(self, node: ast.Dict) -> None:
        if len(node.keys) > 128 or any(key is None for key in node.keys):
            self.reject(node, "large dictionaries and dictionary unpacking are forbidden")
        self.generic_visit(node)

    def visit_List(self, node: ast.List) -> None:
        if len(node.elts) > 128:
            self.reject(node, "container literal is too large")
        self.generic_visit(node)

    visit_Tuple = visit_List
    visit_Set = visit_List

    def visit_Expr(self, node: ast.Expr) -> None:
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            self.reject(node, "only docstrings may be standalone expressions")
        self.generic_visit(node)


def validate_source(source: str, language: str = "python") -> AuditResult:
    """Audit the allowlisted detector language without executing source.

    Go/native code is deliberately unsupported until a separate compiler and
    native-code isolation policy exists. A Python policy cannot audit Go.
    """
    if not isinstance(source, str):
        return AuditResult(False, 0, ["source must be a UTF-8 string"], "", str(language))
    try:
        encoded = source.encode("utf-8")
    except UnicodeEncodeError:
        return AuditResult(False, 0, ["source is not valid UTF-8"], "", str(language))
    digest = hashlib.sha256(encoded).hexdigest()
    if language.lower() not in {"python", "py"}:
        return AuditResult(
            False,
            0,
            ["unsupported language: Go/native sandbox and compiler validation are not implemented"],
            digest,
            language,
        )
    issues: list[str] = []
    if not encoded or len(encoded) > MAX_SOURCE_BYTES:
        issues.append(f"source must be between 1 and {MAX_SOURCE_BYTES} UTF-8 bytes")
    else:
        try:
            tree = ast.parse(source, mode="exec")
            stack: list[tuple[ast.AST, int]] = [(tree, 0)]
            count = 0
            while stack:
                node, depth = stack.pop()
                count += 1
                if count > MAX_NODES or depth > MAX_DEPTH:
                    issues.append("AST exceeds node count or nesting limit")
                    break
                stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
            if not issues:
                policy = _Policy(tree)
                policy.visit(tree)
                issues.extend(policy.issues)
        except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError) as exc:
            issues.append(f"invalid Python source: {type(exc).__name__}")
    return AuditResult(not issues, 100 if not issues else 0, issues, digest)
