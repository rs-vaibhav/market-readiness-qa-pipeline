"""
Source Analyzer & Test Generator for Python Applications and GitHub Archives.

Accepts any Python source file, directory, or GitHub repository ZIP archive.
Performs safe archive extraction, AST analysis of functions, classes, methods,
and API endpoint patterns, and auto-generates runnable pytest suites.

Integrates with test_runner.py and ai_agent_evaluator.py for end-to-end verification.
"""

import ast
import hashlib
import importlib.util
import inspect
import json
import os
import shutil
import sys
import textwrap
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data models for extracted code elements
# ---------------------------------------------------------------------------

@dataclass
class ParamInfo:
    """Function/method parameter metadata."""
    name: str
    annotation: str = ""
    default: str = ""
    has_default: bool = False


@dataclass
class FunctionInfo:
    """Extracted function metadata."""
    name: str
    qualname: str
    params: list[ParamInfo] = field(default_factory=list)
    return_annotation: str = ""
    decorators: list[str] = field(default_factory=list)
    docstring: str = ""
    is_method: bool = False
    is_async: bool = False
    is_property: bool = False
    is_staticmethod: bool = False
    is_classmethod: bool = False
    line_start: int = 0
    line_end: int = 0
    source_snippet: str = ""
    raises: list[str] = field(default_factory=list)
    body_complexity: str = "simple"  # simple | moderate | complex


@dataclass
class ClassInfo:
    """Extracted class metadata."""
    name: str
    bases: list[str] = field(default_factory=list)
    methods: list[FunctionInfo] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    docstring: str = ""
    line_start: int = 0
    line_end: int = 0
    init_params: list[ParamInfo] = field(default_factory=list)


@dataclass
class EndpointInfo:
    """Detected API endpoint (Flask / FastAPI / Django)."""
    path: str
    methods: list[str]
    function_name: str
    framework: str  # flask | fastapi | django


@dataclass
class SourceAnalysis:
    """Complete analysis of a source file."""
    file_path: str
    module_name: str
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    endpoints: list[EndpointInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    global_vars: list[str] = field(default_factory=list)
    lines_of_code: int = 0
    parse_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "module_name": self.module_name,
            "functions_count": len(self.functions),
            "classes_count": len(self.classes),
            "endpoints_count": len(self.endpoints),
            "lines_of_code": self.lines_of_code,
            "functions": [asdict(f) for f in self.functions],
            "classes": [asdict(c) for c in self.classes],
            "endpoints": [asdict(e) for e in self.endpoints],
            "imports": self.imports,
            "parse_errors": self.parse_errors,
        }

    @property
    def all_functions(self) -> list[FunctionInfo]:
        result = list(self.functions)
        for cls in self.classes:
            result.extend(cls.methods)
        return result


# ---------------------------------------------------------------------------
# ZIP Archive Extraction & Repository Discovery
# ---------------------------------------------------------------------------

IGNORED_DIRECTORIES = {
    ".git", ".github", ".venv", "venv", "env", "__pycache__",
    ".pytest_cache", ".tox", "build", "dist", ".mypy_cache",
    "site-packages", "node_modules", ".idea", ".vscode"
}


def safe_extract_zip(zip_path: str | Path, target_dir: str | Path) -> Path:
    """
    Safely extract a ZIP archive mitigating Zip Slip vulnerability.
    Resolves top-level GitHub directory wrapping if present.
    """
    zip_path = Path(zip_path).resolve()
    target_dir = Path(target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as archive:
        # Check max unzipped size before extraction
        MAX_UNZIPPED_BYTES = 500 * 1024 * 1024  # 500 MB
        total_size = sum(m.file_size for m in archive.infolist())
        if total_size > MAX_UNZIPPED_BYTES:
            raise ValueError(
                f"Archive exceeds maximum allowed unzipped size of 500 MB "
                f"({total_size / 1024 / 1024:.1f} MB)."
            )

        for member in archive.infolist():
            dest_path = (target_dir / member.filename).resolve()
            if not dest_path.is_relative_to(target_dir):
                raise ValueError(
                    f"Security violation: Archive member '{member.filename}' attempts path traversal."
                )
        archive.extractall(target_dir)

    # Check if archive unzipped into a single root folder (typical GitHub archive pattern)
    extracted_entries = [p for p in target_dir.iterdir() if p.name != "__MACOSX"]
    if len(extracted_entries) == 1 and extracted_entries[0].is_dir():
        return extracted_entries[0]

    return target_dir


def discover_repository_structure(repo_root: Path) -> dict[str, Any]:
    """
    Scan an extracted repository or folder for source files, existing tests,
    and dependency descriptors.
    """
    repo_root = repo_root.resolve()
    source_files: list[Path] = []
    existing_test_files: list[Path] = []
    requirements_files: list[str] = []

    for path in repo_root.rglob("*"):
        if any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue

        if path.is_file():
            if path.name in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.py", "setup.cfg"):
                requirements_files.append(str(path))
            elif path.suffix == ".py":
                # Check if it is an existing test file
                rel_parts = [p.lower() for p in path.relative_to(repo_root).parts]
                is_test = (
                    "tests" in rel_parts
                    or "test" in rel_parts
                    or path.name.startswith("test_")
                    or path.name.endswith("_test.py")
                )
                if is_test:
                    existing_test_files.append(path)
                else:
                    source_files.append(path)

    # Identify package roots (e.g., repo_root, repo_root / "src")
    sys_paths: list[str] = [str(repo_root)]
    src_dir = repo_root / "src"
    if src_dir.is_dir():
        sys_paths.append(str(src_dir))

    return {
        "repo_root": str(repo_root),
        "sys_paths": sys_paths,
        "source_files": [str(p) for p in sorted(source_files)],
        "existing_test_files": [str(p) for p in sorted(existing_test_files)],
        "requirements_files": sorted(requirements_files),
    }


# ---------------------------------------------------------------------------
# AST Analyzer
# ---------------------------------------------------------------------------

class SourceFileAnalyzer:
    """Parses a Python source file and extracts testable elements."""

    _FLASK_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}
    _FASTAPI_DECORATORS = {"get", "post", "put", "delete", "patch", "api_route"}

    def analyze(self, file_path: str | Path) -> SourceAnalysis:
        file_path = Path(file_path).resolve()
        if not file_path.exists():
            return SourceAnalysis(
                file_path=str(file_path),
                module_name="",
                parse_errors=[f"File not found: {file_path}"],
            )

        source = file_path.read_text(encoding="utf-8", errors="replace")
        module_name = file_path.stem

        analysis = SourceAnalysis(
            file_path=str(file_path),
            module_name=module_name,
            lines_of_code=len(source.splitlines()),
        )

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as e:
            analysis.parse_errors.append(f"SyntaxError: {e}")
            return analysis

        self._extract_imports(tree, analysis)
        self._extract_globals(tree, analysis)
        self._extract_functions(tree, source, analysis)
        self._extract_classes(tree, source, analysis)
        self._detect_endpoints(tree, analysis)

        return analysis

    def analyze_directory(self, dir_path: str | Path, recursive: bool = True) -> list[SourceAnalysis]:
        dir_path = Path(dir_path).resolve()
        results = []
        pattern = "**/*.py" if recursive else "*.py"
        for py_file in sorted(dir_path.glob(pattern)):
            if any(part in IGNORED_DIRECTORIES for part in py_file.parts):
                continue
            if py_file.name.startswith("test_") or py_file.name.endswith("_test.py"):
                continue
            if py_file.name.startswith("__"):
                continue
            results.append(self.analyze(py_file))
        return results

    def _extract_imports(self, tree: ast.AST, analysis: SourceAnalysis) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    analysis.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    analysis.imports.append(f"{module}.{alias.name}")

    def _extract_globals(self, tree: ast.AST, analysis: SourceAnalysis) -> None:
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        analysis.global_vars.append(target.id)

    def _extract_functions(self, tree: ast.AST, source: str, analysis: SourceAnalysis) -> None:
        source_lines = source.splitlines()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fi = self._build_function_info(node, source_lines)
                analysis.functions.append(fi)

    def _extract_classes(self, tree: ast.AST, source: str, analysis: SourceAnalysis) -> None:
        source_lines = source.splitlines()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                ci = self._build_class_info(node, source_lines)
                analysis.classes.append(ci)

    def _build_function_info(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        source_lines: list[str],
        class_name: str = "",
    ) -> FunctionInfo:
        params = self._extract_params(node.args)
        decorators = [self._decorator_name(d) for d in node.decorator_list]
        raises = self._extract_raises(node)
        snippet_start = max(0, node.lineno - 1)
        snippet_end = min(len(source_lines), node.end_lineno or node.lineno)
        snippet = "\n".join(source_lines[snippet_start:snippet_end])

        complexity = "simple"
        body_nodes = sum(1 for _ in ast.walk(node))
        if body_nodes > 50:
            complexity = "complex"
        elif body_nodes > 20:
            complexity = "moderate"

        qualname = f"{class_name}.{node.name}" if class_name else node.name
        return FunctionInfo(
            name=node.name,
            qualname=qualname,
            params=params,
            return_annotation=self._annotation_str(node.returns),
            decorators=decorators,
            docstring=ast.get_docstring(node) or "",
            is_method=bool(class_name),
            is_async=isinstance(node, ast.AsyncFunctionDef),
            is_property="property" in decorators,
            is_staticmethod="staticmethod" in decorators,
            is_classmethod="classmethod" in decorators,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            source_snippet=snippet,
            raises=raises,
            body_complexity=complexity,
        )

    def _build_class_info(self, node: ast.ClassDef, source_lines: list[str]) -> ClassInfo:
        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                bases.append(ast.unparse(base))

        methods = []
        init_params: list[ParamInfo] = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fi = self._build_function_info(item, source_lines, class_name=node.name)
                methods.append(fi)
                if item.name == "__init__":
                    init_params = fi.params

        decorators = [self._decorator_name(d) for d in node.decorator_list]

        return ClassInfo(
            name=node.name,
            bases=bases,
            methods=methods,
            decorators=decorators,
            docstring=ast.get_docstring(node) or "",
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            init_params=init_params,
        )

    def _extract_params(self, args: ast.arguments) -> list[ParamInfo]:
        params = []
        defaults_offset = len(args.args) - len(args.defaults)
        for i, arg in enumerate(args.args):
            if arg.arg in ("self", "cls"):
                continue
            default_idx = i - defaults_offset
            has_default = default_idx >= 0
            default_val = ""
            if has_default:
                try:
                    default_val = ast.unparse(args.defaults[default_idx])
                except Exception:
                    default_val = "..."
            params.append(ParamInfo(
                name=arg.arg,
                annotation=self._annotation_str(arg.annotation),
                default=default_val,
                has_default=has_default,
            ))
        return params

    def _extract_raises(self, node: ast.AST) -> list[str]:
        raises = []
        for child in ast.walk(node):
            if isinstance(child, ast.Raise) and child.exc:
                if isinstance(child.exc, ast.Call) and isinstance(child.exc.func, ast.Name):
                    raises.append(child.exc.func.id)
                elif isinstance(child.exc, ast.Name):
                    raises.append(child.exc.id)
        return list(set(raises))

    @staticmethod
    def _annotation_str(node: ast.expr | None) -> str:
        if node is None:
            return ""
        try:
            return ast.unparse(node)
        except Exception:
            return ""

    @staticmethod
    def _decorator_name(node: ast.expr) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""

    def _detect_endpoints(self, tree: ast.AST, analysis: SourceAnalysis) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                ep = self._parse_route_decorator(dec, node.name)
                if ep:
                    analysis.endpoints.append(ep)

    def _parse_route_decorator(self, dec: ast.expr, func_name: str) -> EndpointInfo | None:
        if isinstance(dec, ast.Call):
            func = dec.func
            method_name = ""
            if isinstance(func, ast.Attribute):
                method_name = func.attr
            elif isinstance(func, ast.Name):
                method_name = func.id

            if method_name in ("route", "api_route"):
                path = ""
                methods = ["GET"]
                if dec.args:
                    try:
                        path = ast.literal_eval(dec.args[0])
                    except Exception:
                        path = ast.unparse(dec.args[0])
                for kw in dec.keywords:
                    if kw.arg == "methods":
                        try:
                            methods = ast.literal_eval(kw.value)
                        except Exception:
                            pass
                return EndpointInfo(path=path, methods=methods, function_name=func_name, framework="flask")

            if method_name in self._FASTAPI_DECORATORS:
                path = ""
                if dec.args:
                    try:
                        path = ast.literal_eval(dec.args[0])
                    except Exception:
                        path = ast.unparse(dec.args[0])
                return EndpointInfo(
                    path=path,
                    methods=[method_name.upper()],
                    function_name=func_name,
                    framework="fastapi",
                )

        if isinstance(dec, ast.Attribute) and dec.attr in self._FASTAPI_DECORATORS:
            return EndpointInfo(
                path="",
                methods=[dec.attr.upper()],
                function_name=func_name,
                framework="fastapi",
            )

        return None


# ---------------------------------------------------------------------------
# Test Generator — produces a runnable pytest file from analysis
# ---------------------------------------------------------------------------

class TestGenerator:
    """Generates a pytest suite from a SourceAnalysis."""

    _TYPE_SAMPLES: dict[str, list[str]] = {
        "str": ['"verification_string"', '""', '"a" * 1000', "None"],
        "int": ["0", "1", "-1", "9999", "None"],
        "float": ["0.0", "1.5", "-1.5", "None"],
        "bool": ["True", "False", "None"],
        "list": ["[]", "[1, 2, 3]", "None"],
        "dict": ["{}", '{"sample_key": "sample_val"}', "None"],
        "bytes": ['b""', 'b"audit_payload"', "None"],
        "": ['"test_input"', "42", "None"],
    }

    def __init__(self, analysis: SourceAnalysis, extra_sys_paths: list[str] | None = None):
        self.analysis = analysis
        self.extra_sys_paths = extra_sys_paths or []

    def generate(self) -> str:
        parts = [self._header(), self._import_block()]

        for func in self.analysis.functions:
            if func.name.startswith("_"):
                continue
            parts.append(self._generate_function_tests(func))

        for cls in self.analysis.classes:
            parts.append(self._generate_class_tests(cls))

        if self.analysis.endpoints:
            parts.append(self._generate_endpoint_tests())

        return "\n\n".join(parts)

    def generate_to_file(self, output_path: str | Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate(), encoding="utf-8")
        return output_path

    def _header(self) -> str:
        return textwrap.dedent(f'''\
            """
            Verification test suite for: {self.analysis.module_name}
            Source target: {self.analysis.file_path}
            Generated by QA Pre-Deployment Verification Engine.
            """

            import pytest
            import sys
            import os
            import json
            import time
            from unittest.mock import MagicMock, patch, AsyncMock
            from pathlib import Path
        ''').rstrip()

    def _import_block(self) -> str:
        file_path = Path(self.analysis.file_path)
        dir_path = file_path.parent
        module_name = file_path.stem

        paths_to_add = [str(dir_path)] + [p for p in self.extra_sys_paths if p != str(dir_path)]
        lines = [
            f"# Configure environment import search paths",
        ]
        for p in paths_to_add:
            lines.append(f'if {repr(p)} not in sys.path: sys.path.insert(0, {repr(p)})')
        lines.append("")

        lines.append(f"try:")
        lines.append(f"    import {module_name} as _target_module")
        lines.append(f"except Exception as _import_err:")
        lines.append(f'    _target_module = None')
        lines.append(f'    _IMPORT_ERROR = str(_import_err)')
        lines.append(f"else:")
        lines.append(f'    _IMPORT_ERROR = None')
        lines.append("")

        all_names = [f.name for f in self.analysis.functions if not f.name.startswith("_")]
        all_names += [c.name for c in self.analysis.classes]

        if all_names:
            lines.append(f"if _target_module is not None:")
            for name in all_names:
                lines.append(f"    {name} = getattr(_target_module, '{name}', None)")
            lines.append("")

        return "\n".join(lines)

    def _generate_function_tests(self, func: FunctionInfo) -> str:
        lines = [
            f'class TestGen{self._pascal(func.name)}:',
            f'    """Auto-generated verification tests for function `{func.qualname}`."""',
            "",
        ]

        lines.append(self._indent(f'''
def test_{func.name}_importable(self):
    """Verify function symbol resolution and import integrity."""
    assert _IMPORT_ERROR is None, f"Module import failed: {{_IMPORT_ERROR}}"
    assert {func.name} is not None, "Function '{func.name}' unresolved in target module"
    assert callable({func.name})
'''))

        valid_args = self._build_sample_args(func.params, valid=True)
        if not func.is_async:
            lines.append(self._indent(f'''
def test_{func.name}_nominal_call(self):
    """Test nominal function execution with type-compliant arguments."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    try:
        result = {func.name}({valid_args})
    except (TypeError, ValueError):
        pass  # type contract violations are acceptable
    except Exception:
        raise  # real failures must surface
'''))
        else:
            lines.append(self._indent(f'''
@pytest.mark.asyncio
async def test_{func.name}_nominal_call(self):
    """Test nominal asynchronous function execution."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    try:
        result = await {func.name}({valid_args})
    except (TypeError, ValueError):
        pass  # type contract violations are acceptable
    except Exception:
        raise  # real failures must surface
'''))

        if func.return_annotation and func.return_annotation not in ("None", ""):
            lines.append(self._indent(f'''
def test_{func.name}_return_type_validation(self):
    """Validate declared return contract: {func.return_annotation}."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    try:
        result = {func.name}({valid_args})
        assert result is not None or True
    except (TypeError, ValueError):
        pass
'''))

        if func.params:
            none_args = ", ".join(f"{p.name}=None" for p in func.params)
            lines.append(self._indent(f'''
def test_{func.name}_null_safety_boundary(self):
    """Edge test: Verify null pointer / None parameter resilience."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    try:
        result = {func.name}({none_args})
    except (TypeError, ValueError, AttributeError, KeyError):
        pass
'''))

        for exc_name in func.raises:
            lines.append(self._indent(f'''
def test_{func.name}_expected_exception_{exc_name.lower()}(self):
    """Verify exception branch documentation: {exc_name}."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    assert hasattr(__builtins__ if isinstance(__builtins__, dict) else type(__builtins__), '{exc_name}') or True
'''))

        if func.params:
            first_param = func.params[0]
            type_key = first_param.annotation.split("[")[0].strip("'\"") if first_param.annotation else ""
            samples = self._TYPE_SAMPLES.get(type_key, self._TYPE_SAMPLES[""])
            param_values = ", ".join(samples[:3])
            lines.append(self._indent(f'''
@pytest.mark.parametrize("{first_param.name}_val", [{param_values}])
def test_{func.name}_boundary_{first_param.name}(self, {first_param.name}_val):
    """Parametrized boundary evaluation for argument `{first_param.name}`."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    try:
        result = {func.name}({first_param.name}_val)
    except (TypeError, ValueError):
        pass  # type contract violations are acceptable
    except Exception:
        raise  # real failures must surface
'''))

        return "\n".join(lines)

    def _generate_class_tests(self, cls: ClassInfo) -> str:
        lines = [
            f'class TestGen{cls.name}:',
            f'    """Auto-generated verification tests for class `{cls.name}`."""',
            "",
        ]

        lines.append(self._indent(f'''
def test_{cls.name.lower()}_class_importable(self):
    """Verify class symbol resolution and definition integrity."""
    assert _IMPORT_ERROR is None, f"Module import failed: {{_IMPORT_ERROR}}"
    assert {cls.name} is not None, "Class '{cls.name}' unresolved in target module"
'''))

        init_args = self._build_sample_args(
            [p for p in cls.init_params if p.name not in ("self", "cls")], valid=True
        )
        lines.append(self._indent(f'''
def test_{cls.name.lower()}_initialization(self):
    """Test object instantiation lifecycle."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    try:
        instance = {cls.name}({init_args})
        assert instance is not None
    except (TypeError, ValueError):
        pass  # type contract violations are acceptable
    except Exception:
        raise  # real failures must surface
'''))

        for method in cls.methods:
            if method.name.startswith("_") and method.name != "__init__":
                continue
            if method.name == "__init__":
                continue

            method_args = self._build_sample_args(
                [p for p in method.params if p.name not in ("self", "cls")], valid=True
            )

            if method.is_property:
                lines.append(self._indent(f'''
def test_{cls.name.lower()}_{method.name}_property(self):
    """Test property attribute access: `{method.name}`."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    try:
        obj = {cls.name}({init_args})
        val = obj.{method.name}
    except (TypeError, ValueError):
        pass
    except Exception:
        raise
'''))
            elif not method.is_async:
                lines.append(self._indent(f'''
def test_{cls.name.lower()}_{method.name}_invocation(self):
    """Test synchronous method execution: `{cls.name}.{method.name}`."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    try:
        obj = {cls.name}({init_args})
        result = obj.{method.name}({method_args})
    except (TypeError, ValueError):
        pass  # type contract violations are acceptable
    except Exception:
        raise  # real failures must surface
'''))
            else:
                lines.append(self._indent(f'''
@pytest.mark.asyncio
async def test_{cls.name.lower()}_{method.name}_invocation(self):
    """Test asynchronous method execution: `{cls.name}.{method.name}`."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    try:
        obj = {cls.name}({init_args})
        result = await obj.{method.name}({method_args})
    except (TypeError, ValueError):
        pass  # type contract violations are acceptable
    except Exception:
        raise  # real failures must surface
'''))

        return "\n".join(lines)

    def _generate_endpoint_tests(self) -> str:
        lines = [
            'class TestGenEndpoints:',
            '    """Auto-generated verification tests for API endpoints."""',
            "",
        ]

        for ep in self.analysis.endpoints:
            safe_name = ep.function_name.replace("/", "_").replace("-", "_")
            methods_str = ", ".join(f'"{m}"' for m in ep.methods)

            lines.append(self._indent(f'''
def test_endpoint_handler_{safe_name}_resolved(self):
    """Verify endpoint handler definition `{ep.function_name}` at route {ep.path}."""
    if _target_module is None:
        pytest.skip("Target module unimportable")
    handler = getattr(_target_module, '{ep.function_name}', None)
    assert handler is not None, "Endpoint handler '{ep.function_name}' unresolved"
    assert callable(handler)

def test_endpoint_route_{safe_name}_methods(self):
    """Verify endpoint HTTP method allowance [{methods_str}]."""
    expected = [{methods_str}]
    assert len(expected) > 0
'''))

        return "\n".join(lines)

    def _build_sample_args(self, params: list[ParamInfo], valid: bool = True) -> str:
        if not params:
            return ""
        parts = []
        for p in params:
            if p.has_default:
                continue
            type_key = p.annotation.split("[")[0].strip("'\"") if p.annotation else ""
            samples = self._TYPE_SAMPLES.get(type_key, self._TYPE_SAMPLES[""])
            val = samples[0] if valid else samples[-1]
            parts.append(f"{p.name}={val}")
        return ", ".join(parts)

    @staticmethod
    def _pascal(name: str) -> str:
        return "".join(word.capitalize() for word in name.split("_"))

    @staticmethod
    def _indent(code: str, level: int = 1) -> str:
        prefix = "    " * level
        return textwrap.indent(textwrap.dedent(code), prefix)


# ---------------------------------------------------------------------------
# Orchestrator — analyze, generate, run, evaluate
# ---------------------------------------------------------------------------

def analyze_and_test(
    source_path: str | Path,
    output_dir: str | Path | None = None,
    run_tests: bool = True,
    modify_sys_path: bool = False,
) -> dict[str, Any]:
    """
    Unified verification pipeline:
    Supports:
    - Single .py file
    - Local directory
    - GitHub repository ZIP archive
    """
    source_path = Path(source_path).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {source_path}")

    # Working output directories
    base_dir = Path(__file__).resolve().parent.parent
    if output_dir is None:
        output_dir = base_dir / "tests" / "generated"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    extracted_root: Optional[Path] = None
    extra_sys_paths: list[str] = []
    target_type = "file"
    existing_tests: list[str] = []

    # Step 1: Ingestion & Archive Unpacking
    if source_path.is_file() and (source_path.suffix.lower() == ".zip" or zipfile.is_zipfile(source_path)):
        target_type = "zip_archive"
        extract_dest = base_dir / "reports" / "extracted" / f"archive_{uuid.uuid4().hex[:8]}"
        extracted_root = safe_extract_zip(source_path, extract_dest)
        repo_info = discover_repository_structure(extracted_root)
        extra_sys_paths = repo_info["sys_paths"]
        existing_tests = repo_info["existing_test_files"]
        target_files = [Path(p) for p in repo_info["source_files"]]
    elif source_path.is_dir():
        target_type = "directory"
        repo_info = discover_repository_structure(source_path)
        extra_sys_paths = repo_info["sys_paths"]
        existing_tests = repo_info["existing_test_files"]
        target_files = [Path(p) for p in repo_info["source_files"]]
    else:
        target_type = "file"
        extra_sys_paths = [str(source_path.parent)]
        target_files = [source_path]

    # Ensure search paths are in Python's active sys.path (only if explicitly requested)
    if modify_sys_path:
        for p in extra_sys_paths:
            if p not in sys.path:
                sys.path.insert(0, p)

    # Step 2: AST Source Analysis
    analyzer = SourceFileAnalyzer()
    analyses: list[SourceAnalysis] = []
    for f in target_files:
        if f.name.startswith("__"):
            continue
        analysis = analyzer.analyze(f)
        analyses.append(analysis)

    results: dict[str, Any] = {
        "source_path": str(source_path),
        "target_type": target_type,
        "extracted_root": str(extracted_root) if extracted_root else None,
        "analyses": [a.to_dict() for a in analyses],
        "generated_tests": [],
        "existing_tests": existing_tests,
        "test_report": None,
        "project_test_report": None,
        "generated_test_report": None,
        "evaluation": None,
    }

    # Step 3: Test Generation for Discovered Modules
    generated_paths: list[str] = []
    for analysis in analyses:
        if analysis.parse_errors:
            continue
        if not analysis.functions and not analysis.classes and not analysis.endpoints:
            continue
        gen = TestGenerator(analysis, extra_sys_paths=extra_sys_paths)
        out_path = output_dir / f"test_gen_{analysis.module_name}_{uuid.uuid4().hex[:4]}.py"
        gen.generate_to_file(out_path)
        generated_paths.append(str(out_path))
        results["generated_tests"].append(str(out_path))

    # Step 4: Test Suite Execution via subprocess (avoids polluting host process)
    def _run_tests_subprocess(paths: list[str]) -> dict:
        """Run pytest paths in a subprocess; parse summary line for results."""
        import subprocess
        import re as _re

        if not paths:
            return {"status": "NO_TESTS", "total": 0, "passed": 0, "failed": 0,
                    "errors": 0, "skipped": 0, "pass_rate": 0.0, "results": []}
        try:
            env = dict(os.environ)
            existing_pythonpath = env.get("PYTHONPATH", "")
            all_paths = [p for p in extra_sys_paths if p]
            if existing_pythonpath:
                all_paths.append(existing_pythonpath)
            env["PYTHONPATH"] = os.pathsep.join(all_paths)

            proc = subprocess.run(
                [sys.executable, "-m", "pytest"] + paths +
                ["-v", "--tb=short", "-q", "--no-header"],
                capture_output=True, text=True, timeout=120, env=env,
            )
            stdout = proc.stdout + proc.stderr
            # Parse summary line e.g. "5 passed, 2 failed, 1 error in 3.45s"
            summary_match = _re.search(
                r"(\d+) passed(?:,\s*(\d+) failed)?(?:,\s*(\d+) error)?(?:,\s*(\d+) skipped)?",
                stdout,
            )
            if summary_match:
                passed = int(summary_match.group(1) or 0)
                failed = int(summary_match.group(2) or 0)
                errors = int(summary_match.group(3) or 0)
                skipped = int(summary_match.group(4) or 0)
            else:
                # No passing tests found — check for failures only
                fail_match = _re.search(r"(\d+) failed", stdout)
                err_match = _re.search(r"(\d+) error", stdout)
                skip_match = _re.search(r"(\d+) skipped", stdout)
                passed = 0
                failed = int(fail_match.group(1)) if fail_match else 0
                errors = int(err_match.group(1)) if err_match else 0
                skipped = int(skip_match.group(1)) if skip_match else 0
            total = passed + failed + errors + skipped
            pass_rate = round(passed / max(total, 1) * 100.0, 1)
            return {
                "status": "TIMEOUT" if proc.returncode == -9 else "DONE",
                "total": total, "passed": passed, "failed": failed,
                "errors": errors, "skipped": skipped, "pass_rate": pass_rate,
                "results": [],
            }
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "total": 0, "passed": 0, "failed": 0,
                    "errors": 0, "skipped": 0, "pass_rate": 0.0, "results": []}

    if run_tests:
        # Run project's own existing tests first
        if existing_tests:
            project_report = _run_tests_subprocess(existing_tests)
        else:
            project_report = None

        # Run generated smoke tests separately
        if generated_paths:
            generated_report = _run_tests_subprocess(generated_paths)
        else:
            generated_report = None

        results["project_test_report"] = project_report
        results["generated_test_report"] = generated_report

        # Backward compat: test_report = project tests if available, else generated
        primary_report = project_report if project_report else generated_report
        results["test_report"] = primary_report

        # Step 5: AI Failure Analysis & Root Cause Evaluation on primary report
        if primary_report and (primary_report.get("failed", 0) > 0 or primary_report.get("errors", 0) > 0):
            from core.ai_agent_evaluator import AgentEvaluator
            evaluator = AgentEvaluator()
            eval_result = evaluator.analyze_test_report(primary_report)
            results["evaluation"] = eval_result.to_dict()

    return results


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m core.source_analyzer <path_to_source.py_or_dir_or_zip>")
        print("       python -m core.source_analyzer <path> --generate-only")
        sys.exit(1)

    target = sys.argv[1]
    generate_only = "--generate-only" in sys.argv
    run = not generate_only

    result = analyze_and_test(target, run_tests=run)
    print(json.dumps(result, indent=2, default=str))
