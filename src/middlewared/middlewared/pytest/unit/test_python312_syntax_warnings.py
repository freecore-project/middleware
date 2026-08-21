from pathlib import Path
import warnings


REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
PYTHON_312_WARNING_SOURCES = (
    REPOSITORY_ROOT / "src/afpusers/files/afpusers.py",
    REPOSITORY_ROOT / "src/freenas/etc/netcli",
    REPOSITORY_ROOT / (
        "src/middlewared/middlewared/alembic/versions/12.0/"
        "2020-02-10_09-47_ssh_weak_ciphers.py"
    ),
    REPOSITORY_ROOT / "src/middlewared/middlewared/plugins/tunables.py",
)


def test_known_python_312_warning_sources_compile_cleanly():
    for source_path in PYTHON_312_WARNING_SOURCES:
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            compile(source_path.read_bytes(), str(source_path), "exec")
