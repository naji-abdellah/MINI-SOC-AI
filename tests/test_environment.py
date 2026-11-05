"""Basic environment and repository sanity tests."""
from pathlib import Path


def test_repo_structure():
    """Verify core directories and essential files exist."""
    root = Path(__file__).parent.parent
    expected_dirs = [
        "docs",
        "ingestion",
        "detections",
        "ml",
        "llm",
        "guardrails",
        "evals",
        "dashboard",
        "data",
    ]
    for d in expected_dirs:
        dir_path = root / d
        assert dir_path.is_dir(), f"Expected directory '{d}' is missing."

    expected_files = [
        "README.md",
        "context.md",
        "docker-compose.yml",
        ".wslconfig.example",
        ".gitignore",
        "requirements.txt",
    ]
    for f in expected_files:
        file_path = root / f
        assert file_path.is_file(), f"Expected file '{f}' is missing."
