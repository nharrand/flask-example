import atheris
import sys, json
from api_logic import normalize_tags

def TestOneInput(data: bytes) -> None:
    # Try to interpret bytes as JSON with a "tags" field
    try:
        obj = json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        return

    if not isinstance(obj, dict) or "tags" not in obj:
        return

    # normalize_tags should *never* throw
    try:
        normalize_tags(obj["tags"])
    except Exception as e:
        # Any uncaught exception is a bug/regression
        raise

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
