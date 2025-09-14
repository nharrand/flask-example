import atheris
import sys
from api_logic import normalize_tags

def TestOneInput(data: bytes) -> None:
    if len(data) < 1:
        return

    # Use structured input generation to target the regression
    # Create problematic tag lists that will expose the bug

    # Use first byte to determine number of tags (1-5)
    num_tags = (data[0] % 5) + 1

    tags = []
    for i in range(min(num_tags, len(data) - 1)):
        if i + 1 >= len(data):
            break

        byte_val = data[i + 1]
        type_selector = byte_val % 6

        if type_selector == 0:
            tags.append(byte_val)
        elif type_selector == 1:
            tags.append(None)
        elif type_selector == 2:
            tags.append(bool(byte_val % 2))
        elif type_selector == 3:
            tags.append(float(byte_val))
        elif type_selector == 4:
            tags.append([byte_val])
        else:
            # Valid string case (for contrast)
            tags.append(f"tag_{byte_val}")

    # normalize_tags should handle all input types gracefully
    # Any exception indicates the regression
    try:
        result = normalize_tags(tags)
        # Verify the contract: always returns List[str]
        assert isinstance(result, list), f"Expected list, got {type(result)}"
        for item in result:
            assert isinstance(item, str), f"Expected all strings, got {type(item)}: {item}"
    except Exception as e:
        # Any uncaught exception is the regression we want to catch
        raise

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
