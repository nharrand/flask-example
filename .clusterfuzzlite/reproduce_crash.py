#!/usr/bin/env python3
"""
Script to reproduce ClusterFuzzLite crashes locally
Usage: python reproduce_crash.py <crash_file>
"""

import sys
import os
from pathlib import Path

def reproduce_crash(crash_file_path):
    """Reproduce a crash from a ClusterFuzzLite crash file"""

    if not os.path.exists(crash_file_path):
        print(f"Error: Crash file not found: {crash_file_path}")
        return 1

    # Read the crash input
    with open(crash_file_path, 'rb') as f:
        crash_input = f.read()

    print(f"Reproducing crash from: {crash_file_path}")
    print(f"Input size: {len(crash_input)} bytes")
    print(f"Input (hex): {crash_input.hex()}")
    print(f"Input (repr): {repr(crash_input)}")
    print("-" * 50)

    # Import the fuzzer
    try:
        # Add .clusterfuzzlite to path so we can import the fuzzer
        sys.path.insert(0, '.clusterfuzzlite')
        from api_fuzzer import TestOneInput

        print("Running TestOneInput with crash input...")
        TestOneInput(crash_input)
        print("No crash occurred - this might be a different environment issue")

    except Exception as e:
        print(f"CRASH REPRODUCED!")
        print(f"Exception: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

def test_with_sample_inputs():
    """Test with some sample inputs that should trigger the regression"""
    print("Testing with sample inputs that should trigger regression...")

    # Add .clusterfuzzlite to path
    sys.path.insert(0, '.clusterfuzzlite')
    from api_fuzzer import TestOneInput

    # Sample inputs that should crash due to non-string types
    test_inputs = [
        # Input that generates integer tags
        bytes([1, 0]),  # num_tags=2, first tag type=0 (integer)
        bytes([2, 1, 2]), # num_tags=3, None and boolean types
        bytes([1, 3]),  # num_tags=2, float type
        bytes([1, 4]),  # num_tags=2, list type
    ]

    for i, test_input in enumerate(test_inputs):
        print(f"\nTest {i+1}: {test_input.hex()}")
        try:
            TestOneInput(test_input)
            print("  No crash")
        except Exception as e:
            print(f"  CRASH: {type(e).__name__}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python reproduce_crash.py <crash_file>")
        print("  python reproduce_crash.py --test-samples")
        sys.exit(1)

    if sys.argv[1] == "--test-samples":
        test_with_sample_inputs()
    else:
        crash_file = sys.argv[1]
        sys.exit(reproduce_crash(crash_file))
