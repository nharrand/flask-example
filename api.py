from typing import Iterable, List

def normalize_tags(tags: Iterable) -> List[str]:
    """
    Contract: return a list of lowercased strings; ignore non-strings.
    """
    if tags is None:
        return []

    out = []
    for t in tags:
        if isinstance(t, str):
            out.append(t.strip().lower())
        # else: ignore non-strings
    return out
