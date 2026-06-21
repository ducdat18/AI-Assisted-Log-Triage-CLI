"""Drain log template mining — a parse-tree clusterer, no LLM, no regex zoo.

The default clusterer normalises messages with a hand-written list of regexes.
That works but is brittle: every new variable-token shape needs a new rule.
Drain (He et al., 2017, "Drain: An Online Log Parsing Approach with Fixed Depth
Tree") learns templates structurally instead.

The algorithm:

1. **Length layer** — group messages by token count; messages of different
   length never merge.
2. **Prefix layers** — descend a fixed-depth tree keyed on the first few tokens
   (tokens that look numeric/variable are keyed as ``<*>`` so they don't
   fragment the tree).
3. **Leaf match** — within a leaf, compare against existing log groups by the
   fraction of identical tokens in the same position (``sim_th``). On a match,
   merge: positions that differ collapse to the ``<*>`` wildcard, so the
   template generalises as more examples arrive.

It is online (one pass, no global clustering), deterministic, and dependency
free. We expose it as an alternative grouping key for :mod:`loglens.clustering`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Tokens that are "obviously variable" are keyed as the wildcard during the tree
# descent so that e.g. uid=10241 and uid=10242 reach the same leaf.
_HAS_DIGIT = re.compile(r"\d")
_WILDCARD = "<*>"


@dataclass
class _LogGroup:
    group_id: int
    tokens: list[str]  # current template tokens (wildcards where they vary)
    count: int = 0

    @property
    def template(self) -> str:
        return " ".join(self.tokens)


@dataclass
class DrainMiner:
    """Online fixed-depth-tree log template miner.

    ``depth`` is the total tree depth including the length and leaf layers
    (must be >= 3). ``sim_th`` is the token-similarity threshold in [0, 1] for
    merging a message into an existing group. ``max_children`` caps prefix fan-out
    per node, collapsing overflow into a shared wildcard branch.
    """

    depth: int = 4
    sim_th: float = 0.4
    max_children: int = 100
    # tree: length -> prefix-token -> ... -> list[_LogGroup]
    _root: dict = field(default_factory=dict)
    _next_id: int = 0

    def __post_init__(self) -> None:
        if self.depth < 3:
            raise ValueError("Drain depth must be >= 3 (length + >=1 prefix + leaf)")

    @staticmethod
    def _tokenize(message: str) -> list[str]:
        return message.strip().split()

    @staticmethod
    def _key(token: str) -> str:
        return _WILDCARD if _HAS_DIGIT.search(token) else token

    def _leaf(self, tokens: list[str], create: bool) -> list[_LogGroup] | None:
        """Walk (or build) the tree to the leaf bucket for these tokens."""

        node = self._root.setdefault(len(tokens), {}) if create else self._root.get(len(tokens))
        if node is None:
            return None
        # Number of prefix layers between the length layer and the leaf.
        prefix_layers = min(self.depth - 2, len(tokens))
        for i in range(prefix_layers):
            key = self._key(tokens[i])
            children = node
            if key not in children:
                if not create:
                    key = _WILDCARD if _WILDCARD in children else key
                    if key not in children:
                        return None
                else:
                    if len([k for k in children if k != _WILDCARD]) >= self.max_children:
                        key = _WILDCARD
                    children.setdefault(key, {})
            node = children[key]
        # Leaf bucket holds the list of groups, under a reserved key.
        if create:
            return node.setdefault("__groups__", [])
        return node.get("__groups__")

    @staticmethod
    def _similarity(template: list[str], tokens: list[str]) -> float:
        if not template:
            return 0.0
        same = sum(1 for a, b in zip(template, tokens) if a == b or a == _WILDCARD)
        return same / len(template)

    def _assign(self, message: str) -> _LogGroup | None:
        """Match ``message`` to an existing group or create one; return it."""

        tokens = self._tokenize(message)
        if not tokens:
            return None
        groups = self._leaf(tokens, create=True)
        assert groups is not None
        best: _LogGroup | None = None
        best_sim = -1.0
        for group in groups:
            sim = self._similarity(group.tokens, tokens)
            if sim > best_sim:
                best_sim, best = sim, group
        if best is not None and best_sim >= self.sim_th:
            best.tokens = [a if (a == b) else _WILDCARD for a, b in zip(best.tokens, tokens)]
            best.count += 1
            return best
        group = _LogGroup(group_id=self._next_id, tokens=list(tokens), count=1)
        self._next_id += 1
        groups.append(group)
        return group

    def add(self, message: str) -> str:
        """Add a log message, returning the template it was assigned to."""

        group = self._assign(message)
        return group.template if group is not None else ""

    def add_id(self, message: str) -> int:
        """Add a log message, returning the stable id of its template group.

        Ids are stable across the run even as a group's template generalises, so
        callers can group entries by id and read each group's final template
        from :meth:`templates` afterwards.
        """

        group = self._assign(message)
        return group.group_id if group is not None else -1

    def templates(self) -> dict[int, str]:
        """Final template text for every group id mined so far."""

        result: dict[int, str] = {}

        def walk(node: dict) -> None:
            for key, child in node.items():
                if key == "__groups__":
                    for group in child:
                        result[group.group_id] = group.template
                elif isinstance(child, dict):
                    walk(child)

        for length_node in self._root.values():
            walk(length_node)
        return result


def mine_templates(messages: list[str], **kwargs: object) -> list[str]:
    """Convenience: mine ``messages`` and return one template per message.

    ``kwargs`` are forwarded to :class:`DrainMiner` (``depth``, ``sim_th``, …).
    """

    miner = DrainMiner(**kwargs)  # type: ignore[arg-type]
    return [miner.add(m) for m in messages]
