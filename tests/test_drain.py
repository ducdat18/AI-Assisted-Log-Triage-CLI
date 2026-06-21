"""Tests for the Drain template miner."""

from __future__ import annotations

import pytest

from loglens.drain import DrainMiner, mine_templates


def test_variable_tokens_collapse_to_wildcard():
    miner = DrainMiner()
    miner.add("Connection to 10.0.0.1 failed after 5000ms")
    template = miner.add("Connection to 10.0.0.9 failed after 5000ms")
    assert "<*>" in template
    assert "Connection to" in template
    assert "failed after" in template


def test_same_shape_messages_share_one_group():
    messages = [f"Failed to flush player state uid={i}: pool exhausted" for i in range(5)]
    ids = [DrainMiner().add_id(m) for m in [messages[0]]]  # sanity: single miner below
    miner = DrainMiner()
    group_ids = [miner.add_id(m) for m in messages]
    assert len(set(group_ids)) == 1
    assert ids  # touch


def test_different_lengths_never_merge():
    miner = DrainMiner()
    a = miner.add_id("disk full on node 3")
    b = miner.add_id("disk full on node 3 immediately after rotation event")
    assert a != b


def test_templates_returns_final_text_per_id():
    miner = DrainMiner()
    miner.add_id("user 1 logged in from 10.0.0.1")
    miner.add_id("user 2 logged in from 10.0.0.2")
    templates = miner.templates()
    assert len(templates) == 1
    only = next(iter(templates.values()))
    assert "<*>" in only


def test_mine_templates_one_per_message():
    messages = ["a 1 b", "a 2 b", "c d e f"]
    out = mine_templates(messages)
    assert len(out) == len(messages)


def test_empty_message_is_safe():
    miner = DrainMiner()
    assert miner.add("") == ""
    assert miner.add_id("   ") == -1


def test_depth_below_minimum_rejected():
    with pytest.raises(ValueError):
        DrainMiner(depth=2)
