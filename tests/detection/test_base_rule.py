"""Unit tests for the BaseRule contract and registry."""

from abc import abstractmethod

import pytest

from detection_engine.base_rule import BaseRule
from detection_engine.rules.base import RuleConfig


def make_config(rule_name: str) -> RuleConfig:
    """Create a valid RuleConfig for testing."""
    return RuleConfig(
        rule_name=rule_name,
        threshold=5,
        window_minutes=5,
        slide_minutes=1,
    )


def test_registered_rules_returns_copy():
    """Modifying the returned registry must not modify the real registry."""
    original = BaseRule.registered_rules()

    result = BaseRule.registered_rules()
    result.clear()

    assert BaseRule.registered_rules() == original


def test_unregister_removes_rule():
    """Unregistering a rule removes it from the registry."""

    class TemporaryRule(BaseRule):
        rule_name = "test_base_rule_unregister"

        def evaluate(self, stream):
            return stream

    try:
        assert (
            "test_base_rule_unregister" in BaseRule.registered_rules()
        )

        BaseRule.unregister("test_base_rule_unregister")

        assert (
            "test_base_rule_unregister" not in BaseRule.registered_rules()
        )
    finally:
        BaseRule.unregister("test_base_rule_unregister")


def test_unregister_missing_rule_is_safe():
    """Unregistering a nonexistent rule does not raise an exception."""
    BaseRule.unregister("test_base_rule_missing")


def test_empty_rule_name_is_rejected():
    """Reject rule classes whose rule_name is empty."""

    with pytest.raises(ValueError, match="non-empty string"):

        class EmptyNameRule(BaseRule):
            rule_name = "   "

            def evaluate(self, stream):
                return stream


@pytest.mark.parametrize("invalid_name", [123, []])
def test_invalid_rule_name_is_rejected(invalid_name):
    """Reject rule names that are not strings."""

    with pytest.raises(ValueError, match="non-empty string"):

        class InvalidNameRule(BaseRule):
            rule_name = invalid_name

            def evaluate(self, stream):
                return stream


def test_duplicate_rule_name_is_rejected():
    """Two different classes cannot register the same rule name."""

    class FirstRule(BaseRule):
        rule_name = "test_duplicate_base_rule"

        def evaluate(self, stream):
            return stream

    try:
        assert (
            BaseRule.registered_rules()["test_duplicate_base_rule"]
            is FirstRule
        )

        with pytest.raises(ValueError, match="Duplicate rule_name"):

            class SecondRule(BaseRule):
                rule_name = "test_duplicate_base_rule"

                def evaluate(self, stream):
                    return stream
    finally:
        BaseRule.unregister("test_duplicate_base_rule")


def test_same_class_identity_can_be_registered_again():
    """Re-registering the same class identity is permitted."""

    class TemporaryRule(BaseRule):
        rule_name = "test_same_base_rule_identity"

        def evaluate(self, stream):
            return stream

    try:
        BaseRule._registry["test_same_base_rule_identity"] = TemporaryRule

        assert (
            BaseRule.registered_rules()["test_same_base_rule_identity"]
            is TemporaryRule
        )
    finally:
        BaseRule.unregister("test_same_base_rule_identity")


def test_rule_repr_includes_class_and_rule_name():
    """The representation identifies the rule class and name."""

    class TemporaryRule(BaseRule):
        rule_name = "test_base_rule_repr"

        def evaluate(self, stream):
            return stream

    try:
        rule = TemporaryRule(make_config("test_base_rule_repr"))

        assert repr(rule) == (
            "<TemporaryRule rule_name='test_base_rule_repr'>"
        )
    finally:
        BaseRule.unregister("test_base_rule_repr")


def test_mismatched_rule_config_is_rejected():
    """A rule must receive configuration for its own name."""

    class TemporaryRule(BaseRule):
        rule_name = "test_base_rule_config"

        def evaluate(self, stream):
            return stream

    try:
        config = make_config("different_rule_name")

        with pytest.raises(ValueError, match="Invalid rule configuration"):
            TemporaryRule(config)
    finally:
        BaseRule.unregister("test_base_rule_config")


def test_intermediate_class_without_rule_name_is_not_registered():
    """An intermediate subclass without its own rule_name is not registered."""

    class IntermediateRule(BaseRule, register=False):
        @abstractmethod
        def extra_method(self):
            """Additional contract for a concrete child."""

    class ConcreteRule(IntermediateRule):
        rule_name = "test_intermediate_base_rule"

        def evaluate(self, stream):
            return stream

        def extra_method(self):
            return None

    try:
        assert (
            BaseRule.registered_rules()["test_intermediate_base_rule"]
            is ConcreteRule
        )
    finally:
        BaseRule.unregister("test_intermediate_base_rule")