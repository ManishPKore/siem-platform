"""Tests for the detection rules repository."""

from unittest.mock import MagicMock

import pytest

from api.models.rule import Rule
from detection_engine.repositories.rules_repository import (
    RuleNotConfiguredError,
    RulesRepository,
)
from detection_engine.rules.base import RuleConfig


@pytest.fixture
def repository():
    """Create a repository backed by a mocked database session."""
    session = MagicMock()
    session_factory = MagicMock(return_value=session)

    repository = RulesRepository(session_factory)

    return repository, session, session_factory


@pytest.fixture
def sample_rule():
    """Create a mock persisted detection rule."""
    rule = MagicMock(spec=Rule)
    rule.rule_name = "brute_force"
    rule.threshold = 5
    rule.window_minutes = 10
    rule.enabled = True
    rule.off_hours_start = None
    rule.off_hours_end = None

    return rule


class TestGetConfig:
    """Tests for loading rule configuration."""

    def test_returns_config_when_rule_exists(
        self, repository, sample_rule
    ):
        repo, session, session_factory = repository
        session.query.return_value.filter.return_value.one_or_none.return_value = (
            sample_rule
        )

        config = repo.get_config("brute_force")

        assert isinstance(config, RuleConfig)
        assert config.rule_name == "brute_force"
        assert config.threshold == 5
        assert config.window_minutes == 10
        assert config.slide_minutes == 10
        assert config.enabled is True
        assert config.off_hours_start is None
        assert config.off_hours_end is None

        session_factory.assert_called_once_with()
        session.query.assert_called_once_with(Rule)
        session.close.assert_called_once_with()

    def test_returns_default_when_rule_is_missing(self, repository):
        repo, session, _ = repository
        session.query.return_value.filter.return_value.one_or_none.return_value = (
            None
        )

        default = RuleConfig(
            rule_name="brute_force",
            threshold=5,
            window_minutes=10,
            slide_minutes=10,
            enabled=True,
        )

        result = repo.get_config("brute_force", default=default)

        assert result is default
        session.close.assert_called_once_with()

    def test_raises_when_rule_is_missing_and_no_default_exists(
        self, repository
    ):
        repo, session, _ = repository
        session.query.return_value.filter.return_value.one_or_none.return_value = (
            None
        )

        with pytest.raises(
            RuleNotConfiguredError,
            match="No configuration found for rule 'brute_force'",
        ):
            repo.get_config("brute_force")

        session.close.assert_called_once_with()

    def test_propagates_database_error_and_closes_session(
        self, repository
    ):
        repo, session, _ = repository
        session.query.side_effect = RuntimeError("database unavailable")

        with pytest.raises(RuntimeError, match="database unavailable"):
            repo.get_config("brute_force")

        session.close.assert_called_once_with()


class TestGetRule:
    """Tests for retrieving persisted rule models."""

    def test_returns_rule_when_found(self, repository, sample_rule):
        repo, session, _ = repository
        session.query.return_value.filter.return_value.one_or_none.return_value = (
            sample_rule
        )

        result = repo.get_rule("brute_force")

        assert result is sample_rule
        session.query.assert_called_once_with(Rule)
        session.close.assert_called_once_with()

    def test_returns_none_when_rule_is_missing(self, repository):
        repo, session, _ = repository
        session.query.return_value.filter.return_value.one_or_none.return_value = (
            None
        )

        result = repo.get_rule("missing_rule")

        assert result is None
        session.close.assert_called_once_with()

    def test_propagates_database_error_and_closes_session(
        self, repository
    ):
        repo, session, _ = repository
        session.query.side_effect = RuntimeError("database unavailable")

        with pytest.raises(RuntimeError, match="database unavailable"):
            repo.get_rule("brute_force")

        session.close.assert_called_once_with()


class TestListEnabled:
    """Tests for listing enabled rules."""

    def test_returns_enabled_rules(self, repository, sample_rule):
        repo, session, _ = repository
        another_rule = MagicMock(spec=Rule)
        another_rule.rule_name = "port_scan"

        expected_rules = [sample_rule, another_rule]

        (
            session.query.return_value
            .filter.return_value
            .order_by.return_value
            .all.return_value
        ) = expected_rules

        result = repo.list_enabled()

        assert result == expected_rules
        session.query.assert_called_once_with(Rule)
        session.close.assert_called_once_with()

    def test_returns_empty_list_when_no_rules_are_enabled(
        self, repository
    ):
        repo, session, _ = repository
        (
            session.query.return_value
            .filter.return_value
            .order_by.return_value
            .all.return_value
        ) = []

        result = repo.list_enabled()

        assert result == []
        session.close.assert_called_once_with()

    def test_propagates_database_error_and_closes_session(
        self, repository
    ):
        repo, session, _ = repository
        session.query.side_effect = RuntimeError("database unavailable")

        with pytest.raises(RuntimeError, match="database unavailable"):
            repo.list_enabled()

        session.close.assert_called_once_with()