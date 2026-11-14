import pytest
from app.services.risk.scorer import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


class TestRiskScorer:
    def test_empty_findings_score_zero(self, scorer):
        assert scorer.calculate_scan_score([]) == 0

    def test_critical_findings_high_score(self, scorer):
        findings = [{"severity": "CRITICAL"}] * 10
        score = scorer.calculate_scan_score(findings)
        assert score > 0
        assert score <= 100

    def test_low_findings_low_score(self, scorer):
        findings = [{"severity": "LOW"}] * 5
        score = scorer.calculate_scan_score(findings)
        assert score < 10

    def test_mixed_severity(self, scorer):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ]
        score = scorer.calculate_scan_score(findings)
        assert 0 < score < 100

    def test_max_score_capped_at_100(self, scorer):
        assert scorer.calculate_scan_score([{"severity": "CRITICAL"}] * 2500) == 100
        assert scorer.calculate_scan_score([{"severity": "CRITICAL"}] * 9000) == 100

    def test_score_still_moves_in_a_large_backlog(self, scorer):
        """A capped straight line gave 100 for 50 criticals and for 400; fixing findings changed nothing."""
        scores = [scorer.calculate_scan_score([{"severity": "CRITICAL"}] * n) for n in (25, 50, 100, 200, 400, 800)]
        assert scores == sorted(set(scores)) and scores[0] == 50 and scores[-1] < 100
        assert scorer.calculate_scan_score([{"severity": "CRITICAL"}] * 5) == 10      # small counts unchanged

    def test_score_increases_with_severity(self, scorer):
        low_score = scorer.calculate_scan_score([{"severity": "LOW"}] * 10)
        high_score = scorer.calculate_scan_score([{"severity": "HIGH"}] * 10)
        critical_score = scorer.calculate_scan_score([{"severity": "CRITICAL"}] * 10)
        assert low_score < high_score < critical_score

    def test_info_severity_zero_weight(self, scorer):
        findings = [{"severity": "INFO"}] * 10
        score = scorer.calculate_scan_score(findings)
        assert score == 0
