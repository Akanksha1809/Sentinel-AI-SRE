"""Pure postmortem rendering: section markers, roundtrip, and golden content."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinel.reports.markdown import (
    ActionFact,
    EvidenceFact,
    HypothesisFact,
    IncidentFacts,
    TimelineFact,
    build_document,
    extract_sections,
    render_evidence,
    render_impact,
    render_remediation,
    render_root_cause,
    render_summary,
    render_timeline,
)

T0 = datetime(2026, 10, 9, 12, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 10, 9, 12, 7, 30, tzinfo=UTC)


def _facts(**overrides: object) -> IncidentFacts:
    base: dict[str, object] = dict(
        short_id="INC-0042",
        service="shop-api",
        environment="local",
        title="High error burn rate",
        severity="critical",
        status="resolved",
        opened_at=T0,
        resolved_at=T1,
        resolved_verified=True,
        alertnames=("ShopApiHighErrorBurnRate",),
    )
    base.update(overrides)
    return IncidentFacts(**base)  # type: ignore[arg-type]


class TestRenderSummary:
    def test_includes_short_id_service_and_severity(self) -> None:
        out = render_summary(_facts())
        assert "INC-0042" in out
        assert "shop-api" in out
        assert "**critical**" in out

    def test_verified_resolution_says_so(self) -> None:
        assert "verified" in render_summary(_facts(resolved_verified=True))
        assert "**not** independently verified" in render_summary(_facts(resolved_verified=False))

    def test_open_incident_shows_status_not_resolved(self) -> None:
        out = render_summary(_facts(status="investigating", resolved_at=None))
        assert "still **investigating**" in out

    def test_no_alerts_recorded_is_explicit(self) -> None:
        assert "none recorded" in render_summary(_facts(alertnames=()))


class TestRenderImpact:
    def test_open_incident_has_no_duration(self) -> None:
        out = render_impact(_facts(resolved_at=None))
        assert "not yet known" in out

    def test_duration_is_formatted_minutes_seconds(self) -> None:
        out = render_impact(_facts())
        assert "7m30s" in out

    def test_duration_over_an_hour_is_formatted(self) -> None:
        out = render_impact(_facts(resolved_at=datetime(2026, 10, 9, 13, 30, 0, tzinfo=UTC)))
        assert "1h30m" in out


class TestRenderTimeline:
    def test_empty_timeline_is_explicit(self) -> None:
        assert "No timeline events" in render_timeline([])

    def test_events_rendered_in_order_given(self) -> None:
        events = [
            TimelineFact(T0, "incident.opened", "alertmanager", "Opened"),
            TimelineFact(T1, "incident.resolved", "responder", "Resolved"),
        ]
        out = render_timeline(events)
        assert out.index("incident.opened") < out.index("incident.resolved")


class TestRenderRootCause:
    def test_no_investigation_is_explicit_and_not_blank(self) -> None:
        out = render_root_cause([])
        assert "not determined by Sentinel" in out

    def test_hypothesis_is_labelled_as_ai_not_fact(self) -> None:
        out = render_root_cause([HypothesisFact("MOCK provider", "DB pool exhausted", 0.8, False)])
        assert "[AI, MOCK provider]" in out
        assert "not confirmed facts" in out

    def test_uncited_hypothesis_is_flagged(self) -> None:
        out = render_root_cause([HypothesisFact("ollama:qwen2.5-coder:3b", "Disk full", 0.4, True)])
        assert "uncited" in out


class TestRenderEvidence:
    def test_empty_is_explicit(self) -> None:
        assert "No evidence" in render_evidence([])

    def test_items_cite_their_ref(self) -> None:
        out = render_evidence([EvidenceFact("m1", "Error ratio", "Spiked to 40%")])
        assert "`m1`" in out
        assert "Error ratio" in out


class TestRenderRemediation:
    def test_empty_is_explicit(self) -> None:
        assert "No remediation" in render_remediation([])

    def test_full_action_lifecycle_rendered(self) -> None:
        out = render_remediation(
            [
                ActionFact(
                    runbook_id="restart-shop-api",
                    status="succeeded",
                    parameters={"service": "shop-api"},
                    dry_run=False,
                    approver="alice",
                    approval_reason="confirmed by dashboard",
                    execution_outcome="changed",
                    verification_passed=True,
                    verification_samples=3,
                )
            ]
        )
        assert "restart-shop-api" in out
        assert "live" in out
        assert "approved by alice" in out
        assert "confirmed by dashboard" in out
        assert "verification passed (3 sample(s))" in out

    def test_proposed_action_with_no_approval_yet(self) -> None:
        out = render_remediation(
            [
                ActionFact(
                    runbook_id="scale-shop-api",
                    status="pending_approval",
                    parameters={},
                    dry_run=True,
                    approver=None,
                    approval_reason=None,
                    execution_outcome=None,
                    verification_passed=None,
                    verification_samples=0,
                )
            ]
        )
        assert "approved by" not in out
        assert "verification" not in out
        assert "dry-run" in out


class TestBuildAndExtractSections:
    def test_build_document_contains_every_section_in_order(self) -> None:
        doc = build_document("Postmortem: INC-0042", {"summary": "S", "impact": "I"})
        for key in (
            "summary",
            "impact",
            "timeline",
            "root_cause",
            "evidence",
            "remediation",
            "lessons_learned",
            "follow_ups",
        ):
            assert f"section:{key}:start" in doc
            assert f"section:{key}:end" in doc
        assert doc.index("section:summary:start") < doc.index("section:impact:start")
        assert doc.index("section:follow_ups:end") < len(doc)

    def test_missing_human_sections_get_placeholders(self) -> None:
        doc = build_document("Title", {})
        assert "Not yet written" in doc

    def test_extract_roundtrips_generated_content(self) -> None:
        original = {"summary": "Summary body here.", "impact": "Impact body here."}
        doc = build_document("Title", original)
        extracted = extract_sections(doc)
        assert extracted["summary"] == "Summary body here."
        assert extracted["impact"] == "Impact body here."

    def test_extract_then_rebuild_preserves_human_edits(self) -> None:
        doc = build_document("Title", {"lessons_learned": "We learned X."})
        human = extract_sections(doc)
        regenerated = build_document(
            "Title",
            {"summary": "New summary", "lessons_learned": human["lessons_learned"]},
        )
        assert "We learned X." in regenerated
        assert "New summary" in regenerated

    def test_extract_ignores_text_outside_markers(self) -> None:
        doc = "# Title\n\nsome preamble\n\n" + build_document("x", {"summary": "Body"})
        extracted = extract_sections(doc)
        assert extracted["summary"] == "Body"

    def test_extract_on_text_with_no_markers_is_empty(self) -> None:
        assert extract_sections("just plain text, no markers at all") == {}

    def test_extract_drops_the_re_derivable_heading(self) -> None:
        doc = build_document("Title", {"summary": "Body text"})
        extracted = extract_sections(doc)
        assert "## Summary" not in extracted["summary"]
        assert extracted["summary"] == "Body text"
