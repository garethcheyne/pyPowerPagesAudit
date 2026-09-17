"""Publishing state: draft content is not served, so it is not live exposure."""

from __future__ import annotations

from helpers import build_model, page

from ppaudit.model import ConfigLoader, PublishingState

STATES = [
    PublishingState(id="state-published", name="Published", is_visible=True,
                    is_default=True),
    PublishingState(id="state-draft", name="Draft", is_visible=False),
]


def _resolve(model):
    """Drive the loader's resolution step without a Dataverse client."""
    ConfigLoader.__new__(ConfigLoader)._resolve_publishing(model)
    return model


def test_visibility_comes_from_the_flag_not_the_state_name():
    model = build_model(
        pages=[page("p1", "Live", "live", state_id="state-published"),
               page("p2", "Pending", "pending", state_id="state-draft")],
        publishing_states=[
            PublishingState(id="state-published", name="Live on site", is_visible=True),
            PublishingState(id="state-draft", name="Awaiting approval", is_visible=False),
        ])
    _resolve(model)
    assert {p.name: p.live for p in model.pages} == {"Live": True, "Pending": False}
    # The label follows the record, so a renamed state still reads correctly.
    assert {p.name: p.state for p in model.pages} == {
        "Live": "Live on site", "Pending": "Awaiting approval"}


def test_an_unreadable_or_missing_state_is_treated_as_live():
    """Fail open: never hide a real exposure because a lookup was missing."""
    model = build_model(
        pages=[page("p1", "No state", "a"),
               page("p2", "Unknown state", "b", state_id="state-gone")],
        publishing_states=STATES)
    _resolve(model)
    assert all(p.live for p in model.pages)


def test_no_publishing_state_table_leaves_everything_live():
    model = build_model(pages=[page("p1", "Anything", "a", state_id="state-draft")])
    _resolve(model)
    assert model.pages[0].live is True


def test_published_pages_carry_the_state_for_the_report():
    model = build_model(pages=[page("p", "Pricing", "pricing",
                                    state="Draft", live=False)])
    model.resolve_page_paths()
    row = model.published_pages()[0]
    assert (row.state, row.live) == ("Draft", False)
