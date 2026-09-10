from collections import Counter
import pytest
from core.quiz_history import QuizHistory
from modules.subnet.logic import QUIZ_BANK, QuizSession, allocate_vlsm, cidr_to_mask, quiz_choices, verify_quiz_bank

def test_fixed_bank_has_90_independently_verified_answers():
    verify_quiz_bank(); assert len(QUIZ_BANK) == 90
    assert Counter(q.question_type for q in QUIZ_BANK) == {'subnet_membership':15,'broadcast_address':15,'usable_hosts':15,'cidr_to_mask':15,'first_usable_host':7,'last_usable_host':8,'wildcard_mask':15}
def test_quiz_session_shuffles_without_repeats():
    session=QuizSession(); seen=[]
    while not session.complete: seen.append(session.current.identifier); session.submit(session.current.correct_answer)
    assert len(seen)==len(set(seen))==90
def test_cidr_conversion(): assert cidr_to_mask('/18')=='255.255.192.0'

def test_vlsm_verified_example_matches_expected_allocation():
    rows = allocate_vlsm("192.168.10.0/24", [("Users", 100), ("Servers", 50), ("Management", 20)])
    assert [(r["name"], r["network"], r["cidr"], r["broadcast"]) for r in rows] == [
        ("Users", "192.168.10.0", "/25", "192.168.10.127"),
        ("Servers", "192.168.10.128", "/26", "192.168.10.191"),
        ("Management", "192.168.10.192", "/27", "192.168.10.223"),
    ]

def test_vlsm_sorts_largest_requirement_first():
    rows = allocate_vlsm("10.0.0.0/24", [("Small", 2), ("Big", 100)])
    assert rows[0]["name"] == "Big" and rows[0]["cidr"] == "/25"

def test_vlsm_rejects_requirements_that_do_not_fit():
    with pytest.raises(ValueError, match="does not fit"):
        allocate_vlsm("10.0.0.0/24", [("A", 300)])
    with pytest.raises(ValueError, match="does not fit"):
        allocate_vlsm("10.0.0.0/23", [("A", 300), ("B", 200)])

def test_vlsm_validates_inputs():
    with pytest.raises(ValueError): allocate_vlsm("not-an-ip", [("A", 2)])
    with pytest.raises(ValueError): allocate_vlsm("10.0.0.0/24", [("", 2)])
    with pytest.raises(ValueError): allocate_vlsm("10.0.0.0/24", [("A", 0)])
    with pytest.raises(ValueError): allocate_vlsm("10.0.0.0/24", [("A", 2), ("a", 2)])
    with pytest.raises(ValueError): allocate_vlsm("10.0.0.0/24", [])

def test_vlsm_smallest_block_is_slash_30():
    rows = allocate_vlsm("10.0.0.0/30", [("P2P", 2)])
    assert rows[0]["cidr"] == "/30" and rows[0]["usable_range"] == "10.0.0.1 – 10.0.0.2"

def test_quiz_choices_always_four_distinct_options_including_answer():
    for question in QUIZ_BANK:
        options = quiz_choices(question.correct_answer, rng=__import__("random").Random(7))
        assert len(options) == 4 and len(set(options)) == 4
        assert question.correct_answer in options
        assert not any("Option " in option for option in options)

def test_quiz_choices_ip_answer_with_colliding_fixed_pool():
    # Regression: "255.255.255.0" collided with the old fixed alternative pool
    # and produced a bogus "Option 4" decoy.
    options = quiz_choices("255.255.255.0", rng=__import__("random").Random(7))
    assert len(options) == 4 and len(set(options)) == 4 and "255.255.255.0" in options

def _entry(index=1):
    return {"date": "2026-08-29", "category": "Usable hosts", "mode": "Practice", "score": index, "total": 15, "percentage": 7}

def test_quiz_history_records_and_caps_at_20(tmp_path):
    store = QuizHistory(tmp_path / "quiz_history.json")
    for index in range(25): store.record(_entry(index))
    entries = store.load()
    assert len(entries) == 20
    assert entries[0]["score"] == 24 and entries[-1]["score"] == 5
    assert store.path.exists()

def test_quiz_history_survives_corrupt_file(tmp_path):
    path = tmp_path / "quiz_history.json"; path.write_text("{not valid json", encoding="utf-8")
    assert QuizHistory(path).load() == []

def test_quiz_history_rejects_malformed_entries(tmp_path):
    store = QuizHistory(tmp_path / "quiz_history.json")
    store.record(_entry())
    path = store.path; path.write_text('[{"date":"2026-08-29","category":"Usable hosts"},{"score":1,"total":15,"percentage":7,"mode":"Practice","date":"2026-08-29","category":"Usable hosts"}]', encoding="utf-8")
    entries = store.load()
    assert len(entries) == 1 and entries[0]["score"] == 1


def test_summary_route_merges_adjacent_24s():
    from modules.subnet.logic import find_summary_route
    result = find_summary_route(["192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24", "192.168.0.0/24"])
    assert result["network"] == "192.168.0.0" and result["prefix"] == 22
    assert result["addresses"] == 1024 and result["wasted"] == 0

def test_summary_route_reports_wasted_space():
    from modules.subnet.logic import find_summary_route
    result = find_summary_route(["10.1.1.0/24", "10.1.2.0/24", "10.1.9.0/24"])
    # 10.1.0.0/21 would stop at 10.1.7.255, so 10.1.9.x forces a /20 block.
    assert result["network"] == "10.1.0.0" and result["prefix"] == 20
    assert result["wasted"] > 0  # 3x/24 inside a /20 leaves plenty unused

def test_summary_route_single_network_and_errors():
    from modules.subnet.logic import find_summary_route
    result = find_summary_route(["172.16.0.0/24"])
    assert result["network"] == "172.16.0.0" and result["prefix"] == 24 and result["wasted"] == 0
    import pytest as _p
    with _p.raises(ValueError, match="valid IPv4 network"):
        find_summary_route(["not-a-network"])
    with _p.raises(ValueError, match="at least one"):
        find_summary_route([])


def test_aggregate_mastery_groups_categories_and_excludes_mixed():
    from modules.subnet.logic import aggregate_mastery
    entries = [
        {"date": "2026-08-01", "category": "Usable hosts", "mode": "Practice", "score": 12, "total": 15, "percentage": 80},
        {"date": "2026-08-02", "category": "Usable hosts", "mode": "Exam 10 minutes", "score": 6, "total": 15, "percentage": 40},
        {"date": "2026-08-03", "category": "Wildcard masks", "mode": "Practice", "score": 13, "total": 15, "percentage": 87},
        {"date": "2026-08-04", "category": "Mixed topics", "mode": "Exam 20 minutes", "score": 80, "total": 90, "percentage": 89},
    ]
    mastery = aggregate_mastery(entries)
    assert len(mastery) == 2
    usable = next(row for row in mastery if row["category"] == "Usable hosts")
    assert usable["attempts"] == 2 and usable["correct"] == 18 and usable["total"] == 30
    assert usable["percentage"] == 60
    wildcard = next(row for row in mastery if row["category"] == "Wildcard masks")
    assert wildcard["attempts"] == 1 and wildcard["percentage"] == 87
    assert mastery[0]["category"] == "Usable hosts"  # sorted by attempts desc
    assert aggregate_mastery([]) == []
