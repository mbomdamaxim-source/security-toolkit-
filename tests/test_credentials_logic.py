"""Tests for the credential auditor's pure logic (no GUI required)."""
import math

import pytest

from modules.credentials.logic import (
    COMMON_PASSWORDS,
    analyze_password,
    common_password_match,
    estimate_entropy_bits,
    format_duration,
    generate_password,
)


def test_common_bank_is_curated_and_valid():
    assert len(COMMON_PASSWORDS) >= 2000
    assert len(set(COMMON_PASSWORDS)) == len(COMMON_PASSWORDS)  # unique
    assert COMMON_PASSWORDS == tuple(sorted(COMMON_PASSWORDS))  # sorted
    assert all(isinstance(entry, str) and entry for entry in COMMON_PASSWORDS)
    for known in ("123456", "password", "qwerty", "iloveyou", "letmein", "admin",
                  "welcome", "monkey", "dragon", "abc123", "qazwsxedc"):
        assert known in COMMON_PASSWORDS


def test_common_bank_includes_expanded_variants():
    # Entries supplied by the project owner from expanded common-password lists.
    for variant in ("imadmin", "mywelcome", "thepassword", "trustno1007",
                    "p@$$w0rd", "qazxsw", "mnbvcxz", "w3lc0m3", "v1c70ry",
                    "$up3rm@n", "7ru$7n01", "admin2026", "dragon112345",
                    "iloveyou2020", "zxcvbnm1"):
        assert variant in COMMON_PASSWORDS


def test_trivial_password_is_flagged_common_and_very_weak():
    report = analyze_password("password")
    assert report.in_common_list and report.common_match == "password"
    assert report.score < 20 and report.strength == "Very weak"
    assert report.checks[-2].passed is False  # the "no obvious patterns" check


def test_numeric_password_is_flagged_common():
    report = analyze_password("123456")
    assert report.in_common_list
    assert report.strength in {"Very weak", "Weak"}


def test_leet_variant_is_detected():
    # "p@ssw0rd" is now in the bank verbatim, so the exact entry wins.
    report = analyze_password("p@ssw0rd")
    assert report.in_common_list and report.common_match == "p@ssw0rd"
    # Leet-normalization fallback still catches variants that are not in the
    # bank verbatim, e.g. "s3cur1ty" -> normalized "security".
    assert common_password_match("P@ssw0rd") == "p@ssw0rd"
    assert common_password_match("s3cur1ty") == "security"


def test_strong_random_password_scores_very_strong():
    report = analyze_password("Kx9#mP2$vL7qWr!T")
    assert not report.in_common_list
    assert report.score >= 80 and report.strength == "Very strong"
    assert report.entropy_bits >= 100
    assert report.patterns == ()
    assert all(check.passed for check in report.checks)


def test_medium_password_scores_strong():
    report = analyze_password("Tr0ub4dour&3")
    assert not report.in_common_list
    assert report.strength == "Strong"
    assert report.score >= 60


def test_empty_password_returns_floor_report():
    report = analyze_password("")
    assert report.score == 0 and report.strength == "Very weak"
    assert report.entropy_bits == 0.0 and not report.in_common_list


def test_non_text_password_rejected():
    with pytest.raises(TypeError):
        analyze_password(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        analyze_password("abc", context=123)  # type: ignore[arg-type]


def test_entropy_math_is_length_times_log2_pool():
    assert estimate_entropy_bits("aaaa") == pytest.approx(4 * math.log2(26))
    assert estimate_entropy_bits("aaaa1111") == pytest.approx(8 * math.log2(36))
    assert estimate_entropy_bits("") == 0.0


def test_crack_time_math_uses_stated_rates():
    report = analyze_password("Kx9#mP2$vL7qWr!T")
    expected = 2 ** report.entropy_bits
    assert report.offline_crack_seconds == pytest.approx(expected / 1_000_000_000)
    assert report.online_crack_seconds == pytest.approx(expected / 1_000)


def test_format_duration_units_and_pluralisation():
    assert format_duration(0.5) == "less than a second"
    assert format_duration(1) == "1 second"
    assert format_duration(45) == "45 seconds"
    assert format_duration(60) == "1 minute"
    assert format_duration(3600) == "1 hour"
    assert format_duration(86_400) == "1 day"
    assert format_duration(31_557_600) == "1 year"
    assert format_duration(3_155_760_000) == "100 years"


def test_keyboard_walk_detected():
    report = analyze_password("poiuytrewq")  # top row, reversed
    assert "keyboard" in report.patterns
    assert report.strength in {"Very weak", "Weak"}


def test_repeated_characters_detected():
    report = analyze_password("aaaaaaaa")
    assert "repeat" in report.patterns
    assert report.strength == "Very weak"


def test_repeating_pattern_detected():
    report = analyze_password("abababab")
    assert "pattern" in report.patterns
    assert report.strength == "Very weak"


def test_year_and_embedded_word_detected():
    report = analyze_password("Summer2024!")
    assert "year" in report.patterns and "word" in report.patterns
    assert report.score <= 35 and report.strength == "Weak"
    assert report.offline_crack_seconds < 1  # honest: a word + a year is trivial


def test_substring_common_word_caught_without_exact_bank_match():
    report = analyze_password("P@ssword2024")
    assert not report.in_common_list  # not an exact bank entry...
    assert "word" in report.patterns   # ...but contains "password"
    assert report.score <= 35 and report.strength == "Weak"
    assert report.offline_crack_seconds < 1


def test_personal_context_detected_when_supplied():
    with_context = analyze_password("Maxim2005", context="Maxim 2005")
    assert "context" in with_context.patterns
    assert with_context.score <= 35 and with_context.strength == "Weak"
    assert with_context.offline_crack_seconds < 1

    without_context = analyze_password("Maxim2005")
    assert "context" not in without_context.patterns
    assert "year" in without_context.patterns  # "2005" is still a year


def test_pattern_check_listed_in_report_checks():
    report = analyze_password("qazwsxedc")
    labels = [check.label for check in report.checks]
    assert any("patterns" in label for label in labels)
    failed = [check for check in report.checks if not check.passed]
    assert any("patterns" in check.label for check in failed)


def test_generate_password_is_secure_and_valid():
    password = generate_password()
    assert len(password) == 20
    assert any(c.islower() for c in password)
    assert any(c.isupper() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(not c.isalnum() for c in password)
    assert common_password_match(password) is None
    assert analyze_password(password).strength == "Very strong"
    with pytest.raises(ValueError):
        generate_password(length=4)
    with pytest.raises(ValueError):
        generate_password(length=200)


def test_generate_password_produces_varied_output():
    samples = {generate_password(12, symbols=False) for _ in range(20)}
    assert len(samples) >= 15
    assert all(not any(not c.isalnum() for c in sample) for sample in samples)


def test_generated_passphrases_score_very_strong_and_match_nist_entropy():
    from modules.credentials.logic import generate_passphrase, estimate_entropy_bits, is_passphrase
    four = generate_passphrase(4)
    assert is_passphrase(four)
    assert estimate_entropy_bits(four) == pytest.approx(4 * math.log2(7776), abs=0.5)
    assert analyze_password(four).strength == "Very strong"
    five_hyphen = generate_passphrase(5, "-")
    assert is_passphrase(five_hyphen)
    assert estimate_entropy_bits(five_hyphen) == pytest.approx(5 * math.log2(7776), abs=0.5)
    with pytest.raises(ValueError):
        generate_passphrase(2)
    with pytest.raises(ValueError):
        generate_passphrase(4, "")


def test_known_passphrase_no_longer_penalised_as_weak():
    report = analyze_password("correct horse battery staple")
    assert report.strength == "Very strong"
    assert report.score >= 80
    assert estimate_entropy_bits("correct horse battery staple") == pytest.approx(4 * math.log2(7776), abs=0.5)


def test_short_single_words_remain_capped():
    assert analyze_password("summer2024!").strength == "Weak"
    assert analyze_password("password").strength == "Very weak"
