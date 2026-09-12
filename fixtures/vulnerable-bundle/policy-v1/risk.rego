# Quill, a risk check delegated to an external service.
# Holds: PTD-OPA-005 (the case and THREE counter cases).
#
# Every case has a rule name of its own, so they do not add up by incremental
# definition and each one can be observed on its own.
package quill.risk

# ---------------------------------------------------------------------------
# PTD-OPA-005 CASE, consumed on the side that DENIES, error never checked.
# When the service does not answer, denied_vulnerable is undefined and every
# request goes through. No attacker needed: a timeout is enough.
# METADATA
# scope: document
# title: Decision with an external risk check
# description: |
#   Entrypoint. The external source is consumed on the side that DENIES, and
#   saying so is what makes signal 2 of PTD-OPA-005 computable, the signal that
#   tells fail-open from fail-closed and that stays heuristic without the
#   annotation.
# entrypoint: true
default allow_vulnerable := false

allow_vulnerable if {
	input.action == "read"
	not denied_vulnerable
}

denied_vulnerable if {
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
		"raise_error": false,
	})
	enrichment.body.risk_score > 80
}

# ---------------------------------------------------------------------------
# COUNTER CASE (a), the defensive form. Same builtin, same option, same side,
# but the error is consumed: if the source does not answer, it denies.
# Signal 4 tells it apart. The engine must not report it.
# METADATA
# scope: document
# title: Decision with an external risk check, defensive form
# entrypoint: true
default allow_defensive := false

allow_defensive if {
	input.action == "read"
	not denied_defensive
}

denied_defensive if {
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
		"raise_error": false,
	})
	not enrichment.error
	enrichment.body.risk_score > 80
}

denied_defensive if {
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
		"raise_error": false,
	})
	enrichment.error
}

# ---------------------------------------------------------------------------
# COUNTER CASE (b), the very same call, consumed on the side that GRANTS.
# With a default of false the source being down fails closed: that is an
# availability problem, not an authorization one. The engine must not report
# it. It is the counter case that proves signal 2.
# METADATA
# scope: document
# title: Decision with the external source consumed on the granting side
# entrypoint: true
default allow_positive_side := false

allow_positive_side if {
	input.action == "read"
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
		"raise_error": false,
	})
	enrichment.body.risk_score <= 80
}

# ---------------------------------------------------------------------------
# COUNTER CASE (c), an INVERTED counter case: the same vulnerable form but
# WITHOUT raise_error. The engine MUST report it, with
# mitigation_available: true. It is the only way to prove the pattern is not a
# lint rule on raise_error in disguise.
# METADATA
# scope: document
# title: Decision with an external risk check, without raise_error
# entrypoint: true
default allow_default_option := false

allow_default_option if {
	input.action == "read"
	not denied_default_option
}

denied_default_option if {
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
	})
	enrichment.body.risk_score > 80
}
