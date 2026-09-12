# The Rego v0 variant of policy-v1/risk.rego.
package quill.risk

# PTD-OPA-005 CASE, consumed on the denying side, error never checked
# METADATA
# scope: document
# title: Decision with an external risk check
# entrypoint: true
default allow_vulnerable = false

allow_vulnerable {
	input.action == "read"
	not denied_vulnerable
}

denied_vulnerable {
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
		"raise_error": false,
	})
	enrichment.body.risk_score > 80
}

# COUNTER CASE (a), the defensive form
# METADATA
# scope: document
# title: Decision with an external risk check, defensive form
# entrypoint: true
default allow_defensive = false

allow_defensive {
	input.action == "read"
	not denied_defensive
}

denied_defensive {
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
		"raise_error": false,
	})
	not enrichment.error
	enrichment.body.risk_score > 80
}

denied_defensive {
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
		"raise_error": false,
	})
	enrichment.error
}

# COUNTER CASE (b), the same call on the granting side: fail-closed
# METADATA
# scope: document
# title: Decision with the external source consumed on the granting side
# entrypoint: true
default allow_positive_side = false

allow_positive_side {
	input.action == "read"
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
		"raise_error": false,
	})
	enrichment.body.risk_score <= 80
}

# COUNTER CASE (c), at the default, without raise_error: report it all the same
# METADATA
# scope: document
# title: Decision with an external risk check, without raise_error
# entrypoint: true
default allow_default_option = false

allow_default_option {
	input.action == "read"
	not denied_default_option
}

denied_default_option {
	enrichment := http.send({
		"method": "GET",
		"url": "https://risk.petard-fixture.invalid/score",
	})
	enrichment.body.risk_score > 80
}
