"""Default regex patterns for the rule-based XSS detector."""


DEFAULT_XSS_PATTERNS: list[str] = [
	# Inline Script Injection
	r"(?i)<\s*/?\s*script\b",
	r"(?i)\b(?:java|vb)script\s*:",
	# Event Handler Injection
	r"(?i)\bon[a-z][a-z0-9_-]*\s*=",
	# Cookie Theft
	r"(?i)\bdocument\s*\.\s*cookie\b",
	r"(?i)\bdocument\s*\[\s*['\"]cookie['\"]\s*\]",
	r"(?i)\bcookie\s*[.\[),;+]",
	# DOM Manipulation
	r"(?i)\b(?:document|window)\s*\.\s*(?:write|writeln|location|innerHTML|outerHTML)\b",
	r"(?i)\bdocument\s*\.\s*title\b",
	r"(?i)\b(?:document\s*\.\s*(?:body|documentElement)|documentElement)\s*\.\s*style\b",
	r"(?i)\b(?:eval|setTimeout|setInterval)\s*\(",
]
