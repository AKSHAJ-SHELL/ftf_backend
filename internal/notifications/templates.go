package notifications

import (
	"fmt"
	"strings"
)

// renderConfirmEmail builds the plaintext + HTML for the confirm flow.
// Kept inline (vs. embed) because the templates are small, depend on no
// per-tenant data, and changing them is a deploy event we want to grep.
func renderConfirmEmail(p ConfirmEmailPayload) (subject, text, html string) {
	subject = "Confirm your subscription to Fund the Future"
	text = strings.Join([]string{
		"Welcome to Fund the Future.",
		"",
		"Click the link below to confirm your subscription:",
		p.ConfirmURL,
		"",
		"If you did not request this, you can ignore this email.",
		"",
		"To stop receiving any email from us, use this one-click link:",
		p.UnsubscribeURL,
	}, "\n")
	html = fmt.Sprintf(`<!doctype html>
<html><body style="font-family:Georgia, serif; max-width:560px; margin:auto; padding:24px; color:#2a2620;">
<h1 style="font-weight:400; font-size:24px;">Welcome to Fund the Future</h1>
<p>Click the button below to confirm your subscription. The link expires in seven days.</p>
<p><a href="%s" style="display:inline-block; padding:12px 20px; background:#5c7a5f; color:#f8f4ed; text-decoration:none; border-radius:4px;">Confirm subscription</a></p>
<p style="color:#6b6660;">If you did not request this, you can ignore this email.</p>
<hr style="border:none; border-top:1px solid #e8e0d6;"/>
<p style="font-size:12px; color:#6b6660;">To stop receiving any email from us, <a href="%s">unsubscribe with one click</a>.</p>
</body></html>`, p.ConfirmURL, p.UnsubscribeURL)
	return subject, text, html
}
