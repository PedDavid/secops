package main

import (
	"fmt"
	"io"
	"strings"
)

func badgeSummary(r *DiffResult) string {
	if len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Changed) == 0 {
		return "no changes"
	}
	var parts []string
	if len(r.Changed) > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", len(r.Changed)))
	}
	if len(r.Added) > 0 {
		parts = append(parts, fmt.Sprintf("%d added", len(r.Added)))
	}
	if len(r.Removed) > 0 {
		parts = append(parts, fmt.Sprintf("%d removed", len(r.Removed)))
	}
	return strings.Join(parts, ", ")
}

func badgeColor(r *DiffResult) string {
	if len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Changed) == 0 {
		return "#4c1" // brightgreen
	}
	return "#dfb317" // yellow
}

// renderBadge writes a shields.io-compatible flat SVG badge.
func renderBadge(w io.Writer, message, colorHex string) {
	const label = "packages"
	// Approximate character width for DejaVu Sans 11px.
	charWidth := 6.5
	pad := 10.0

	lw := float64(len(label))*charWidth + pad
	mw := float64(len(message))*charWidth + pad
	total := lw + mw

	fmt.Fprintf(w, `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="%.0f" height="20">
  <linearGradient id="s" x2="0" y2="100%%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="%.0f" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="%.0f" height="20" fill="#555"/>
    <rect x="%.0f" width="%.0f" height="20" fill="%s"/>
    <rect width="%.0f" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="%.1f" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%.1f" y="14">%s</text>
    <text x="%.1f" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%.1f" y="14">%s</text>
  </g>
</svg>`,
		total, total,
		total, lw, mw, colorHex, total,
		lw/2+1, label, lw/2, label,
		lw+mw/2+1, message, lw+mw/2, message,
	)
}
