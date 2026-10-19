package main

import (
	_ "embed"
	"html/template"
	"io"
	"log/slog"
)

//go:embed templates/report.html
var reportHTML string

//go:embed templates/progress.js
var progressJS string

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{"findingSection": func(title string, items []Finding) any {
	return struct {
		Title string
		Items []Finding
	}{title, items}
}}).Parse(reportHTML))

type reportData struct {
	OldRef string
	NewRef string
	Result *DiffResult
}

func renderHTML(w io.Writer, oldRef, newRef string, result *DiffResult) {
	if err := reportTmpl.Execute(w, reportData{OldRef: oldRef, NewRef: newRef, Result: result}); err != nil {
		slog.Error("template render failed", "err", err)
	}
}

func renderFragment(w io.Writer, result *DiffResult) {
	if err := reportTmpl.ExecuteTemplate(w, "reportContent", result); err != nil {
		slog.Error("fragment render failed", "err", err)
	}
}
