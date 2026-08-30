package main

import (
	"html/template"
	"io"
	"net/http"

	"github.com/labstack/echo/v5"
)

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(
	c *echo.Context,
	w io.Writer,
	name string,
	data any,
) error {
	err := t.templates.ExecuteTemplate(w, name, data)

	if err != nil {
		return echo.NewHTTPError(
			http.StatusInternalServerError,
			err.Error(),
		)
	}

	return nil
}
