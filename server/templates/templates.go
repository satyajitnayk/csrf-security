package templates

import (
	"html/template"
	"log"
	"net/http"
)

type LoginPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RegisterPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RestrictedPage struct {
	CsrfSecret    string
	SecretMessage string
}

const basePath = "./server/templates/templateFiles"

var templates = template.Must(template.ParseFiles(basePath+"/login.tmpl", basePath+"/register.tmpl", basePath+"/restricted.tmpl"))

func RenderTemplate(w http.ResponseWriter, templateName string, p interface{}) {
	err := templates.ExecuteTemplate(w, templateName+".tmpl", p)
	if err != nil {
		log.Printf("Template error here: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
