package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/satyajitnayk/csrf-security/db"
	"github.com/satyajitnayk/csrf-security/server/middleware/myJwt"
	"github.com/satyajitnayk/csrf-security/server/templates"
)

// using all the handler as there is no library like gin used here

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

// help in recovery from panic situation
// used as middleware
func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panic("Recovered! Panic: %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "/logout", "/deleteUser":
			log.Println("In auth restricted section")

			authCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no auth cookie")
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(401), 401)
				return
			} else if authErr != nil {
				log.Panic("panic: %+v", authErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			refreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no refresh cookie found")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)
				return
			} else if refreshErr != nil {
				log.Panic("panic: %+v", refreshErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			requestCsrfToken := grabCsrfFromRequest(r)
			log.Println(requestCsrfToken)

			// check for jwt validity
			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshTokens(authCookie.Value, refreshCookie.Value, requestCsrfToken)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized attempt! JWT not valid!")
					http.Error(w, http.StatusText(401), 401)
					return
				} else {
					log.Panic("err not nil")
					log.Panic("panic: %+v", err)
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}
			log.Println("Successfully recreated jwts")

			w.Header().Set("Access-Control-Allow-Origin", "*")
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)

		default:
			// no check needed
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromRequest(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{CsrfSecret: csrfSecret, SecretMessage: "Hello Satya!!"})
	case "/login":
		switch r.Method {
		case "GET":
		case "POST":
		default:
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage{BAlertUser: false, AlertMsg: ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
			// username exists
			if err == nil {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				// username not exists
				role := "user"
				uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				log.Println("uuid: " + uuid)

				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", 302)
	case "/deleteUser":
	default:
	}
}

// revoke our cookies
func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	// if present, revoke the refresh cookie from our db
	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		// do nothing
		return
	} else if refreshErr != nil {
		log.Panic("panic: %+v")
		http.Error(*w, http.StatusText(500), 500)
	}

	// revoke refersh token
	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)
}

// pick csrf from request
func grabCsrfFromRequest(r *http.Request) string {
	csrfFromForm := r.FormValue("X-CSRF-Token")

	if csrfFromForm != "" {
		return csrfFromForm
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}
