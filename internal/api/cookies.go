package api

import (
	"net/http"
	"time"

	"github.com/vinaayakh/secure-vault/internal/auth"
)

func setAuthCookies(w http.ResponseWriter, accessRaw, refreshRaw string, accessTTL, refreshTTL time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.AccessCookieName,
		Value:    accessRaw,
		Path:     "/",
		MaxAge:   int(accessTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     auth.RefreshCookieName,
		Value:    refreshRaw,
		Path:     auth.RefreshCookiePath,
		MaxAge:   int(refreshTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.AccessCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     auth.RefreshCookieName,
		Value:    "",
		Path:     auth.RefreshCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
