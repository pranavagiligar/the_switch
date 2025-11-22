package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/pranavagiligar/the_switch/internal/config"
	"github.com/pranavagiligar/the_switch/internal/models"
	"github.com/pranavagiligar/the_switch/internal/utils"
)

// EnableCORS adds CORS headers to allow frontend access
func EnableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware checks for a valid JWT before proceeding to the handler
func AuthMiddleware(next http.HandlerFunc, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := getTokenFromHeader(r)
		if err != nil {
			utils.RespondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized access: " + err.Error()})
			return
		}

		claims := &models.Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return cfg.JWTKey, nil
		})

		if err != nil || !token.Valid {
			status := http.StatusUnauthorized
			errorMsg := "Invalid or expired token"
			if err != nil && strings.Contains(err.Error(), "token is expired") {
				errorMsg = "Token expired"
			}
			utils.RespondJSON(w, status, map[string]string{"error": errorMsg})
			return
		}

		// Token is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	}
}

// getTokenFromHeader extracts the JWT from the Authorization header
func getTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header required")
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization format")
	}
	return parts[1], nil
}
