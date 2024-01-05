package myJwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/satyajitnayk/csrf-security/db"
	"github.com/satyajitnayk/csrf-security/db/models"
)

const (
	privKeyPath = "/keys/app.rsa"
	pubKeyPath  = "/keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func InitJWT() error {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return err
	}

	// parse the data
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	return nil
}

func CreateNewTokens(uuid string, role string) (authTokenString string, refreshTokenString string, csrfSecret string, err error) {
	// genrating csrf secrte
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}

	// genrating refresh token
	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	// genrating auth token
	authTokenString, err = createAuthTokensString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	return
}

func CheckAndRefreshTokens(oldAuthTokenString string, oldRefreshTokenString string, oldCsrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {
	if oldCsrfSecret == "" {
		log.Println("No CSRF token!")
		err = errors.New("Unauthorized")
		return
	}
	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	authTokenClaims, ok := authToken.Claims.(*mdoels.TokenClaims)
	if !ok {
		return
	}
	if oldCsrfSecret != authTokenClaims.Csrf {
		log.Println("CSRF token doesn't match jwt!")
		err = errors.New("Unauthorized")
		return
	}

	if authToken.Valid {
		log.Println("Auth token is valid")

		newCsrfSecret = authToken.Csrf

		newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)

		newAuthTokenString = oldAuthTokenString
		return
	}
}

func createAuthTokensString(uuid string, role string, csrfSecret string) (authTokenString string, err error) {
	authTokenExpirationTime := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExpirationTime,
		},
		role,
		csrfSecret,
	}
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	authTokenString, err := authJwt.SignedString(signKey)
	return
}

func createRefreshTokenString(uuid string, role string, csrfSecret string) {
	refreshTokenExpirationTime := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJwtTokenId, err := db.StoreRefreshToken()
	if err != nil {
		return
	}
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        refreshJwtTokenId,
			Subject:   uuid,
			ExpiresAt: refreshTokenExpirationTime,
		},
		role,
		csrfSecret,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, err := refreshJwt.SignedString(signKey)
	return
}

func updateRefreshTokenExp() {

}

func updateAuthTokenString(uuid string, role string, csrfSecret string) (authTokenString string, err error) {

}

func RevokeRefreshToken(uuid string, role string, csrfSecret string) (refreshTokenString string, err error) {

}

func updateRefreshTokenCsrf() {

}

func GrabUUID() {

}
