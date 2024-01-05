package db

import (
	"errors"
	"log"

	"github.com/satyajitnayk/csrf-security/db/models"
	"github.com/satyajitnayk/csrf-security/randomstrings"
	"golang.org/x/crypto/bcrypt"
)

// not using any DB so using these variables
var users = map[string]models.User{}
var refreshTokens map[string]string

func InitDB() {
	refreshTokens = make(map[string]string)
}

func StoreUser(username string, password string, role string) (uuid string, err error) {
	uuid, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	//check uuid is unique or not
	u := models.User{}
	for u != users[uuid] {
		uuid, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	passwordHash, hashErr := generateBcryptHash(password)
	if hashErr != nil {
		err = hashErr
		return
	}

	users[uuid] = models.User{Username: username, PasswordHash: passwordHash, Role: role}
	return uuid, err
}

func DeleteUser(uuid string) (models.User, error) {
	delete(users, uuid)
}

func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		return u, nil
	}
	return u, errors.New("User not found with given uuid")
}

func FetchUserByUsername(username string) (models.User, string, error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}
	return models.User{}, "", errors.New("User not found with given username")
}

func StoreRefreshToken() (jwtTokenId string, err error) {

}

func DeleteRefreshToken() {

}

func CheckRefreshToken() bool {

}

func LogUserIn(username string, password string) (models.User, string, error) {
	user, uuid, userErr := FetchUserByUsername(username)
	log.Println(user, uuid, userErr)
	if userErr != nil {
		return models.User{}, "", userErr
	}

	return user, uuid, checkPasswordAgainstHash(user.PasswordHash, password)
}

func generateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}

func checkPasswordAgainstHash(passwordHash string, password string) error {
	bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))

}
