package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var (
	key = []byte("13522094928")
)

func main() {
	httpServer := http.Server{
		Addr: "0.0.0.0:8080",
	}
	http.HandleFunc("/login", LoginHandle)
	userInfo := &UserInfo{}
	http.Handle("/user/info", AuthRequiredMiddleware(userInfo))
	http.HandleFunc("/user/info2", AuthRequiredMiddleware2(UserInfo2))

	err := httpServer.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

type LoginReq struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func LoginHandle(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		ResponseWithJSON(writer, http.StatusBadRequest, "bad request")
		return
	}
	DebugPrint(request.Header)
	// Parse body
	body, err := io.ReadAll(request.Body)
	if err != nil {
		ResponseWithJSON(writer, http.StatusBadRequest, err.Error())
		return
	}
	defer request.Body.Close()
	var login LoginReq
	err = json.Unmarshal(body, &login)
	if err != nil {
		ResponseWithJSON(writer, http.StatusBadRequest, err.Error())
		return
	}
	DebugPrint(login)
	// Parse body Method-2
	// json.NewDecoder(request.Body).Decode()
	// https://www.alexedwards.net/blog/how-to-properly-parse-a-json-request-body

	// Generate JWT
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Issuer:    login.User,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(key)
	if err != nil {
		ResponseWithJSON(writer, http.StatusBadRequest, err.Error())
		return
	}
	ResponseWithJSON(writer, http.StatusOK, tokenStr)
}

func AuthRequiredMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		DebugPrint("this is AuthRequiredMiddleware")
		claims, err := ValidJWT(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			ResponseWithJSON(writer, http.StatusUnauthorized, fmt.Sprintf("Access Deny, Reason:%v", err))
			return
		}
		DebugPrint(*claims)
		next.ServeHTTP(writer, request)
	})
}

func AuthRequiredMiddleware2(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		DebugPrint("this is AuthRequiredMiddleware2")
		claims, err := ValidJWT(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			ResponseWithJSON(writer, http.StatusUnauthorized, fmt.Sprintf("Access Deny, Reason:%v", err))
			return
		}
		DebugPrint(*claims)
		next.ServeHTTP(writer, request)
	}
}

func UserInfo2(writer http.ResponseWriter, request *http.Request) {
	ResponseWithJSON(writer, http.StatusOK, "user is devin")
	return
}

type UserInfo struct{}

func (ui UserInfo) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ResponseWithJSON(writer, http.StatusOK, "user is devin")
	return
}

func ValidJWT(tokenString string) (*jwt.RegisteredClaims, error) {
	claims := jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

func DebugPrint(msg interface{}) {
	fmt.Printf("[DEBUG] %+v\n", msg)
}

func ResponseWithJSON(writer http.ResponseWriter, statusCode int, obj any) {
	writer.WriteHeader(http.StatusBadRequest)
	objByte, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	writer.Write(objByte)
	return
}
