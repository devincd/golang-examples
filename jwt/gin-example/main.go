package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func main() {
	engine := gin.New()
	engine.Use(gin.Logger(), gin.Recovery())
	engine.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	engine.POST("/login", Login)
	loginGroup := engine.Group("/user/")
	loginGroup.Use(AuthRequired())
	{
		loginGroup.GET("/info", UserInfo)
	}

	// listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
	err := engine.Run()
	if err != nil {
		panic(err)
	}
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.Request.Header.Get("token")
		claims := jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return mySigningKey, nil
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, fmt.Sprintf("Not Allowed, Reason:%v", err))
			return
		}
		fmt.Fprintf(os.Stdout, "claims: %+v, and token.Valid is %t\n", claims, token.Valid)
	}
}

type LoginReq struct {
	User     string `json:"user" binding:"required"`
	Password string `json:"password,omitempty" binding:"required"`
}

var mySigningKey = []byte("AllYourBase")

// Login for get JWT
func Login(c *gin.Context) {
	// Search the user and password in DB
	var loginInfo LoginReq
	err := c.BindJSON(&loginInfo)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}
	// Create the Claims
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Second)),
		Issuer:    loginInfo.User,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)
	c.JSON(http.StatusOK, ss)
}

func UserInfo(c *gin.Context) {
	c.JSON(http.StatusOK, LoginReq{
		User: "devin",
	})
}
