package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"jwt/model"
	"jwt/utils"
)

func Login(c *gin.Context) {
	var user model.User
	secret := c.Request.Header.Get("secret")
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "Invalid request", "result": nil})
		return
	}
	fmt.Println("Received user:", user)
	if user.Username != "csa" || user.Password != "123456" {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Unauthorized", "result": nil})
		return
	}
	token := utils.GenerateJWT(user, secret)
	c.JSON(http.StatusOK, gin.H{"code": 200, "message": "success", "result": token})
}
