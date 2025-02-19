package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"jwt/utils"
)

func ValidateToken(c *gin.Context) {
	//表头获取token
	token := c.Request.Header.Get("Authorization")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "Token missing"})
		return
	}
	//密钥
	parts := strings.SplitN(token, " ", 2)
	claims, err := utils.ValidateToken(parts[1], "dech53")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid token", "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 200, "message": "Token is valid", "user": claims.User})
}
