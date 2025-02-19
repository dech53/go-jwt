package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func Getfromtoken(c *gin.Context) {
	username, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{"code": 200, "message": username})
}
