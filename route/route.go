package route

import (
	"github.com/gin-gonic/gin"
	"jwt/api"
	"jwt/utils"
)

func SetupRouter() {
	r := gin.Default()
	r.POST("/login", api.Login)
	r.Use(utils.JWTAuthMiddleware())
	r.GET("/validatetoken", api.ValidateToken)
	r.GET("/getfromtoken", api.Getfromtoken)
	r.Run(":8088")
}
