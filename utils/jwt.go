package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"jwt/model"
	"net/http"
	"strings"
	"time"
)

type JWTClaims struct {
	User    string `json:"username"`
	Expires int64  `json:"exp"`
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func decodeBase64(data string) []byte {
	Data, _ := base64.StdEncoding.DecodeString(data)
	return Data
}

func Signature(unsignedToken, secret string) string {
	return encodeBase64([]byte(unsignedToken + secret))
}

func GenerateJWT(user model.User, secret string) string {
	//加密header
	header := encodeBase64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	//结构体创建claims
	claims := JWTClaims{
		User:    user.Username,
		Expires: time.Now().Add(time.Hour * 1).Unix(),
	}
	claimsJson, err := json.Marshal(claims)
	if err != nil {
		println(err.Error())
		return ""
	}
	playload := encodeBase64(claimsJson)
	unsignedToke := header + "." + playload
	signature := Signature(unsignedToke, secret)
	token := unsignedToke + "." + signature
	return token
}

func ValidateToken(token, secret string) (*JWTClaims, error) {
	//通过密钥解密验证token是否正确
	parts := strings.Split(token, ".")
	var claims JWTClaims
	if len(parts) != 3 {
		return nil, fmt.Errorf("Token格式错误")
	}
	unsignedToke := parts[0] + "." + parts[1]
	expectedSignature := Signature(unsignedToke, secret)
	if parts[2] != expectedSignature {
		return nil, fmt.Errorf("Token不正确")
	}
	payload := decodeBase64(parts[1])
	err := json.Unmarshal(payload, &claims)
	if err != nil {
		println(err.Error())
	}
	if claims.Expires < time.Now().Unix() {
		return nil, fmt.Errorf("Token过期")
	}
	fmt.Println("校验成功")
	return &claims, err
}

func ParseToken(token, secret string) (*JWTClaims, error) {
	return ValidateToken(token, secret)
}

func JWTAuthMiddleware() func(c *gin.Context) {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		secret := c.Request.Header.Get("secret")
		fmt.Println("Authorization Header:", authHeader)
		fmt.Println("Secret Header:", secret)
		if authHeader == "" {
			c.JSON(http.StatusOK, gin.H{
				"code": 2003,
				"msg":  "请求头中auth为空",
			})
			c.Abort()
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.JSON(http.StatusOK, gin.H{
				"code": 2004,
				"msg":  "请求头中auth格式有误",
			})
			c.Abort()
			return
		}
		mc, err := ParseToken(parts[1], secret)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 2005,
				"msg":  "无效的Token",
			})
			c.Abort()
			return
		}
		c.Set("username", mc.User)
		c.Next()
	}
}
