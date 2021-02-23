package middleware

import (
	"net/http"
	"project/common/api"
	mycasbin "project/pkg/casbin"
	"project/utils"

	"github.com/gin-gonic/gin"
)

//权限检查中间件
func AuthCheckRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 这个结构体包含了一个用户所有信息
		data := new(api.UserInfo)
		// 定义一个string类型的切片用来保存用户的所有角色
		var role []string
		var err error
		// 获取到用户的所有信息：先去缓存中查，如果存在则将其从string转为struct，要不就去数据库中查找
		userInfo, err := api.GetUserData(c)
		// 将userInfo的值赋给data
		data = userInfo
		// 只取出该用户的角色信息
		roles := data.Roles
		// 一一遍历
		for _, v := range *roles {
			// 取出角色id存入上文定义的role
			role = append(role, utils.IntToString(v.ID))
		}
		if err != nil {
			c.Abort()
			return
		}
		// 这里加载配置
		e, err := mycasbin.LoadPolicy()
		if err != nil {
			c.Abort()
			return
		}
		//检查权限
		//此处为多角色 要在做处理
		var res bool
		res, err = e.Enforce(role, c.Request.URL.Path, c.Request.Method)
		if err != nil {
			c.Abort()
			return
		}

		if res {
			c.Next()
		} else {
			c.JSON(http.StatusOK, gin.H{
				"code": 403,
				"msg":  "对不起，您没有该接口访问权限，请联系管理员",
			})
			c.Abort()
			return
		}
	}
}
