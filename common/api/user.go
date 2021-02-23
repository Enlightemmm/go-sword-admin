package api

import (
	"encoding/json"
	"errors"
	"project/app/admin/models"
	"project/app/admin/service"
	"project/common/cache"

	"github.com/gin-gonic/gin"
)

const (
	CtxUserIdAndName = "user"
	CtxUserIDKey     = "user_id"
	CtxUserInfoKey   = "info"
	CtxUserOnline    = "user_online"
)

type UserMessage struct {
	UserId   int
	Username string
}

type UserInfo struct {
	Jobs           *[]models.SysJob
	Roles          *[]models.SysRole
	MenuPermission *[]string
	Dept           *models.SysDept
	DataScopes     *[]int
}

var ErrorUserNotLogin = errors.New("用户未登录")

// GetCurrentUserId 获取当前登录的用户ID
func GetCurrentUserId(c *gin.Context) (userId int, err error) {
	// 从上下文里面获取到当前用户的id
	uid, ok := c.Get(CtxUserIDKey)
	if !ok {
		// 对于这个变量将其放到了最上面，在这里直接引用
		err = ErrorUserNotLogin
		return
	}
	// 将这个空接口类型的uid断言为int类型
	userId, ok = uid.(int)
	if !ok {
		// 如果出错则还是引用上文中的错误。
		err = ErrorUserNotLogin
		return
	}
	return
}

// GetUserMessage 获取当前登录的用户ID和用户名
func GetUserMessage(c *gin.Context) (*UserMessage, error) {
	res, ok := c.Get(CtxUserIdAndName)
	if !ok {
		err := ErrorUserNotLogin
		return nil, err
	}
	userMessage := res.(*UserMessage)
	return userMessage, nil
}

// 获取用户完整信息
func GetUserData(c *gin.Context) (user *UserInfo, err error) {

	// 通过这个方法获取当前登录的用户的id（int类型）
	userId, err := GetCurrentUserId(c)
	if err != nil {
		return
	}
	// 初始化一个string类型的变量
	keys := new([]string)
	// 如果要使用append（）方法则需要先将其从*[]string转为[]string，
	// 然后通过redis获取在cache目录下的定义好的常量（分别表示各部分在缓存中的位置）
	*keys = append(*keys, cache.KeyUserJob, cache.KeyUserRole, cache.KeyUserMenu, cache.KeyUserDept, cache.KeyUserDataScope)
	// 获取用户缓存，传进去一个*[]string和当前的用户id，在这里的第一个参数主要是指上面的五个
	cacheMap := cache.GetUserCache(keys, userId)
	// 获取key对应的值,使用.Result()的原因是取出cacheMap里的*redis.StringCmd的cmd.Val(), cmd.err
	cacheJob, jobErr := cacheMap[cache.KeyUserJob].Result()
	cacheRole, rolesErr := cacheMap[cache.KeyUserRole].Result()
	cacheMenu, menuErr := cacheMap[cache.KeyUserMenu].Result()
	cacheDept, deptErr := cacheMap[cache.KeyUserDept].Result()
	cacheDataScopes, dataScopesErr := cacheMap[cache.KeyUserDataScope].Result()
	// 初始化岗位struct
	jobs := new([]models.SysJob)
	// 获取用户的岗位信息
	if err = service.GetUserJobData(cacheJob, jobErr, jobs, userId); err != nil {
		return nil, err
	}

	// 初始化角色struct
	roles := new([]models.SysRole)
	// 从redis中获取角色信息（如果不存在就去数据库查询）
	if err = service.GetUserRoleData(cacheRole, rolesErr, roles, userId); err != nil {
		return nil, err
	}

	// 初始化用户身份
	menuPermission := new([]string)
	// 获取用户身份
	if err = service.GetUserMenuData(cacheMenu, menuErr, userId, menuPermission, roles); err != nil {
		return nil, err
	}

	// 初始化用户的部门信息
	dept := new(models.SysDept)
	// 查询用户部门信息
	if err = service.GetUserDeptData(cacheDept, deptErr, dept, userId); err != nil {
		return nil, err
	}

	//
	dataScopes := new([]int)
	if err = service.GetUserDataScopes(cacheDataScopes, dataScopesErr, dataScopes, userId, dept.ID, roles); err != nil {
		return nil, err
	}

	user = new(UserInfo)
	user.Jobs = jobs
	user.Roles = roles
	user.MenuPermission = menuPermission
	user.Dept = dept
	user.DataScopes = dataScopes
	return
}

// GetUserOnline 获取用户线上数据
func GetUserOnline(c *gin.Context) (userOnline *models.OnlineUser, err error) {
	res, ok := c.Get(CtxUserOnline)
	if !ok {
		err = ErrorUserNotLogin
		return
	}
	userOnline = new(models.OnlineUser)
	err = json.Unmarshal([]byte(res.(string)), userOnline)
	return
}
