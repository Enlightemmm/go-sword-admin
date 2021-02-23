package service

import (
	"encoding/json"
	"fmt"
	"io"
	appcache "project/app/admin/models/cache"
	"project/common/cache"
	"project/pkg/jwt"
	"project/utils/config"
	"time"

	"project/app/admin/models"
	"project/app/admin/models/bo"
	"project/app/admin/models/dto"
	"project/common/global"
	"project/utils"

	"github.com/gin-gonic/gin"
	"github.com/mssola/user_agent"
	"go.uber.org/zap"
)

type User struct {
}

// Login 返回json web token
func (u *User) Login(c *gin.Context, p *dto.UserLoginDto) (data *bo.LoginData, err error) {
	user := new(models.SysUser)
	user.Username = p.Username

	user.Password = p.Password
	if err = user.Login(); err != nil {
		return
	}

	keys := new([]string)
	*keys = append(*keys, cache.KeyUserJob, cache.KeyUserRole, cache.KeyUserMenu, cache.KeyUserDept, cache.KeyUserDataScope)
	cacheMap := cache.GetUserCache(keys, user.ID)

	cacheJob, jobErr := cacheMap[cache.KeyUserJob].Result()
	cacheRole, rolesErr := cacheMap[cache.KeyUserRole].Result()
	cacheMenu, menuErr := cacheMap[cache.KeyUserMenu].Result()
	cacheDept, deptErr := cacheMap[cache.KeyUserDept].Result()
	cacheDataScopes, dataScopesErr := cacheMap[cache.KeyUserDataScope].Result()

	jobs := new([]models.SysJob)
	if err = GetUserJobData(cacheJob, jobErr, jobs, user.ID); err != nil {
		return
	}

	roles := new([]models.SysRole)
	if err = GetUserRoleData(cacheRole, rolesErr, roles, user.ID); err != nil {
		return
	}

	menuPermission := new([]string)
	if err = GetUserMenuData(cacheMenu, menuErr, user.ID, menuPermission, roles); err != nil {
		return
	}

	dept := new(models.SysDept)
	if err = GetUserDeptData(cacheDept, deptErr, dept, user.ID); err != nil {
		return
	}

	dataScopes := new([]int)
	if err = GetUserDataScopes(cacheDataScopes, dataScopesErr, dataScopes, user.ID, dept.ID, roles); err != nil {
		return
	}

	token, err := jwt.GenToken(user.ID, user.Username)
	if err != nil {
		return
	}

	var jobMessage []*bo.Job
	for _, job := range *jobs {
		jobMessage = append(jobMessage, &bo.Job{
			ID:   job.ID,
			Name: job.Name,
		})
	}
	var roleMessage []*bo.Role
	for _, role := range *roles {
		roleMessage = append(roleMessage, &bo.Role{
			ID:        role.ID,
			Level:     role.Level,
			Name:      role.Name,
			DataScope: role.DataScope,
		})
	}
	deptMessage := new(bo.DeptCommon)
	deptMessage.ID = dept.ID
	deptMessage.Name = dept.Name

	data = new(bo.LoginData)
	loginUser := new(bo.LoginUser)
	recordUser := new(bo.RecordUser)
	recordUserHalf := new(bo.RecordUserHalf)
	roleDeptJobBool := new(bo.RoleDeptJobBool)
	recordUserHalf.Id = user.ID
	recordUserHalf.DeptId = user.DeptId
	recordUserHalf.CreateBy = user.CreateBy
	recordUserHalf.UpdateBy = user.UpdateBy
	recordUserHalf.PwdResetTime = user.PwdResetTime
	recordUserHalf.CreateTime = user.CreateTime
	recordUserHalf.UpdateTime = user.UpdateTime
	recordUserHalf.AvatarName = user.Avatar
	recordUserHalf.AvatarPath = user.AvatarPath
	recordUserHalf.Email = user.Email
	recordUserHalf.NickName = user.NickName
	recordUserHalf.Phone = user.Phone
	recordUserHalf.Username = user.Username
	recordUser.RecordUserHalf = recordUserHalf

	roleDeptJobBool.Enabled = utils.ByteIntoBool(user.Enabled)
	roleDeptJobBool.Gender = utils.ByteIntoBool(user.Gender)
	roleDeptJobBool.Jobs = jobMessage
	roleDeptJobBool.Role = roleMessage
	roleDeptJobBool.Dept = deptMessage
	recordUser.RoleDeptJobBool = roleDeptJobBool

	loginUser.User = recordUser
	loginUser.DataScopes = *dataScopes
	loginUser.Roles = *menuPermission

	data.User = loginUser
	data.Token = "Bearer " + token

	err = u.RedisUserMessage(c, data, token)
	return
}

// GetUserJobData 获取用户岗位数据
func GetUserJobData(cacheJob string, jobErr error, jobs *[]models.SysJob, userId int) (err error) {
	if jobErr != nil {
		// 这个错误是查询缓存时捎带的，如果出现错误则去数据库查询
		err = models.GetUserJob(jobs, userId)
		if err != nil {
			return
		}
		// 将从数据库查询到的信息通过一个goroutine存到redis中
		go cache.SetUserCache(userId, jobs, cache.KeyUserJob)

	} else {
		// 将从redis中取出的string类型的数据转为struct类型
		err = utils.JsonToStruct(cacheJob, jobs)
	}
	return
}

// GetUserRoleData 获取用户角色数据
func GetUserRoleData(cacheRole string, rolesErr error, roles *[]models.SysRole, userId int) (err error) {
	if rolesErr != nil {
		// 如果查询redis时出现错误（包括没有查找到）则从数据库取出数据
		err = models.GetUserRole(roles, userId)
		if err != nil {
			return
		}
		// 开启一个goroutine将数据存到redis里
		go cache.SetUserCache(userId, roles, cache.KeyUserRole)
	} else {
		// 如果没有出错则将从redis中获取到的string转换成struct
		err = utils.JsonToStruct(cacheRole, roles)
	}
	return
}

// GetUserMenuData
func GetUserMenuData(cacheMenu string, menuErr error, userId int, menuPermission *[]string, roles *[]models.SysRole) (err error) {
	*menuPermission = []string{}
	if menuErr != nil {
		// 如果从redis拿的时候有错误，则先初始化下面这个结构体（判断是否是管理者）
		a := new(models.Admin)
		// 因为redis中没有所以要来mysql中查询
		if err = a.GetIsAdmin(userId); err != nil {
			return
		}
		// 先将其转为int型
		// 如果是则在最终的结构体中存入admin
		if utils.ByteIntoInt(a.IsAdmin) == 1 {
			*menuPermission = []string{`admin`}
			// 同时起一个goroutine将用户id，是否管理和key传入
			go cache.SetUserCache(userId, menuPermission, cache.KeyUserMenu)
		} else {
			menus := new([]models.SysMenu)
			if err = models.SelectUserMenuPermission(menus, roles); err != nil {
				return
			}
			for _, menu := range *menus {
				if menu.Permission != "" {
					*menuPermission = append(*menuPermission, menu.Permission)
				}
			}
			go cache.SetUserCache(userId, menus, cache.KeyUserMenu)
		}
	} else {
		if cacheMenu == `["admin"]` {
			*menuPermission = []string{`admin`}
		} else {
			menus := new([]models.SysMenu)
			if err = utils.JsonToStruct(cacheMenu, menus); err != nil {
				return
			}
			for _, menu := range *menus {
				if menu.Permission != "" {
					*menuPermission = append(*menuPermission, menu.Permission)
				}
			}
		}
	}
	return
}

// GetUserDeptData 获取用户部门数据
func GetUserDeptData(cacheDept string, deptErr error, dept *models.SysDept, userId int) (err error) {
	if deptErr != nil {
		// 如果从redis中查的时候没有查找则到mysql中查询
		err = models.SelectUserDept(dept, userId)
		if err != nil {
			return
		}
		// 开一个goroutine将信息存入redis
		go cache.SetUserCache(userId, dept, cache.KeyUserDept)
	} else {
		err = utils.JsonToStruct(cacheDept, dept)
	}
	return
}

// GetUserDataScopes 获取用户数据权限
func GetUserDataScopes(cacheDataScopes string, dataScopesErr error, dataScopes *[]int, userId int, deptId int, roles *[]models.SysRole) (err error) {
	// 如果在redis中没有查找到
	if dataScopesErr != nil {
		// 定义一个[]int
		var dataScopesRoleIds []int
		// 声明的时候为默认值false
		var allScopes bool
		// 遍历从redis或mysql中获取到的[]models.SysRole，取出每一项
		// 从这里可以看出struct也是可以遍历的
		for _, role := range *roles {
			// 这里只判断其中的DataScope
			switch role.DataScope {
			case `全部`:
				// 如果data_scope字段为全部，则allScopes为true
				allScopes = true

				*dataScopes = []int{}
				break
			case `本级`:
				// 如果是本级则将部门id存入该切片
				*dataScopes = append(*dataScopes, deptId)
			default:
				// 如果是其他则将用户id存入该切片
				dataScopesRoleIds = append(dataScopesRoleIds, role.ID)
			}
		}

		if !allScopes {
			deptIds, err := models.SelectUserDeptIdByRoleId(dataScopesRoleIds)
			if err != nil {
				return err
			}
			*dataScopes = append(*dataScopes, deptIds...)
		}
		go cache.SetUserCache(userId, dataScopes, cache.KeyUserDataScope)
	} else {
		err = utils.JsonToStruct(cacheDataScopes, dataScopes)
	}
	return err
}

func (u *User) RedisUserMessage(c *gin.Context, l *bo.LoginData, token string) (err error) {
	online := new(models.OnlineUser)
	ua := user_agent.New(c.Request.UserAgent())
	browserName, browserVersion := ua.Browser()
	online.LoginTime = utils.NowUnix()
	online.LoginLocation = utils.GetLocation(c.ClientIP())
	online.Browser = browserName + " " + browserVersion
	online.Dept = l.User.User.Dept.Name
	online.Ip = c.ClientIP()
	online.Nickname = l.User.User.NickName
	online.Username = l.User.User.Username
	online.Token = token
	userOnline, err := json.Marshal(online)
	if err != nil {
		zap.L().Error("RedisUserOnline Marshal failed", zap.Error(err))
		return
	}

	//添加缓存
	if err = global.Rdb.Set(fmt.Sprintf("%s%s%s", config.JwtConfig.RedisHeader, "-", token), userOnline, time.Second*time.Duration(config.JwtConfig.Timeout)).Err(); err != nil {
		zap.L().Error("用户缓存错误", zap.Error(err))
		return
	}
	return
}

func (u *User) InsertUser(p *dto.InsertUserDto, userID int) (err error) {
	//设置默认密码123456
	defaultPass := "123456"
	pass := utils.EncodeMD5(defaultPass)
	//初始化 user数据
	user := &models.SysUser{
		DeptId:       p.DeptId,
		Email:        p.Email,
		NickName:     p.NickName,
		Phone:        utils.Int64ToString(p.Phone),
		Username:     p.UserName,
		Enabled:      []byte{1},
		Gender:       utils.StrBoolIntoByte(p.Gender),
		CreateBy:     userID,
		UpdateBy:     userID,
		IsAdmin:      []byte{0},
		Password:     pass,
		PwdResetTime: utils.GetCurrentTimeUnix(),
	}
	jobs := p.Jobs
	roles := p.Roles

	if err := user.InsertUser(jobs, roles); err != nil {
		return err
	}
	return nil
}

func (u *User) SelectUserInfoList(p *dto.SelectUserInfoArrayDto, currentUser *models.ModelUserMessage) (data *bo.UserInfoListBo, err error) {
	user := new(models.SysUser)
	data, err = user.SelectUserInfoList(p, currentUser)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (u *User) DeleteUser(ids []int) error {
	user := new(models.SysUser)
	return user.DeleteUser(ids)
}

func (u *User) UpdateUser(p *dto.UpdateUserDto, optionId int) error {
	user := new(models.SysUser)
	return user.UpdateUser(p, optionId)
}

func (u *User) UpdateUserCenter(p *dto.UpdateUserCenterDto, optionId int) (err error) {
	user := new(models.SysUser)
	return user.UpdateUserCenter(p, optionId)
}

func (u *User) SelectUserInfo(p *models.ModelUserMessage) (data *bo.UserCenterInfoBo, err error) {
	//读取缓存
	if data, err = appcache.GetUserCenterCache(p.UserId); err != nil && data != nil {
		return data, nil
	}
	user := new(models.SysUser)
	data, err = user.SelectUserInfo(p)
	if err != nil {
		return nil, err
	}
	//	redis缓存
	err = appcache.SetUserCenterInfoCache(data)
	if err != nil {
		zap.L().Error("SetUserCenterInfoCache failed", zap.Error(err))
	}
	return data, nil
}

func (u *User) UpdatePassWord(p *dto.UpdateUserPassDto, optionId int) (err error) {
	user := new(models.SysUser)
	return user.UpdatePassWord(p, optionId)
}

func (u *User) UpdateAvatar(path string, userId int) (err error) {
	user := new(models.SysUser)
	return user.UpdateAvatar(path, userId)
}

func (u *User) UserDownload(p *dto.DownloadUserInfoDto) (content io.ReadSeeker, err error) {
	user := new(models.SysUser)
	var downloadUsers []interface{}
	userList, err := user.UserDownload(p)
	if err != nil {
		return nil, err
	}
	//数据整合
	recordUsers := userList.Records
	for _, v := range recordUsers {
		jobs := ""
		roles := ""
		for k, job := range v.Jobs {
			if k != len(v.Jobs)-1 {
				jobs += job.Name + ","
			} else {
				jobs += job.Name
			}
		}
		for k, role := range v.Role {
			if k != len(v.Role)-1 {
				roles += role.Name + ","
			} else {
				roles += role.Name
			}
		}
		tmp := &bo.DownloadUserBo{
			Username:     v.Username,
			Dept:         v.Dept.Name,
			Jobs:         jobs,
			Role:         roles,
			Email:        v.Email,
			Phone:        v.Phone,
			PwdResetTime: utils.UnixTimeToString(v.PwdResetTime),
			CreateTime:   utils.UnixTimeToString(v.CreateTime),
		}
		if v.Enabled {
			tmp.Enabled = "启用"
		} else {
			tmp.Enabled = "未启用"
		}
		downloadUsers = append(downloadUsers, tmp)
	}
	content = utils.ToExcel([]string{"用户名", "角色", "部门", "岗位", "邮箱", "状态", "手机号码", "修改密码的时间", "创建日期"}, downloadUsers)
	return
}
