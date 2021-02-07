package service

import (
	"encoding/json"
	"fmt"
	"io"
	appcache "project/app/admin/models/cache"
	"project/common/cache"
	"project/pkg/jwt"
	"project/utils/config"

	"strconv"
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
		return nil, err
	}

	jobs := new([]models.SysJob)
	if err = GetUserJobData(jobs, user.ID); err != nil {
		return nil, err
	}

	roles := new([]models.SysRole)
	if err = GetUserRoleData(roles, user.ID); err != nil {
		return nil, err
	}

	menuPermission := new([]string)
	if err = GetUserMenuData(user.ID, menuPermission, roles); err != nil {
		return nil, err
	}

	dept := new(models.SysDept)
	if err = GetUserDeptData(dept, user.ID); err != nil {
		return nil, err
	}

	dataScopes := new([]int)
	if err = GetUserDataScopes(dataScopes, user.ID, dept.ID, roles); err != nil {
		return nil, err
	}

	token, err := jwt.GenToken(user.ID, user.Username)
	if err != nil {
		return nil, err
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
func GetUserJobData(jobs *[]models.SysJob, userId int) (err error) {
	cacheJob, err := cache.GetUserCache(userId, cache.KeyUserJob)
	if err != nil {
		err = models.GetUserJob(jobs, userId)
		if err != nil {
			return
		}
		cache.SetUserCache(userId, jobs, cache.KeyUserJob)

	} else {
		err = utils.JsonToStruct(cacheJob, jobs)
	}
	return
}

// GetUserRoleData 获取用户角色数据
func GetUserRoleData(roles *[]models.SysRole, userId int) (err error) {
	cacheRole, err := cache.GetUserCache(userId, cache.KeyUserRole)
	if err != nil {
		err = models.GetUserRole(roles, userId)
		if err != nil {
			return
		}
		cache.SetUserCache(userId, roles, cache.KeyUserRole)
	} else {
		err = utils.JsonToStruct(cacheRole, roles)
	}
	return
}

// GetUserMenuData 获取用户菜单权限
func GetUserMenuData(userId int, menuPermission *[]string, roles *[]models.SysRole) (err error) {
	cacheMenu, err := cache.GetUserCache(userId, cache.KeyUserMenu)
	if err != nil {
		a := new(models.Admin)
		if err = a.GetIsAdmin(userId); err != nil {
			return
		}

		if utils.ByteIntoInt(a.IsAdmin) == 1 {
			*menuPermission = []string{`admin`}
			cache.SetUserCache(userId, menuPermission, cache.KeyUserMenu)
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
			cache.SetUserCache(userId, menus, cache.KeyUserMenu)
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
func GetUserDeptData(dept *models.SysDept, userId int) (err error) {
	cacheDept, err := cache.GetUserCache(userId, cache.KeyUserDept)
	if err != nil {
		err = models.SelectUserDept(dept, userId)
		if err != nil {
			return
		}
		cache.SetUserCache(userId, dept, cache.KeyUserDept)
	} else {
		err = utils.JsonToStruct(cacheDept, dept)
	}
	return
}

// GetUserDataScopes 获取用户数据权限
func GetUserDataScopes(dataScopes *[]int, userId int, deptId int, roles *[]models.SysRole) error {
	cacheDataScopes, err := cache.GetUserCache(userId, cache.KeyUserDataScope)
	if err != nil {
		err = nil
		var dataScopesRoleIds []int
		var allScopes bool
		for _, role := range *roles {
			switch role.DataScope {
			case `全部`:
				allScopes = true
				*dataScopes = []int{}
				break
			case `本级`:
				*dataScopes = append(*dataScopes, deptId)
			default:
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
		cache.SetUserCache(userId, dataScopes, cache.KeyUserDataScope)
	} else {
		err = utils.JsonToStruct(cacheDataScopes, dataScopes)
		if err != nil {
			return err
		}
	}
	return err
}

func (u *User) RedisUserMessage(c *gin.Context, l *bo.LoginData, token string) (err error) {
	//构造角色名字集合
	roleNames := make([]string, 0)
	for _, v := range l.User.User.Role {
		roleNames = append(roleNames, v.Name)
	}
	//初始化缓存模型
	var userInfo []byte
	userInfo, err = json.Marshal(models.RedisUserInfo{
		UserId:   l.User.User.Id,
		UserName: l.User.User.Username,
		DeptId:   l.User.User.DeptId,
		Role:     roleNames,
	})

	if err != nil {
		zap.L().Error("RedisUserInfo Marshal failed", zap.Error(err))
		return
	}

	//添加缓存
	if err := global.Rdb.Set(strconv.Itoa(l.User.User.Id), userInfo, 0).Err(); err != nil {
		zap.L().Error("用户缓存错误", zap.Error(err))
		return err
	}

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
		Enabled:      utils.StrBoolIntoByte(p.Enabled),
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

func (u *User) SelectUserInfoList(p *dto.SelectUserInfoArrayDto) (data *bo.UserInfoListBo, err error) {
	user := new(models.SysUser)
	data, err = user.SelectUserInfoList(p)
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

func (u *User) SelectUserInfo(p *models.RedisUserInfo) (data *bo.UserCenterInfoBo, err error) {
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
	err = appcache.SetUserCenterListCache(data)
	if err != nil {
		zap.L().Error("SetUserCenterListCache failed", zap.Error(err))
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
