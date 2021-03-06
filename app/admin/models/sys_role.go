package models

import (
	"project/app/admin/models/bo"
	"project/app/admin/models/dto"
	"project/utils"
	"strconv"

	orm "project/common/global"
)

type SysRole struct {
	ID           int    `gorm:"primary_key" json:"id"`                  //ID
	Name         string `json:"name"`                                   //角色名称
	Level        int    `json:"level"`                                  //角色级别（越小越大）
	Description  string `json:"description"`                            //描述
	DataScope    string `json:"data_scope"`                             //数据权限
	IsProtection []byte `json:"is_protection" gorm:"default:[]byte{0}"` //是否受保护（内置角色，1为内置角色，默认值为0）
	CreateBy     int    `json:"create_by" gorm:"autoCreateTime:milli"`  //创建者id
	UpdateBy     int    `json:"update_by" gorm:"autoCreateTime:milli"`  //更新者id
	CreateTime   int64  `json:"create_time"`                            //创建日期
	UpdateTime   int64  `json:"update_time"`                            //更新时间
	IsDeleted    []byte `json:"is_deleted"`                             //软删除（默认值为0，1为删除）
}

func (e SysRole) RoleAllNum() (num int64) {
	if err := orm.Eloquent.Table("sys_role").Where("is_deleted=0").Count(&num).Error; err != nil {
		return
	}
	return
}

// 多条件查询角色
func (e SysRole) SelectRoles(p dto.SelectRoleArrayDto, orderData []bo.Order) (sysRole []SysRole, err error) {
	var order string
	for key, value := range orderData {
		order += value.Column + " "
		if value.Asc == "true" {
			if key == len(orderData)-1 {
				order += "asc "
			} else {
				order += "asc, "
			}
		} else {
			if key == len(orderData)-1 {
				order += "desc "
			} else {
				order += "desc, "
			}
		}
	}

	// 查询
	if p.Blurry != "" && p.StartTime == "" {
		// 查询Blurry
		err = orm.Eloquent.Where("name like ? or description like ? and is_deleted=0",
			"%"+p.Blurry+"%", "%"+p.Blurry+"%").
			Limit(p.Size).Offset((p.Current - 1) * p.Size).Order(order).Find(&sysRole).Error
		return
	}
	if p.Blurry == "" && p.StartTime != "" {
		// 查询Time
		startTime, err1 := strconv.ParseInt(p.StartTime, 10, 64)
		if err1 != nil {
			err = err1
			return
		}
		endTime, err1 := strconv.ParseInt(p.EndTime, 10, 64)
		if err1 != nil {
			err = err1
			return
		}
		err = orm.Eloquent.Where("create_time >= ? and create_time <= ? and is_deleted=0", startTime, endTime).
			Limit(p.Size).Offset((p.Current - 1) * p.Size).Order(order).Find(&sysRole).Error
		return
	}
	if p.Blurry != "" && p.StartTime != "" {
		// 查询All
		startTime, err1 := strconv.ParseInt(p.StartTime, 10, 64)
		if err1 != nil {
			err = err1
			return
		}
		endTime, err1 := strconv.ParseInt(p.EndTime, 10, 64)
		if err1 != nil {
			err = err1
			return
		}
		err = orm.Eloquent.Where("name like ? or description like ? and create_time >= ? and create_time <= ?  and is_deleted=0",
			"%"+p.Blurry+"%", "%"+p.Blurry+"%", startTime, endTime).
			Limit(p.Size).Offset((p.Current - 1) * p.Size).Order(order).Find(&sysRole).Error
		return
	}
	if err = orm.Eloquent.Where("is_deleted=0").Limit(p.Size).Offset((p.Current - 1) * p.Size).Order(order).Find(&sysRole).Error; err != nil {
		return
	}
	return
}

// 查询Dept Menu
func (e SysRole) SysDeptAndMenu(id int) (sysDept []SysDept, sysMenu []SysMenu, err error) {
	// 查询Dept
	if err = orm.Eloquent.Where("id = any(?)", orm.Eloquent.Table("sys_roles_depts").Select("dept_id").
		Where("role_id = ?", id)).Find(&sysDept).Error; err != nil {
		return
	}
	// 查询Menu
	if err = orm.Eloquent.Where("id = any(?)", orm.Eloquent.Table("sys_roles_menus").Select("menu_id").
		Where("role_id = ?", id)).Find(&sysMenu).Error; err != nil {
		return
	}
	return
}

// 新建角色
func (e SysRole) InsertRole(deptsData []int) (err error) {
	tx := orm.Eloquent.Begin()
	e.IsProtection = append(e.IsProtection, 1)
	e.CreateTime = utils.GetCurrentTimeUnix()
	e.UpdateTime = utils.GetCurrentTimeUnix()
	e.IsDeleted = append(e.IsDeleted, 0)
	result := tx.Create(&e)
	if err = result.Error; err != nil {
		tx.Rollback()
		return
	}
	for _, deptValue := range deptsData {
		var sysRoleDept SysRolesDepts
		sysRoleDept.RoleId = e.ID
		sysRoleDept.DeptId = deptValue
		if err = tx.Create(&sysRoleDept).Error; err != nil {
			tx.Rollback()
			return
		}
	}
	tx.Commit()
	return
}

// 修改角色
func (e SysRole) UpdateRole(deptsData []int, menusData []int) (err error) {
	tx := orm.Eloquent.Begin()
	e.UpdateTime = utils.GetCurrentTimeUnix()
	// 修改sysrole表
	if err = tx.Model(&e).Updates(e).Error; err != nil {
		tx.Rollback()
		return
	}
	// 修改sys_rols_depts表
	if err = tx.Delete(SysRolesDepts{}, "role_id = ?", e.ID).Error; err != nil {
		tx.Rollback()
		return
	}
	for _, deptsNum := range deptsData {
		var sysRoleDept SysRolesDepts
		sysRoleDept.RoleId = e.ID
		sysRoleDept.DeptId = deptsNum
		if err = tx.Create(&sysRoleDept).Error; err != nil {
			tx.Rollback()
			return
		}
	}
	tx.Commit()
	return
}

// 删除角色
func (e SysRole) DeleteRole(p []int) (err error) {
	for _, values := range p {
		err = orm.Eloquent.Table("sys_role").Where("id = ?", values).Updates(SysRole{UpdateBy: e.ID, IsDeleted: []byte{1}}).Error
	}
	return
}

// 修改角色菜单
func (e SysRole) UpdateRoleMenu(id int, p []int) (err error) {
	tx := orm.Eloquent.Begin()
	var sysRoleMenus SysRolesMenus
	tx.Where("role_id = ?", id).Delete(&sysRoleMenus)
	for _, menuID := range p {
		var sysRoleMenus SysRolesMenus
		sysRoleMenus.RoleId = id
		sysRoleMenus.MenuId = menuID
		results := tx.Table("sys_roles_menus").Create(&sysRoleMenus)
		if results.Error != nil {
			tx.Rollback()
			return results.Error
		}
	}
	tx.Commit()
	return
}

// 查询单个角色
func (e SysRole) SelectRoleOne() (role SysRole, err error) {
	err = orm.Eloquent.First(&role, e.ID).Error
	return
}

// 查询所有角色
func (e SysRole) SelectRoleAll() (roleAll []bo.RecordRole, err error) {
	var sysRoleAll []SysRole
	if err = orm.Eloquent.Find(&sysRoleAll).Error; err != nil {
		return
	}
	for _, roleID := range sysRoleAll {
		var menuIDAll []SysRolesMenus
		// 格式化角色数据
		var roleDate bo.RecordRole
		// 格式化Menu数据
		var menuData bo.Menu
		orm.Eloquent.Where("role_id = ?", roleID.ID).Find(&menuIDAll)
		for _, menuID := range menuIDAll {
			var sysMenu SysMenu
			orm.Eloquent.Where(map[string]interface{}{"id": menuID.MenuId}).First(&sysMenu)
			if sysMenu.Cache[0] == 1 {
				menuData.Cache = true
			} else {
				menuData.Cache = false
			}
			menuData.Component = sysMenu.Component
			menuData.CreateBy = sysMenu.CreateBy
			menuData.CreateTime = sysMenu.CreateTime
			if sysMenu.Hidden[0] == 1 {
				menuData.Hidden = true
			} else {
				menuData.Hidden = false
			}
			menuData.Icon = sysMenu.Icon
			menuData.ID = sysMenu.ID
			if sysMenu.IFrame[0] == 1 {
				menuData.Iframe = true
			} else {
				menuData.Iframe = false
			}
			menuData.Label = sysMenu.Title
			menuData.Leaf = false
			menuData.MenuSort = sysMenu.MenuSort
			menuData.Name = sysMenu.Name
			menuData.Path = sysMenu.Path
			menuData.Permission = sysMenu.Permission
			menuData.Pid = sysMenu.Pid
			menuData.SubCount = sysMenu.SubCount
			menuData.Title = sysMenu.Title
			menuData.Type = sysMenu.Type
			menuData.UpdateTime = sysMenu.UpdateTime
			menuData.UpdateBy = sysMenu.UpdateBy
			roleDate.Menus = append(roleDate.Menus, menuData)
		}
		roleDate.CreateBy = roleID.CreateBy
		roleDate.ID = roleID.ID
		roleDate.Level = roleID.Level
		roleDate.UpdateBy = roleID.UpdateBy
		roleDate.CreateTime = roleID.CreateTime
		roleDate.DataScope = roleID.DataScope
		roleDate.Description = roleID.Description
		roleDate.Name = roleID.Name
		roleDate.UpdateTime = roleID.UpdateTime
		if roleID.IsProtection[0] == 1 {
			roleDate.Protection = true
		} else {
			roleDate.Protection = false
		}
		roleAll = append(roleAll, roleDate)
	}
	return
}

func (e SysRole) SelectRoleLevel(roleName []string) (level bo.SelectCurrentUserLevel, err error) {
	for _, values := range roleName {
		var role SysRole
		err = orm.Eloquent.Where("name = ?", values).First(&role).Error
		if err != nil {
			return
		}
		if level.Level > role.Level {
			level.Level = role.Level
		}
	}
	if level.Level == 0 {
		level.Level = 1
	}
	return
}
