package dto

//GetJobList 岗位列表数据入参
type GetJobList struct {
	EndTime   int    `form:"endTime"`                    //结束时间
	StartTime int    `form:"startTime"`                  //创建时间
	Size      int    `form:"size" binding:"required"`    //每页数据
	Current   int    `form:"current" binding:"required"` //当前页
	Name      string `form:"name"`                       //模糊查询
	Orders    string `form:"orders" binding:"required"`  //排序规则
}

type AddJob struct {
	ID      int    `json:"id"`                         //ID
	JobSort int    `json:"jobSort" binding:"required"` //排序
	Name    string `json:"name" binding:"required"`    //岗位名称
	Enabled bool   `json:"enabled" binding:"required"` //岗位状态
}

type UpdateJob struct {
	ID      int    `json:"id"`                         //ID
	JobSort int    `json:"jobSort" binding:"required"` //排序
	Enabled uint8  `json:"enabled" binding:"required"` //岗位状态
	Name    string `json:"name" binding:"required"`    //岗位名称
}
