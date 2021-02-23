package cache

import (
	"fmt"
	"time"

	"project/common/global"
	"project/utils"
	"project/utils/config"

	"github.com/go-redis/redis/v7"
)

// GetUserCache 获取用户缓存
// redis.StringCmd 统一返回格式
func GetUserCache(keys *[]string, userId int) (cacheMap map[string]*redis.StringCmd) {
	// 这是map这种数据结构的初始化分配空间的方法
	cacheMap = make(map[string]*redis.StringCmd, len(*keys))
	// TxPipeline是默认加了multi/exec事务标志，
	// 	  所以我们不需要显示的设置
	// 		Do.("multi")： 标识事务的开始,
	// 		Do.("exec")：  事务的提交(commit)
	//redis在事务的执行中并没有提供回滚操作，它会按顺序执行完队列中的所有命令而不管中间是否有命令出错
	// (当然，执行出错的命令会打印出错信息)，所以一致性没办法保障。
	// Multi/exec能够确保在multi/exec两个语句之间的命令之间没有其他客户端正在执行命令
	pipe := global.Rdb.TxPipeline()
	// 遍历取出缓存中的值存入map中，因为Get方法只接受一个返回值，所以使用spintf方法将两个参数合到一起
	for _, k := range *keys {
		// fmt.Sprintf 字符串拼接操作，支持不同类型转换
		cacheMap[k] = pipe.Get(fmt.Sprintf("%s%d", k, userId))
	}
	// Redis Exec 命令用于执行所有事务块内的命令
	_, _ = pipe.Exec()
	return
}

// SetUserCache 设置用户缓存
// 存储的是用户身份（角色）
// 传入用户id，内容和key
func SetUserCache(userId int, data interface{}, cacheKey string) {
	// 先将其转为string类型
	res, err := utils.StructToJson(data)
	if err != nil {
		return
	}
	// 将数据存入redis。
	global.Rdb.Set(fmt.Sprintf("%s%d", cacheKey, userId), res, time.Duration(config.JwtConfig.Timeout)*time.Second)
}
