package utils

import "encoding/json"

//传进来一个空接口，意思是接收各种结构体
func StructToJson(value interface{}) (res string, err error) {
	// 将结构体转为[]byte
	bytes, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	// []byte可以直接转为string
	return string(bytes), nil
}

// 将第一个string类型的参数存储在value中
func JsonToStruct(data string, value interface{}) error {
	// 先将string类型的值转为[]byte类型
	return json.Unmarshal([]byte(data), value)
}
