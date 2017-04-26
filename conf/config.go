package config

import(
	"fmt"
)

var HTTP_CLIENT_IP string
var HTTP_X_FORWARDED_FOR string
var REMOTE_ADDR string

func Init(){
	fmt.Println("Initing...")
}