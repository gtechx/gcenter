package config

import(
	"fmt"
)

type Config struct{
	appname string
	httpport int
	runmode string
	UC_DBHOST string
	UC_DBUSER string
	UC_DBPW string
	UC_DBNAME string
	UC_DBCHARSET string
	UC_DBTABLEPRE string
	UC_COOKIEPATH string
	UC_COOKIEDOMAIN string
	UC_DBCONNECT int
	UC_CHARSET string
	UC_FOUNDERPW string
	UC_FOUNDERSALT string
	UC_KEY string
	UC_SITEID string
	UC_MYKEY string
	UC_DEBUG int
	UC_PPP int
}

var HTTP_CLIENT_IP string
var HTTP_X_FORWARDED_FOR string
var REMOTE_ADDR string

func Init(){
	fmt.Println("Initing...")
}