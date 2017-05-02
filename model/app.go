package model

type appmodel struct{
	appid int16
	`type` string
	name string
	url string
	authkey string
	ip string
	viewprourl string
	apifilename string
	charset string
	dbcharset string
	synlogin int8
	recvnote int8
	extra string
	tagtemplates string
	allowips string
}

// var db
// var base

// func (this *appmodel) __construct(&base) {
// 	this->appmodel(base)
// }

// func (this *appmodel) appmodel(&base) {
// 	this->base = base
// 	this->db = base->db
// }

//col = '*', where = ''
func (this *appmodel) get_apps(col, where string) {
	arr = this->db->fetch_all("SELECT col FROM " + UC_DBTABLEPRE + "applications" + (where ? " WHERE " + where : ""), "appid")
	foreach(arr as k => v) {
		isset(v["extra"]) && !empty(v["extra"]) && v["extra"] = unserialize(v["extra"])
		if(tmp = this->base->authcode(v["authkey"], "DECODE", UC_MYKEY)) {
			v["authkey"] = tmp
		}
		arr[k] = v
	}
	return arr
}

//appid, includecert = FALSE
func (this *appmodel) get_app_by_appid(appid int, includecert bool) {
	appid = intval(appid)
	arr = this->db->fetch_first("SELECT * FROM " + UC_DBTABLEPRE + "applications WHERE appid=" + utils.IntToStr(appid)
	arr["extra"] = unserialize(arr["extra"])
	if(tmp = this->base->authcode(arr["authkey"], "DECODE", UC_MYKEY)) {
		arr["authkey"] = tmp
	}
	if includecert {
		this->load("plugin")
		certfile = _ENV["plugin"]->cert_get_file()
		appdata = _ENV["plugin"]->cert_dump_decode(certfile)
		if(is_array(appdata[appid])) {
			arr += appdata[appid]
		}
	}
	return arr
}

func (this *appmodel) delete_apps(appids) {
	strappids := this->base->implode(appids)
	this->db->query("DELETE FROM " + UC_DBTABLEPRE + "applications WHERE appid IN (" + strappids + ")")
	return this->db->affected_rows()
}

//private
//appid, operation = 'ADD'
func (this *appmodel) alter_app_table(appid int, operation string) {
	if(operation == "ADD") {
		this->db->query("ALTER TABLE " + UC_DBTABLEPRE + "notelist ADD COLUMN app" + utils.IntToStr(appid) +" tinyint NOT NULL", "SILENT")
	} else {
		this->db->query("ALTER TABLE " + UC_DBTABLEPRE + "notelist DROP COLUMN app" + utils.IntToStr(appid), "SILENT")
	}
}

//url, ip = ""
func (this *appmodel) test_api(url, ip string) bool{
	this->base->load("misc")
	if(!ip) {
		ip = _ENV["misc"]->get_host_by_url(url)
	}

	if(ip < 0) {
		return false
	}
	return _ENV["misc"]->dfopen(url, 0, "", "", 1, ip)
}
