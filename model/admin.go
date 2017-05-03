package model

import (
	"math/rand"
	"os"
)

type adminbaseController struct {
	baseController
	cookie_status int
}

func (this *adminbaseController) __construct() {
	$this->adminbaseController();
}

func (this *adminbaseController) Init() {
	baseController.Init()

	var sid string
	this.cookie_status = 0
	if _COOKIE["sid"] != nil{
		this.cookie_status = 1
		sid = getgpc("sid", "C")
	}else{
		sid = rawurlencode(getgpc("sid", "R"))
	}
	//this.cookie_status = isset(_COOKIE["sid"]) ? 1 : 0
	//sid = this.cookie_status ? getgpc("sid", "C") : rawurlencode(getgpc("sid", "R"))
	this.view.sid = this.sid_decode(sid) ? sid : ""
	this.view.assign("sid", this.view.sid)
	this.view.assign("iframe", getgpc("iframe"))
	a = getgpc("a")
	if !(getgpc("m") =="user" && (a == "login" || a == "logout")) {
		this.check_priv()
	}
}

func (this *adminbaseController) check_priv() {
	username = this.sid_decode(this.view.sid)
	if empty(username) {
		header("Location: " + UC_API + "/admin.php?m=user&a=login&iframe=" + getgpc("iframe", "G") + (this.cookie_status ? "" : "&sid=" + this.view.sid))
		exit
	} else {
		this.user["isfounder"] = username == "UCenterAdministrator" ? 1 : 0
		if(!this.user["isfounder"]) {
			admin = this.db.fetch_first("SELECT a.*, m.* FROM " + UC_DBTABLEPRE + "admins a LEFT JOIN " + UC_DBTABLEPRE + "members m USING(uid) WHERE a.username=" + username)
			if(empty(admin)) {
				header("Location: " + UC_API + "/admin.php?m=user&a=login&iframe=" + getgpc("iframe", "G") + (this.cookie_status ? "" : "&sid=" + this.view.sid))
				exit
			} else {
				this.user = admin
				this.user["username"] = username
				this.user["admin"] = 1
				this.view.sid = this.sid_encode(username)
				this.setcookie("sid", this.view.sid, 86400)
			}
		} else {
			this.user["username"] = "UCenterAdministrator"
			this.user["admin"] = 1
			this.view.sid = this.sid_encode(this.user["username"])
			this.setcookie("sid", this.view.sid, 86400)
		}
		this.view.assign("user", this.user)
	}
}

func (this *adminbaseController) is_founder(username) {
	return this.user["isfounder"]
}

func (this *adminbaseController) writelog(action, extra string) {
	log = htmlspecialchars(this.user["username"] + "\t" + this.onlineip + "\t" + utils.Int64ToStr(this.time) + "\t" + action + "\t" + extra)
	logfile = UC_ROOT + "./data/logs/" + gmdate("Ym", this.time) + ".php"

	fileinfo, err := os.Stat(logfile)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
	}

	if fileinfo.Size() > 2048000 {
		//PHP_VERSION < "4.2.0" && mt_srand((float64)microtime() * 1000000)
		hash = ""
		chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
		for i = 0; i < 4; i++ {
			hash = hash + chars[rand.Intn(0, 61)]
		}
		format := "200601"
		tm := time.Unix(time, nsec)
		timestr := tm.Format(format)
		rename(logfile, UC_ROOT + "./data/logs/" + timestr + "_" + hash + ".php")
	}

	fp, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return
	}
	fp.WriteString("<?PHP exit?>\t" + str_replace(array("<?", "?>", "<?php"), "", log) + "\n")
	if err := fp.Close(); err != nil {
		return
	}

	// if(fp = @fopen(logfile, "a")) {
	// 	@flock(fp, 2)
	// 	@fwrite(fp, "<?PHP exit?>\t" + str_replace(array("<?", "?>", "<?php"), "", log) + "\n")
	// 	@fclose(fp)
	// }
}

func (this *adminbaseController) fetch_plugins() {
	plugindir = UC_ROOT + "./plugin"
	d = opendir(plugindir)
	while f = readdir(d) {
		if f != "." && f != ".." && is_dir(plugindir + "/" + f) {
			pluginxml = plugindir + f + "/plugin.xml"
			plugins[] = xml_unserialize(pluginxml)
		}
	}
}

func (this *adminbaseController) _call($a, $arg) {
	if(method_exists($this, $a) && $a{0} != '_') {
		$this->$a();
	} else {
		exit('Method does not exists');
	}
}

func (this *adminbaseController) sid_encode($username) {
	$ip = $this->onlineip;
	$agent = $_SERVER['HTTP_USER_AGENT'];
	$authkey = md5($ip.$agent.UC_KEY);
	$check = substr(md5($ip.$agent), 0, 8);
	return rawurlencode($this->authcode("$username\t$check", 'ENCODE', $authkey, 1800));
}

func (this *adminbaseController) sid_decode($sid) {
	$ip = $this->onlineip;
	$agent = $_SERVER['HTTP_USER_AGENT'];
	$authkey = md5($ip.$agent.UC_KEY);
	$s = $this->authcode(rawurldecode($sid), 'DECODE', $authkey, 1800);
	if(empty($s)) {
		return FALSE;
	}
	@list($username, $check) = explode("\t", $s);
	if($check == substr(md5($ip.$agent), 0, 8)) {
		return $username;
	} else {			
		return FALSE;
	}
}
