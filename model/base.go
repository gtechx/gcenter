package model

import (
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/orm"
	"github.com/nature19862001/base/php"
	"strconv"
	"strings"
	"time"
	"regexp"
	"utils"
	"encoding/json"
	"crypto/md5"
	"encoding/hex"
	"encoding/base64"
)

type baseController struct {
	beego.Controller
	time int64
	onlineip string
	db orm.Ormer
	//var $view
	user map[string]interface{}
	settings map[string]interface{}
	cache map[string]interface{}
	app map[string]interface{}
	lang map[string]interface{}
	input map[string]interface{}
}

_CACHE := make(map[string]map[string]interface{})

func daddslashes($string, $force = 0, $strip = FALSE) {
	if(!MAGIC_QUOTES_GPC || $force) {
		if(is_array($string)) {
			foreach($string as $key => $val) {
				$string[$key] = daddslashes($val, $force, $strip);
			}
		} else {
			$string = addslashes($strip ? stripslashes($string) : $string);
		}
	}
	return $string;
}

func getgpc($k, $t='R') {
	switch($t) {
		case 'P': $var = &$_POST; break;
		case 'G': $var = &$_GET; break;
		case 'C': $var = &$_COOKIE; break;
		case 'R': $var = &$_REQUEST; break;
	}
	return isset($var[$k]) ? (is_array($var[$k]) ? $var[$k] : trim($var[$k])) : NULL;
}

func (this *baseController) Init() {
	this.init_var()
	this.init_db()
	this.init_cache()
	this.init_app()
	this.init_user()
	this.init_template()
	this.init_note()
	this.init_mail()
	//		$this->cron()
}

func (this *baseController) init_var() {
	this.time = time.Now().Unix()
	$cip = getenv('HTTP_CLIENT_IP')
	$xip = getenv('HTTP_X_FORWARDED_FOR')
	$rip = getenv('REMOTE_ADDR')
	$srip = $_SERVER['REMOTE_ADDR']
	if $cip && php.Strcasecmp($cip, "unknown") {
		$this->onlineip = $cip
	} else if($xip && php.Strcasecmp($xip, 'unknown')) {
		$this->onlineip = $xip
	} else if($rip && php.Strcasecmp($rip, 'unknown')) {
		$this->onlineip = $rip
	} else if($srip && php.Strcasecmp($srip, 'unknown')) {
		$this->onlineip = $srip
	}
	
	reg, err:= regexp.Compile("/[\d\.]{7,15}/")
	
	if err == nil{
		match := reg.FindAllString(this.onlineip, -1)
		
		if match != nil{
			this.onlineip = match[0]
		}else{
			this.onlineip = "unknown"
		}
	}
	//preg_match("/[\d\.]{7,15}/", $this->onlineip, $match)
	//$this->onlineip = $match[0] ? $match[0] : 'unknown'

	define('FORMHASH', $this->formhash())
	$_GET['page'] =  max(1, intval(getgpc('page')))

	include_once UC_ROOT.'./view/default/main.lang.php'
	$this->lang = &$lang
}

func (this *baseController) init_cache() {
	$this->settings = $this->cache('settings')
	$this->cache['apps'] = $this->cache('apps')
	if(PHP_VERSION > '5.1') {
		$timeoffset = intval($this->settings['timeoffset'] / 3600)
		@date_default_timezone_set('Etc/GMT'.($timeoffset > 0 ? '-' : '+').(abs($timeoffset)))
	}
}

func (this *baseController) init_input(getagent string) {
	$input = getgpc('input', 'R')
	if($input) {
		$input = $this->authcode($input, 'DECODE', $this->app['authkey'])
		parse_str($input, $this->input)
		$this->input = daddslashes($this->input, 1, TRUE)
		$agent = $getagent ? $getagent : $this->input['agent']

		if(($getagent && $getagent != $this->input['agent']) || (!$getagent && md5($_SERVER['HTTP_USER_AGENT']) != $agent)) {
			exit('Access denied for agent changed')
		} elseif($this->time - $this->input('time') > 3600) {
			exit('Authorization has expired')
		}
	}
	if(empty($this->input)) {
		exit('Invalid input')
	}
}

func (this *baseController) init_db() {
	this.db = orm.NewOrm()
	//require_once UC_ROOT.'lib/db.class.php'
	//$this->db = new ucserver_db()
	//$this->db->connect(UC_DBHOST, UC_DBUSER, UC_DBPW, UC_DBNAME, UC_DBCHARSET, UC_DBCONNECT, UC_DBTABLEPRE)
}

func (this *baseController) init_app() {
	appid := php.Intval(this.GetString("appid"))
	if appid != 0{
		this->app = this->cache["apps"][appid]
	}
	//$appid && $this->app = $this->cache['apps'][$appid]
}

func (this *baseController) init_user() {
	if(isset($_COOKIE['uc_auth'])) {
		@list($uid, $username, $agent) = explode('|', $this->authcode($_COOKIE['uc_auth'], 'DECODE', ($this->input ? $this->app['appauthkey'] : UC_KEY)))
		if($agent != md5($_SERVER['HTTP_USER_AGENT'])) {
			$this->setcookie('uc_auth', '')
		} else {
			@$this->user['uid'] = $uid
			@$this->user['username'] = $username
		}
	}
}

func (this *baseController) init_template() {
	$charset = UC_CHARSET
	require_once UC_ROOT.'lib/template.class.php'
	$this->view = new template()
	$this->view->assign('dbhistories', $this->db->histories)
	$this->view->assign('charset', $charset)
	$this->view->assign('dbquerynum', $this->db->querynum)
	$this->view->assign('user', $this->user)
}

func (this *baseController) init_note() {
	if this.note_exists() && this.GetString("inajax") != "" {
		$this->load('note')
		$_ENV['note']->send()
	}
}

func (this *baseController) init_mail() {
	if($this->mail_exists() && !getgpc('inajax')) {
		$this->load('mail')
		$_ENV['mail']->send()
	}
}

//authcode(str string, $operation = 'DECODE', $key = '', $expiry = 0)
func (this *baseController) authcode(str string, operation string, key string, expiry int64) string{

	ckey_length := 4	// 随机密钥长度 取值 0-32
	// 加入随机密钥，可以令密文无任何规律，即便是原文和密钥完全相同，加密结果也会每次不同，增大破解难度。
	// 取值越大，密文变动规律越大，密文变化 = 16 的 $ckey_length 次方
	// 当此值为 0 时，则不产生随机密钥

	key = php.Md5(key ? key : UC_KEY)
	keya := php.Md5(php.Substr(key, 0, 16))
	keyb := php.Md5(php.Substr(key, 16, 16))
	
	keyc = ""
	if ckey_length != 0{
		if operation == "DECODE"{
			keyc = php.Substr(str, 0, ckey_length)
		}else{
			keyc = php.Substr(md5(utils.Int64ToStr(php.Microtime())), -ckey_length)
		}
	}
	//keyc = ckey_length ? (operation == "DECODE" ? substr(str, 0, ckey_length): substr(md5(microtime()), -ckey_length)) : ""

	cryptkey := keya + php.Md5(keya + keyc)
	key_length := php.Strlen(cryptkey)
	
	if operation == "DECODE"{
		str = php.Base64_decode(php.Substr(str, ckey_length))
	}else{
		var rexpiry int64
		if expiry == 0{
			rexpiry = 0
		}else{
			rexpiry = expiry + time()
		}
		str1 = php.Sprintf("%010d", rexpiry)
		str = str1 + php.Substr(php.Md5(str + keyb), 0, 16) + str
	}
	//str = operation == "DECODE" ? base64_decode(substr(str, ckey_length)) : sprintf("%010d", expiry ? expiry + time() : 0).substr(md5(str.keyb), 0, 16) + str
	string_length := php.Strlen(str)

	result := ""
	box := php.Range(0, 255, 1)

	rndkey := make([]int, 255)
	for i = 0 i <= 255 i++ {
		rndkey[i] = ord(cryptkey[i % key_length])
	}

	for j = 0, i = 0 i < 256 i++ {
		j = (j + box[i] + rndkey[i]) % 256
		tmp := box[$i]
		box[i] = box[j]
		box[j] = tmp
	}

	for a = j = i = 0 i < string_length i++ {
		a = (a + 1) % 256
		j = (j + box[a]) % 256
		tmp := box[a]
		box[a] = box[j]
		box[j] = tmp
		result = result + php.Chr(php.Ord(str[i]) ^ (box[(box[a] + box[j]) % 256]))
	}

	if operation == "DECODE" {
		if (php.Substr(result, 0, 10) == 0 || php.Substr(result, 0, 10) - php.Time() > 0) && php.Substr(result, 10, 16) == php.Substr(php.Md5(php.Substr(result, 26)+keyb), 0, 16) {
			return php.Substr(result, 26)
		} else {
			return ""
		}
	} else {
		return keyc + php.Str_replace("=", "", php.Base64_encode(result), -1)
	}

}

func (this *baseController) page(num , perpage, curpage int, mpurl string) string {
	multipage := ""
	if php.Strpos(mpurl, "?") != 0{
		mpurl = mpurl + "&"
	}else{
		mpurl = mpurl + "?"
	}
	//mpurl = mpurl + strpos(mpurl, "?") ? "&" : "?"
	if num > perpage {
		pag := 10
		offset := 2

		pages = php.Ceil(num / perpage)
		
		var from int
		var to int
		if pag > pages {
			from = 1
			to = pages
		} else {
			from = curpage - offset
			to = from + pag - 1
			if from < 1 {
				to = curpage + 1 - from
				from = 1
				if to - from < pag {
					to = pag
				}
			} else if to > pages {
				from = pages - pag + 1
				to = pages
			}
		}
		ajaxtarget := ""
		autogoto := false
		simple := false
		realpages := 0
		if (curpage - offset > 1 && pages > pag{
			multipage = "<a href=\"" + mpurl + "pag=1\" class=\"first\"" + ajaxtarget + ">1 ...</a>"
		}
		if (curpage > 1 && !simple{
			multipage = multipage + "<a href=\"" + mpurl + "pag=" + utils.IntToStr(curpage - 1) + "\" class=\"prev\"" + ajaxtarget + ">&lsaquo&lsaquo</a>"
		}
		//multipage = (curpage - offset > 1 && pages > pag ? "<a href=\"" + mpurl + "pag=1\" class=\"first\"" + ajaxtarget + ">1 ...</a>" : "").
		//(curpage > 1 && !simple ? "<a href=\"" + mpurl + "pag=" + (curpage - 1) + "\" class=\"prev\"" + ajaxtarget + ">&lsaquo&lsaquo</a>" : "");
		for i = from; i <= to; i++ {
			if i == curpage{
				multipage = multipage + "<strong>" + utils.IntToStr(i) + "</strong>"
			}else{
				multipage = multipage + "<a href=\"" + mpurl + "pag=" + utils.IntToStr(i)// + ($ajaxtarget && $i == $pages && $autogoto ? '#' : '') 
				if ajaxtarget != "" && i == pages && autogoto{
					multipage = multipage + "#"
				}
				multipage = multipage + "\"" + ajaxtarget + ">" + utils.IntToStr(i) + "</a>"
			}
			//multipage .= i == curpage ? '<strong>'.i.'</strong>' :
			//'<a href="'.$mpurl.'pag='.$i.($ajaxtarget && $i == $pages && $autogoto ? '#' : '').'"'.$ajaxtarget.'>'.$i.'</a>'
		}

		if curpage < pages && !simple{
			multipage = multipage + "<a href=\"" + mpurl + "pag="  + utils.IntToStr(curpage + 1) + "\" class=\"next\"" + ajaxtarget + ">&rsaquo&rsaquo</a>"
		}
		if to < pages{
			multipage = multipage + "<a href=\"" + mpurl + "pag=" + utils.IntToStr(pages) + "\" class=\"last\"" + ajaxtarget + ">... "  + utils.IntToStr(realpages) + "</a>"
		}
		if !simple && pages > pag && ajaxtarget == ""{
			multipage = multipage + "<kbd><input type=\"text\" name=\"custompage\" size=\"3\" onkeydown=\"if(event.keyCode==13) {window.location=\'" + mpurl + "pag=\'+this.value return false}\" /></kbd>"
		}
		//multipage .= (curpage < pages && !simple ? '<a href="'.$mpurl.'pag='.($curpage + 1).'" class="next"'.$ajaxtarget.'>&rsaquo&rsaquo</a>' : '').
		//($to < $pages ? '<a href="'.$mpurl.'pag='.$pages.'" class="last"'.$ajaxtarget.'>... '.$realpages.'</a>' : '').
		//(!$simple && $pages > $pag && !$ajaxtarget ? '<kbd><input type="text" name="custompage" size="3" onkeydown="if(event.keyCode==13) {window.location=\''.$mpurl.'pag=\'+this.value return false}" /></kbd>' : '')

		if multipage != ""{
			tempstr := "<div class=\"pages\">"
			if !simple{
				tempstr = tempstr + "<em>&nbsp" + utils.IntToStr(num) + "&nbsp</em>"
			}
			multipage = tempstr + multipage + "</div>"
		}
		//multipage = multipage ? '<div class="pages">'.(!$simple ? '<em>&nbsp'.$num.'&nbsp</em>' : '').$multipage.'</div>' : ''
	}
	return multipage
}

func (this *baseController) page_get_start(page , ppp, totalnum int) int{
	totalpage := php.Ceil(totalnum / ppp)
	page =  php.Max(1, php.Min(totalpage, php.Intval(page)))
	return (page - 1) * ppp
}

func (this *baseController) load(model string, base *baseController, release string) {
	$base = $base ? $base : $this
	if(empty($_ENV[$model])) {
		$release = !$release ? RELEASE_ROOT : $release
		if(file_exists(UC_ROOT.$release."model/$model.php")) {
			require_once UC_ROOT.$release."model/$model.php"
		} else {
			require_once UC_ROOT."model/$model.php"
		}
		eval('$_ENV[$model] = new '.$model.'model($base)')
	}
	return $_ENV[$model]
}

//$k = array(), $decode = FALSE
func (this *baseController) get_setting(k []string, decode bool) map[string]string{
	result := make(map[string]string)
	sqladd := ""
	if len(k) > 0{
		sqladd = "WHERE k IN (" + this.implode(k) + ")"
	}
	//$sqladd = $k ? "WHERE k IN (" + this.implode(k) + ")" : ""
	settings := this->db->fetch_all("SELECT * FROM " + UC_DBTABLEPRE + "settings " + sqladd)
	if len(settings) > 0{
		for _, value in range settings{
			result[value['k']] = $decode ? unserialize(value['v']) : value['v']
		}
	}
	// if(is_array($settings)) {
	// 	foreach($settings as $arr) {
	// 		result[arr['k']] = $decode ? unserialize(arr['v']) : arr['v']
	// 	}
	// }
	return result
}

func array_keys(maparr map[interface{}]interface{}) []interface{}{
	keys := make([]interface{}, len(maparr))
	for k := range maparr {
        keys = append(keys, k)
    }
    return keys
}

func array_values(maparr map[interface{}]interface{}) []interface{}{
	keys := make([]interface{}, len(maparr))
	for k := range maparr {
        keys = append(keys, k)
    }
    return keys
}

//$k, $v, $encode = FALSE
func (this *baseController) set_setting(k string, v string, encode bool) {
	//$v = is_array($v) || $encode ? addslashes(serialize($v)) : $v
	this->db->query("REPLACE INTO " + UC_DBTABLEPRE + "settings SET k=" + k + ", v=" + v)
}

// $redirect = '', $type = 0, $vars = array()
func (this *baseController) message(message string, redirect string, typ int, $vars = array()) {
	include_once UC_ROOT.'view/default/messages.lang.php'
	if(isset($lang[$message])) {
		$message = $lang[$message] ? php.Str_replace(php.Array_keys($vars), php.Array_values($vars), $lang[$message]) : $message
	}
	$this->view->assign('message', $message)
	$this->view->assign('redirect', $redirect)
	if($type == 0) {
		$this->view->display('message')
	} else if($type == 1) {
		$this->view->display('message_client')
	}
	exit
}

func (this *baseController) formhash() string{
	return php.Substr(php.Md5(php.Substr(utils.Int64ToStr(this.time), 0, -4) + UC_KEY), 16)
}

func (this *baseController) submitcheck() bool{
	return this.GetString("formhash") == formhash()
}

//$typ = 3
func (this *baseController) date(time int64, typ int) string{
	//format := typ & 2 ? (!empty(this.settings["dateformat"]) ? this.settings["dateformat"] : "Y-n-j") : ""
	//format = typ & 1 ? (!empty(this.settings["timeformat"]) ? this.settings["timeformat"] : "H:i") : ""
	if tye == 2{
		if len(this.settings["dateformat"]) == 0{
			format = "2006-Jan-2"
		}else{
			format = this.settings["dateformat"]
		}
	}
	if tye == 1{
		if len(this.settings["timeformat"]) == 0{
			format = "15:04"
		}else{
			format = this.settings["timeformat"]
		}
	}
	time = time + this.settings["timeoffset"]
	nsec := time / 10000000000
	tm := time.Unix(time, nsec)
	return tm.Format(format)
	//return gmdate(implode(" ", format), time + this.settings["timeoffset"])
}

func (this *baseController) implode(strarr []string) string{
	return "'" + strings.Join(strarr, "','") + "'"
	//return "'".implode("','", (array)$arr)."'"
}

//$dir = '.'
func (this *baseController) set_home(uid int64, dir string) {
	if dir == ""{
		dir = "."
	}
	struid := sprintf("%09d", uid)
	dir1 := substr(struid, 0, 3)
	dir2 := substr(struid, 3, 2)
	dir3 := substr(struid, 5, 2)
	!is_dir(dir + "/" + dir1) && mkdir(dir + "/" + dir1, 0777)
	!is_dir(dir + "/".dir1 + "/" + dir2) && mkdir(dir + "/" + dir1 + "/" + dir2, 0777)
	!is_dir(dir + "/".dir1 + "/" + dir2 + "/" + dir3) && mkdir(dir + "/" + dir1 + "/" + dir2 + "/" + dir3, 0777)
}

func (this *baseController) get_home(uid int64) {
	struid := sprintf("%09d", uid)
	dir1 = substr(struid, 0, 3)
	dir2 = substr(struid, 3, 2)
	dir3 = substr(struid, 5, 2)
	return dir1 + "/" + dir2 + "/" + dir3
}

// size = "big", type = ""
func (this *baseController) get_avatar(uid int64, size string, typ string) string{
	//size = in_array(size, array("big", "middle", "small")) ? size : "big"
	if size != "big" && size != "middle" && size != "small"{
		size = "big"
	}
	//uid = abs(intval(uid))
	struid := php.Sprintf("%09d", uid)
	dir1 = php.Substr(struid, 0, 3)
	dir2 = php.Substr(struid, 3, 2)
	dir3 = php.Substr(struid, 5, 2)

	var typeadd string = ""
	if typ == "real"{
		typeadd = "_real"
	}
	//typeadd = typ == "real" ? "_real" : ""
	return  dir1 + "/" + dir2 + "/" + dir3 + "/" + php.Substr(struid, -2, 2) + typeadd + "_avatar_" + size + ".jpg"
}

func (this *baseController) cache(cachefile string) interface{}{
	//static $_CACHE = array()
	value, ok := _CACHE[cachefile]
	if !ok {
		cachepath := UC_DATADIR + "./cache/" + cachefile + ".cache"
		if !utils.FileExists(cachepath) {
			this.load("cache")
			$_ENV["cache"]->updatedata($cachefile)
		} else {
			//include_once $cachepath
			str := utils.ReadFileAll(cachepath)
			var datamap []map[string]interface{}
			json.Unmarshal([]byte(str), &datamap)
			_CACHE[cachefile] = datamap
			value = datamap
		}
	}
	return value//$_CACHE[$cachefile]
}

func (this *baseController) input($k) {
	return isset($this->input[$k]) ? (is_array($this->input[$k]) ? $this->input[$k] : trim($this->input[$k])) : NULL
}

//$htmlon = 0
func (this *baseController) serialize(s string, htmlon int) {
	if php.File_exists(UC_ROOT.RELEASE_ROOT + "./lib/xml.class.php") {
		include_once UC_ROOT.RELEASE_ROOT."./lib/xml.class.php"
	} else {
		include_once UC_ROOT."./lib/xml.class.php"
	}

	return xml_serialize(s, htmlon)
}

func (this *baseController) unserialize(s string) {
	if php.File_exists(UC_ROOT.RELEASE_ROOT + "./lib/xml.class.php") {
		include_once UC_ROOT.RELEASE_ROOT."./lib/xml.class.php"
	} else {
		include_once UC_ROOT."./lib/xml.class.php"
	}

	return xml_unserialize(s)
}

//$dot = ' ...'
func (this *baseController) cutstr(str string, length int, dot string) string{
	if php.Strlen(str) <= $length {
		return str
	}

	if dot == ""{
		dot = " ..."
	}

	str = php.Str_replace("&amp", "&", str)
	str = php.Str_replace("&quot", "\"", str)
	str = php.Str_replace("&lt", "<", str)
	str = php.Str_replace("&gt", ">", str)
	//str = str_replace(array('&amp', '&quot', '&lt', '&gt'), array('&', '"', '<', '>'), $str)

	tmpstrcut := ""
	if php.Strtolower(UC_CHARSET) == "utf-8" {

		n := 0
		tn := 0
		noc := 0
		while n < php.Strlen(str) {

			t := php.Ord(str[n])
			if t == 9 || t == 10 || (32 <= t && t <= 126) {
				tn = 1 n++ noc++
			} else if 194 <= t && t <= 223 {
				tn = 2 n += 2 noc += 2
			} else if 224 <= t && t < 239 {
				tn = 3 n += 3 noc += 2
			} else if 240 <= t && t <= 247 {
				tn = 4 n += 4 noc += 2
			} else if 248 <= t && t <= 251 {
				tn = 5 n += 5 noc += 2
			} else if t == 252 || t == 253 {
				tn = 6 n += 6 noc += 2
			} else {
				n++
			}

			if noc >= length {
				break
			}

		}
		if noc > length {
			n -= tn
		}

		tmpstrcut = php.Substr(str, 0, n)

	} else {
		for i = 0; i < length; i++ {
			if php.Ord(str[i]) > 127{
				tmpstrcut = tmpstrcut + str[i].str[++i]
			}else{
				tmpstrcut = tmpstrcut + str[i]
			}
			//tmpstrcut = tmpstrcut + ord(str[i]) > 127 ? str[i].str[++i] : str[i]
		}
	}

	tmpstrcut = php.Str_replace("&", "&amp", tmpstrcut)
	tmpstrcut = php.Str_replace("\"", "&quot", tmpstrcut)
	tmpstrcut = php.Str_replace("<", "&lt", tmpstrcut)
	tmpstrcut = php.Str_replace(">", "&gt", tmpstrcut)
	//tmpstrcut = str_replace(array('&', '"', '<', '>'), array('&amp', '&quot', '&lt', '&gt'), tmpstrcut)

	return tmpstrcut + dot
}

var UC_COOKIEPATH string = "/"
var UC_COOKIEDOMAIN string = ""

//life = 0, $httponly = false
func (this *baseController) setcookie(key, value string, life int64, httponly bool) {
	//(!defined('UC_COOKIEPATH')) && define('UC_COOKIEPATH', '/')
	//(!defined('UC_COOKIEDOMAIN')) && define('UC_COOKIEDOMAIN', '')

	if value == "" || life < 0 {
		value = ""
		life = -1
	}

	if life > 0{
		life = this.time + life
	}else if life < 0{
		life = this.time - 31536000
	}else{
		life = 0
	}
	
	//$life = $life > 0 ? $this->time + $life : ($life < 0 ? $this->time - 31536000 : 0)
	var path string
	if httponly{
		path = UC_COOKIEPATH + " HttpOnly"
	}else{
		path = UC_COOKIEPATH
	}
	//$path = $httponly && PHP_VERSION < '5.2.0' ? UC_COOKIEPATH." HttpOnly" : UC_COOKIEPATH
	secure := $_SERVER['SERVER_PORT'] == 443 ? 1 : 0
	// if(PHP_VERSION < '5.2.0') {
	// 	setcookie($key, $value, $life, $path, UC_COOKIEDOMAIN, $secure)
	// } else {
	php.Setcookie($key, $value, $life, $path, UC_COOKIEDOMAIN, $secure, $httponly)
	//}
}

func (this *baseController) note_exists() bool{
	noteexists := this.db.fetch_first("SELECT value FROM " + UC_DBTABLEPRE + "vars WHERE name='noteexists'")
	if len(noteexists) == 0 {
		return false
	} else {
		return true
	}
}

func (this *baseController) mail_exists() bool{
	mailexists := this.db.fetch_first("SELECT value FROM " + UC_DBTABLEPRE + "vars WHERE name='mailexists'")
	if len(mailexists) == 0 {
		return false
	} else {
		return true
	}
}

func (this *baseController) dstripslashes(str string) string{
	// if(is_array($string)) {
	// 	foreach($string as $key => $val) {
	// 		$string[$key] = $this->dstripslashes($val)
	// 	}
	// } else {
	// 	$string = stripslashes($string)
	// }
	return str
}
