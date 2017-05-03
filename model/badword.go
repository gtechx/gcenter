package model

type Badwords{
	id int16
	admin string `orm:"size(15)default('')"`
	find string
	replacement string
	findpattern string
}

// var db
// var base

// func (this *Badwords) __construct(&base) {
// 	this->badwordmodel(base)
// }

// func (this *Badwords) badwordmodel(&base) {
// 	this->base = base
// 	this->db = base->db
// }

//find, replacement, admin, typ = 1
func (this *Badwords) Add_badword(find, replacement, admin string, typ int) {
	if find != "" {
		find = trim(find)
		replacement = trim(replacement)
		findpattern := this->pattern_find(find)
		if(typ == 1) {
			this->db->query("REPLACE INTO " + UC_DBTABLEPRE + "badwords SET find='" + find + "', replacement='" + replacement + "', admin='" + admin + "', findpattern='" + findpattern + "'")
		} elseif(typ == 2) {
			this->db->query("INSERT INTO " + UC_DBTABLEPRE + "badwords SET find='" + find + "', replacement='" + replacement + "', admin='" + admin + "', findpattern='" + findpattern + "'", "SILENT")
		}
	}
	return this->db->insert_id()
}

func (this *Badwords) Get_total_num() {
	data = this->db->result_first("SELECT COUNT(*) FROM " + UC_DBTABLEPRE + "badwords")
	return data
}

func (this *Badwords) Get_list(page, ppp, totalnum int) {
	start = this->base->page_get_start(page, ppp, totalnum)
	data = this->db->fetch_all("SELECT * FROM " + UC_DBTABLEPRE + "badwords LIMIT " + start + ", " + ppp)
	return data
}

func (this *Badwords) Delete_badword(arr []string) {
	badwordids = this->base->implode(arr)
	this->db->query("DELETE FROM " + UC_DBTABLEPRE + "badwords WHERE id IN (" + badwordids + ")")
	return this->db->affected_rows()
}

func (this *Badwords) Truncate_badword() {
	this->db->query("TRUNCATE " + UC_DBTABLEPRE + "badwords")
}

func (this *Badwords) Update_badword(find, replacement string, id int64) {
	findpattern = this->pattern_find(find)
	this->db->query("UPDATE " + UC_DBTABLEPRE + "badwords SET find='" + find + "', replacement='" + replacement + "', findpattern='" + findpattern + "' WHERE id='" + id + "'")
	return this->db->affected_rows()
}

func (this *Badwords) Pattern_find(find string) {
	find = preg_quote(find, "/'")
	find = str_replace("\\", "\\\\", find)
	find = str_replace("'", "\\'", find)
	return '/' + preg_replace("/\\\{(\d+)\\\}/", ".{0,\\1}", find) + "/is"
}
