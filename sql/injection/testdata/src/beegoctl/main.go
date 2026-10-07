package main

import (
	"fmt"

	"github.com/astaxie/beego"
	"xorm.io/xorm"
)

// ApiController embeds beego.Controller, so Input()/GetString() are promoted,
// mirroring casdoor's controllers (CVE-2022-24124).
type ApiController struct {
	beego.Controller
}

var db *xorm.Engine

// getViaInput reads a request field through the promoted Input().Get() and
// interpolates it into the query text: a real injection.
func (c *ApiController) getViaInput() {
	field := c.Input().Get("field")
	db.Where(fmt.Sprintf("%s like ?", field), "value") // want "potential sql injection"
}

// getViaGetString reads a request field through the promoted GetString().
func (c *ApiController) getViaGetString() {
	field := c.GetString("field")
	db.Where(fmt.Sprintf("%s like ?", field), "value") // want "potential sql injection"
}

// safeBound passes the request value as a bound parameter, which is safe.
func (c *ApiController) safeBound() {
	value := c.GetString("value")
	db.Where("name like ?", value)
}

// Rebuilding a request string byte by byte does not sanitize its contents.
func rebuild(field string) string {
	var out []byte
	for i := 0; i < len(field); i++ {
		out = append(out, field[i])
	}
	return string(out)
}

func (c *ApiController) reconstructedField() {
	field := rebuild(c.GetString("field"))
	db.Where(fmt.Sprintf("%s like ?", field), "value") // want "potential sql injection"
}

func (c *ApiController) reconstructedBound() {
	value := rebuild(c.GetString("value"))
	db.Where("name like ?", value)
}

func (c *ApiController) reconstructedConstant() {
	_ = c.GetString("unrelated")
	db.Where(fmt.Sprintf("%s like ?", rebuild("name")), "value")
}

// Decoding and reassembling runes preserves ASCII SQL syntax in request data.
func rebuildRunes(field string) string {
	var out []rune
	for _, r := range field {
		out = append(out, r)
	}
	return string(out)
}

func (c *ApiController) reconstructedRuneField() {
	field := rebuildRunes(c.GetString("field"))
	db.Where(fmt.Sprintf("%s like ?", field), "value") // want "potential sql injection"
}

func (c *ApiController) reconstructedRuneBound() {
	value := rebuildRunes(c.GetString("value"))
	db.Where("name like ?", value)
}

func (c *ApiController) reconstructedRuneConstant() {
	_ = c.GetString("unrelated")
	db.Where(fmt.Sprintf("%s like ?", rebuildRunes("name")), "value")
}

func main() {
	c := &ApiController{}
	c.getViaInput()
	c.getViaGetString()
	c.safeBound()
	c.reconstructedField()
	c.reconstructedBound()
	c.reconstructedConstant()
	c.reconstructedRuneField()
	c.reconstructedRuneBound()
	c.reconstructedRuneConstant()
}
