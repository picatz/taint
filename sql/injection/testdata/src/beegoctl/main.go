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

func main() {
	c := &ApiController{}
	c.getViaInput()
	c.getViaGetString()
	c.safeBound()
}
