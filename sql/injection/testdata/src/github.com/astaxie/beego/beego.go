package beego

import "net/url"

// Controller mirrors the astaxie/beego v1 Controller: Input() returns the
// parsed request form and GetString/GetStrings return request values.
type Controller struct{}

func (c *Controller) Input() url.Values                               { return nil }
func (c *Controller) GetString(key string, def ...string) string     { return "" }
func (c *Controller) GetStrings(key string, def ...[]string) []string { return nil }
