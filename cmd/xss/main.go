package main

import (
	"github.com/picatz/taint/internal/analyzercmd"
	"github.com/picatz/taint/xss"
)

func main() {
	analyzercmd.Main(xss.Analyzer)
}
