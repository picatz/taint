package main

import (
	"github.com/picatz/taint/xss"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(xss.Analyzer)
}
