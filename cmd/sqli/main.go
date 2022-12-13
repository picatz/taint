package main

import (
	"github.com/picatz/taint/sql/injection"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(injection.Analyzer)
}
