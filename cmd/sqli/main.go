package main

import (
	"github.com/picatz/taint/internal/analyzercmd"
	"github.com/picatz/taint/sql/injection"
)

func main() {
	analyzercmd.Main(injection.Analyzer)
}
