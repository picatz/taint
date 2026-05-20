package main

import (
	"github.com/picatz/taint/command/injection"
	"github.com/picatz/taint/internal/analyzercmd"
)

func main() {
	analyzercmd.Main(injection.Analyzer)
}
