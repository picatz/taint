package main

import (
	"github.com/picatz/taint/command/pathtraversal"
	"github.com/picatz/taint/internal/analyzercmd"
)

func main() {
	analyzercmd.Main(pathtraversal.Analyzer)
}
