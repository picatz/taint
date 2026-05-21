package main

import (
	"github.com/picatz/taint/internal/analyzercmd"
	"github.com/picatz/taint/network/ssrf"
)

func main() {
	analyzercmd.Main(ssrf.Analyzer)
}
