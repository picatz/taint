package main

import (
	"context"
	"os/exec"
)

const (
	constCommand = "echo ok"
	constProgram = "ls"
	constShell   = "bash"
)

func main() {
	exec.Command("ls", "-la")
	exec.CommandContext(context.Background(), "ls", "-la")
	exec.Command("sh", "-c", "echo ok")
	exec.CommandContext(context.Background(), "sh", "-c", "echo ok")
	exec.Command("sh", "-ec", constCommand)
	exec.Command(constShell, "-lc", constCommand)
	exec.Command(constProgram, "-la")
}
