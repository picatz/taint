package main

import (
	"context"
	"os/exec"
)

func main() {
	exec.Command("ls", "-la")
	exec.CommandContext(context.Background(), "ls", "-la")
	exec.Command("sh", "-c", "echo ok")
	exec.CommandContext(context.Background(), "sh", "-c", "echo ok")
}
