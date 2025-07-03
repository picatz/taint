package main

import (
	"fmt"
	"os"
)

type command struct {
	name string
	run  func(args []string) error
}

type commands []*command

func (c commands) run(args []string) error {
	for i := 0; i < len(c); i++ {
		cmd := c[i]
		if cmd.name == args[0] {
			return cmd.run(args[1:])
		}
	}

	return fmt.Errorf("unknown command: %s", args[0])
}

type cli struct {
	commands commands
}

func (c *cli) run(args []string) error {
	return c.commands.run(args)
}

func doSomething() error {
	fmt.Println("doing something")
	return nil
}

func main() {
	c := &cli{
		commands{
			{
				name: "do-something",
				run: func(args []string) error {
					return doSomething()
				},
			},
		},
	}

	err := c.run(os.Args[1:])
	if err != nil {
		panic(err)
	}
}