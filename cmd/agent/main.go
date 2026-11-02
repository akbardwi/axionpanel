// Command agent is the AxionPanel privileged daemon. It accepts validated
// operation requests from the panel over a Unix socket.
package main

import (
	"flag"
	"log"
)

var version = "0.0.0-dev"

func main() {
	socket := flag.String("socket", "/run/axionpanel/agent.sock", "Unix socket path")
	flag.Parse()
	log.Printf("axionpanel agent %s (socket %s): not implemented yet", version, *socket)
}
