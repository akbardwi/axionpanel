// Package web embeds the built frontend (web/dist) into the panel binary.
// Run `make web` before `make build`; without a build the panel serves a 503
// explaining how to produce one.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built frontend rooted at dist/.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // dist is embedded at compile time; this cannot fail
	}
	return sub
}
