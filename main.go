// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
//
// forked from https://github.com/c0nrad/http2fuzz and 
// 	modified by Justin Palk
//
package main

import (
	"flag"
	"os"

	"github.com/jmpalk/http2fuzz/config"
	"github.com/jmpalk/http2fuzz/fuzzer"
)

func main() {

	if config.FuzzMode == config.ModeClient {
		fuzzer.Client()
	} else if config.FuzzMode == config.ModeServer {
		fuzzer.Server()
	} else {
		flag.Usage()
		os.Exit(1)
	}

	select {}
}
