package main

import "github.com/wasilibs/go-re2"

func main() {
	r := re2.MustCompile("foo")
	println(r.MatchString("foo"))
}
