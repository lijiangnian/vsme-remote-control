//go:build !darwin

package main

func terminalAttached() bool { return false }
