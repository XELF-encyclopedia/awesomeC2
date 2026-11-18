package operator

import (
	"crypto/rand"
	"io"
	"time"
)

func readRand(b []byte) (int, error) { return io.ReadFull(rand.Reader, b) }

type deadliner interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func setReadDeadline(c io.ReadWriteCloser, t time.Time) error {
	if d, ok := c.(deadliner); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func setWriteDeadline(c io.ReadWriteCloser, t time.Time) error {
	if d, ok := c.(deadliner); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}
