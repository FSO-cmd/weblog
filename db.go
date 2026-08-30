package main

import (
	"context"

	"github.com/jackc/pgx/v5"
)

var err error

func connectDB() (*pgx.Conn, error) {
	conn, err := pgx.Connect(
		context.Background(),
		"postgres://weblog:123456@localhost:5432/weblog",
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
