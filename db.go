package main

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func connectDB() (*pgxpool.Pool, error) {
	dsn := os.Getenv("DATABASE_URL")

	if dsn == "" {
		dsn = "postgres://weblog:123456@localhost:5432/weblog"
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, err
	}

	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		pool.Close()
		return nil, err
	}

	if _, err := pool.Exec(context.Background(), string(schema)); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}
