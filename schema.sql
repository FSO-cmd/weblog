CREATE TABLE IF NOT EXISTS users (
                                     id SERIAL PRIMARY KEY,
                                     username VARCHAR(20) NOT NULL UNIQUE,
    password TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS posts (
                                     id SERIAL PRIMARY KEY,
                                     title TEXT NOT NULL,
                                     content TEXT NOT NULL,
                                     author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    image TEXT,
    is_private BOOLEAN NOT NULL DEFAULT FALSE
    );

CREATE TABLE IF NOT EXISTS comments (
                                        id SERIAL PRIMARY KEY,
                                        post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

CREATE TABLE IF NOT EXISTS post_shares (
                                           post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, user_id)
    );

CREATE INDEX IF NOT EXISTS idx_posts_author_id
    ON posts(author_id);

CREATE INDEX IF NOT EXISTS idx_comments_post_id
    ON comments(post_id);

CREATE INDEX IF NOT EXISTS idx_comments_user_id
    ON comments(user_id);

CREATE INDEX IF NOT EXISTS idx_post_shares_post_id
    ON post_shares(post_id);

CREATE INDEX IF NOT EXISTS idx_post_shares_user_id
    ON post_shares(user_id);