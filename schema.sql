CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL
);

CREATE TABLE user_data (
    user_id INTEGER PRIMARY KEY REFERENCES users(user_id),
    json_data JSONB NOT NULL
);

CREATE TABLE finance_data (
    user_id INTEGER PRIMARY KEY REFERENCES users(user_id),
    data JSONB NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
