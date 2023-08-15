CREATE TABLE users (
    username VARCHAR(50) PRIMARY KEY,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,                   -- Added a primary key for the accounts table
    description VARCHAR(255) NOT NULL,
    username VARCHAR(50) NOT NULL,           -- Made the username NOT NULL
    encrypted_data TEXT NOT NULL,            -- Made the encrypted_data NOT NULL
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE  -- Added ON DELETE CASCADE
);

CREATE INDEX idx_accounts_username ON accounts(username);   -- Added an index on the username column for faster lookups
