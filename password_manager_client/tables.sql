CREATE TABLE users (
	username VARCHAR(50) PRIMARY KEY,
	password VARCHAR(255) NOT NULL
);

CREATE TABLE accounts (
	description VARCHAR(255),
	username VARCHAR(50),
	encrypted_data TEXT,
	FOREIGN KEY (username) REFERENCES users(username)
);

