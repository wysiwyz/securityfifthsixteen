-- add new database
create database newIBank;
use newIBank;

-- add new table
CREATE TABLE `users`(
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(45) NOT NULL,
	`password` VARCHAR(45) NOT NULL,
	`enabled` INT NOT NULL,
	PRIMARY KEY(`id`));

CREATE TABLE `authorities` (
    `id` int NOT NULL AUTO_INCREMENT,
	`username` VARCHAR(45) NOT NULL,
	`authority` VARCHAR(45) NOT NULL,
	PRIMARY KEY(`id`));

--add a username(happy), passwd(12345), enabledUser(1)
INSERT IGNORE INTO `users` VALUES (NULL, 'happy', '12345', '1');
INSERT IGNORE INTO `authorities` VALUES (NULL, 'happy', 'write');

--add new table for section 03-011
CREATE TABLE `customer` (
    `id` int NOT NULL AUTO_INCREMENT,
    `email` varchar(45) NOT NULL,
    `pwd` varchar(200) NOT NULL,
    `role` varchar(45) NOT NULL,
    PRIMARY KEY (`id`)
);

INSERT INTO `customer` (`email`, `pwd`, `role`)
  VALUES ('chihalingley@test.co', '54321', 'admin');