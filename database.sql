#users table
CREATE TABLE `egov`.`users` ( `userid` VARCHAR(70) NOT NULL PRIMARY KEY , `username` VARCHAR(30) NOT NULL UNIQUE, `name` VARCHAR(30) NOT NULL , `password` VARCHAR(300) NOT NULL , `registerationTime` DATE NOT NULL DEFAULT CURRENT_TIMESTAMP );

#keys table
CREATE TABLE `egov`.`userKeys` ( `userid` VARCHAR(70) NOT NULL , `type` VARCHAR(10) NOT NULL , `publicKey` VARCHAR(300) NOT NULL UNIQUE, `creation` DATE NOT NULL DEFAULT CURRENT_TIMESTAMP , `deprication` DATE );

#Request table
CREATE TABLE `egov`.`request` ( `requestID` VARCHAR(40) NOT NULL PRIMARY KEY, `userid` VARCHAR(70) NOT NULL , `unit` VARCHAR(10) NOT NULL , `subject` VARCHAR(50) NOT NULL , `body` TEXT NOT NULL , `submisionDate` DATE NOT NULL DEFAULT CURRENT_TIMESTAMP , `status` VARCHAR(10) NOT NULL , `comments` TEXT NOT NULL , `integrity` VARCHAR(10) NOT NULL, `proof` VARCHAR(300) NOT NULL);

#Settings
#CREATE TABLE `egov`.`settings` ( `userid` VARCHAR(70) NOT NULL PRIMARY KEY, `phone` INT(10) NOT NULL UNIQUE , `email` VARCHAR(30) NOT NULL UNIQUE , `temporaryCode` INT(6) NOT NULL UNIQUE, `creation` DATE NOT NULL DEFAULT CURRENT_TIMESTAMP , `deprication` DATE NOT NULL );
CREATE TABLE `egov`.`settings` ( `userid` VARCHAR(70) NOT NULL PRIMARY KEY, `phone` INT(10) NOT NULL UNIQUE , `email` VARCHAR(30) NOT NULL UNIQUE , `temporaryCode` INT(6) NOT NULL UNIQUE, `creation` TIME DEFAULT CURRENT_TIME, `deprication` TIME NOT NULL DEFAULT ADDTIME(CURRENT_TIME(), 003000));

# Request status table
CREATE TABLE `egov`.`requestStatus` ( `requestId` VARCHAR(40) NOT NULL PRIMARY KEY, `officialId` VARCHAR(70) NOT NULL , `action` TEXT NOT NULL , `actionTime` DATE NOT NULL DEFAULT CURRENT_TIMESTAMP );

# Nodes table
CREATE TABLE `egov`.`nodes` ( `sno` INT(4) NOT NULL , `ip` VARCHAR(50) NOT NULL PRIMARY KEY, `status` VARCHAR(10) NOT NULL );

#officials
CREATE TABLE `egov`.`officials` ( `officialId` VARCHAR(70) NOT NULL PRIMARY KEY, `name` VARCHAR(50) NOT NULL , `unit` VARCHAR(10) NOT NULL , `email` VARCHAR(30) NOT NULL UNIQUE , `password` VARCHAR(300) NOT NULL , `secret` INT(6) NOT NULL UNIQUE, `registerationTime` DATE NOT NULL DEFAULT CURRENT_TIMESTAMP , `type` VARCHAR(10) NOT NULL, `grade` INT(1) NOT NULL ) ;
