CREATE TABLE `url_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`url` text NOT NULL,
	`threatLevel` enum('safe','suspicious','dangerous') NOT NULL,
	`riskScore` int NOT NULL,
	`reasons` text NOT NULL,
	`triggeredRules` text NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `url_scans_id` PRIMARY KEY(`id`)
);
