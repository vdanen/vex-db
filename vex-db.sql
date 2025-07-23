DROP TABLE IF EXISTS `cve`;
CREATE TABLE `cve` (
    `cve` VARCHAR(18),
    `cvss_score` FLOAT,
    `cvss_metrics` VARCHAR(48),
    `severity` VARCHAR(10),
    `public_date` TEXT,
    `updated_date` TEXT,
    `description` TEXT,
    `mitigation` TEXT,
    `statement` TEXT,
    PRIMARY KEY(`cve`)
);

DROP TABLE IF EXISTS `affects`;
CREATE TABLE `affects` (
    `cve` VARCHAR(18),
    `product` TEXT,
    `cpe` TEXT,
    `purl` TEXT,
    `errata` TEXT,
    `release_date` TEXT,
    `state` TEXT,
    `reason` TEXT,
    `components` TEXT
);
  
