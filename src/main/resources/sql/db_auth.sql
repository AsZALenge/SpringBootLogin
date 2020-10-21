# Host: localhost  (Version 5.7.17-log)
# Date: 2020-06-23 20:52:09
# Generator: MySQL-Front 6.0  (Build 2.20)


#
# Structure for table "oauth_role"
#

DROP TABLE IF EXISTS `oauth_role`;
CREATE TABLE `oauth_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `role_name` varchar(50) DEFAULT NULL,
  `role_status` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;

#
# Data for table "oauth_role"
#

INSERT INTO `oauth_role` VALUES (1,'ROLE_ADMIN','active'),(2,'ROLE_USER','active');

#
# Structure for table "oauth_user"
#

DROP TABLE IF EXISTS `oauth_user`;
CREATE TABLE `oauth_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `first_name` varchar(100) DEFAULT NULL,
  `last_name` varchar(100) DEFAULT NULL,
  `username` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `role` int(5) DEFAULT NULL,
  `status` varchar(10) DEFAULT NULL,
  `role_entity_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FKl5alypubd40lwejc45vl35wjb` (`role`),
  KEY `FKcgvlbw3uxs532jje6xsul0v8o` (`role_entity_id`),
  CONSTRAINT `FKcgvlbw3uxs532jje6xsul0v8o` FOREIGN KEY (`role_entity_id`) REFERENCES `oauth_role` (`id`),
  CONSTRAINT `FKl5alypubd40lwejc45vl35wjb` FOREIGN KEY (`role`) REFERENCES `oauth_role` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=28 DEFAULT CHARSET=utf8 COMMENT='table user for auth';

#
# Data for table "oauth_user"
#

INSERT INTO `oauth_user` VALUES (13,'artt','user is admin','artt','$2a$10$66zwH6NN4L/7yZ.MsPvtqe8syfa/gCoVl8tIlak/TnyVECJd/54oS',1,'active',NULL),(23,'นาย อมร','นอนวัด','amon','$2a$10$CfBJ44Hr6qBXBBKoWoRQku/1g8QlMtPz8Ee8qZAY4MJ0c6aKCvAtO',2,'active',NULL),(27,'นายสมร','สกุลสัง','smon','$2a$10$BPEUT/JX2v/VvNDakNj5qOZh0AoqH.dq3kxx9gP5PTdCmsfVPgery',2,'active',NULL);
