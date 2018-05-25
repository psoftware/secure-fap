DROP TABLE IF EXISTS users;
CREATE TABLE users(username varchar(50) primary key, password varchar(128), salt varchar(32));
-- provaatonio
INSERT INTO users VALUES('antonio','58c417e10e066b0a11665eb13ebb6dabdbc3900ccbf2c7d3199fcea277faa154', 'salT123salt456789bigsalt77819mm');
-- provaconsales
INSERT INTO users VALUES('vincenzo','bb021ee90a61b773c253adf23a4af73354bf259ef5e6f0785b21c9c6dd6c9e36', 'ZAZZ123saltTh_2j7awssaltyhz_9x2');
