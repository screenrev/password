var crypto = require('crypto');
var SALT_L = 8;
var ALGORITHM = 'sha1';


exports.generate = function(password) {
	var salt = generateSalt();
	return generateHash(password, salt);
};


exports.verify = function(password, hashedPassword) {
	if (!password || !hashedPassword) return false;
	var salt = hashedPassword.slice(0, 8);
	return generateHash(password, salt) == hashedPassword;
};


var generateSalt = function() {
	return crypto.randomBytes(~~(SALT_L / 2)).toString('hex').substring(0, SALT_L);
};


var generateHash = function(password, salt) {
	var hash = crypto.createHmac(ALGORITHM, salt).update(password).digest('hex');
	return salt + hash;
};
