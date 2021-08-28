/**
* Actual express middleware layer
* @param {Object} [options] Options to adjust behaviour, `expressJail.defaults` is used to populate this
* @returns {ExpressMiddleware} Express compatible middleware function
*/
var expressJail = module.exports = function expressJailMiddleware(options) {
	var settings = {
		...expressJail.defaults,
		...options,
	};

	// Convert settings.paths into a Set for easier querying / dedupeing
	settings.paths = new Set(settings.paths);

	return function(req, res, next) {
		if (settings.paths.has(req.path)) {
			console.log('DISALLOW FORBIDDEN PATH', req.path);
			res.sendStatus(settings.responseCode);
		} else {
			next();
		}
	};
};

expressJail.defaults= {
	paths: [
		'/ 3ms',
		'/.aws/config',
		'/.env',
		'//secure/ManageFilters.jspa',
		'/.git/HEAD',
		'/id_dsa',
		'/id_rsa',
		'//plugins/servlet/gadgets/makeRequest',
		'/plugins/servlet/Wallboard/',
		'/.svn/entries',
		'/.ssh/id_rsa',
		'/.ssh/id_dsa',
		'/clients/2345/2345.js',
		'/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application',
	],
	responseCode: 404,
};
