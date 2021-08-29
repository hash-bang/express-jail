var debug = require('debug')('express-jail');
var exec = require('@momsfriendlydevco/exec');
var eventer = require('@momsfriendlydevco/eventer');

/**
* Actual express middleware layer
* @param {Object} [options] Options to adjust behaviour, `expressJail.defaults` is used to populate this
* @returns {ExpressMiddleware} Express compatible middleware function
*
* @emits ban Emitted as `({ip})` before an IP is banned, if the async return is boolean `false` the adding operation is aborted
* @emits banned Emitted as `({ip})` after an IP is banned
*
* @emits unban Emitted as `({ip})` before an IP is unbanned, if the async return is boolean `false` the removal operation is aborted
* @emits unbanned Emitted as `({ip})` after an IP is unbanned
*/
var expressJail = module.exports = function expressJailMiddleware(options) {
	var settings = {
		...expressJail.defaults,
		...options,
	};

	// Convert settings.paths into a Set for easier querying / dedupeing
	settings.paths = new Set(settings.paths);

	// Boot & prepare jail
	var bootComplete = false;
	var bootPromise = Promise.resolve()
		// Try pinging server {{{
		.then(()=> exec([...settings.clientBinary, 'ping'], {buffer: true})
			.catch(e => { throw new Error(`F2B-client ping error: ${e.toString()}`) })
			.then(res => res != 'Server replied: pong' && Promise.reject(`Unexpected response when pinging F2B - ${res}`))
		)
		// }}}
		// Query existing jails list {{{
		.then(()=> exec([...settings.clientBinary, 'status'], {buffer: true})
			.catch(e => { throw new Error(`F2B-client status error: ${e.toString()}`) })
		)
		// }}}
		// Check jail exists or create it {{{
		.then(res => {
			var f2bRes = /\- Jail list:\s*(?<jails>.*)/ms.exec(res)?.groups;
			f2bRes = {
				jails: f2bRes?.jails
					? f2bRes.jails.split(/\s*,\s*/)
					: []
			};

			if (f2bRes.jails.includes(settings.jail)) {
				debug(`F2B jail "${settings.jail}" already exists - skipping creation`);
			} else {
				debug(`F2B jail "${settings.jail}" doesnt exist - creating`);
				return exec([...settings.clientBinary, 'add', settings.jail])
					.catch(e => { throw new Error(`F2B-client jail creation error: ${e.toString()}`) })
			}
		})
		// }}}
		// End {{{
		.then(()=> bootComplete = true)
		.catch(e => console.warn('express-jail - setup error', e))
		// }}}

	var jailMiddleware = function(req, res, next) {
		Promise.resolve()
			.then(()=> !bootComplete && bootPromise)
			.then(()=> {
				if (settings.paths.has(req.path)) {
					return jailMiddleware.ban(req.ip, req)
						.then(()=> res.sendStatus(settings.responseCode))
				} else {
					next();
				}
			})
	};


	/**
	* Ban an incomming IP address by adding it to the F2B jail
	* @param {string} ip The IP address to ban
	* @returns {Promise} A promise which resolves when the operation has completed
	*
	*/
	jailMiddleware.ban = function expressJailBan(ip, req) {
		return Promise.resolve()
			.then(()=> jailMiddleware.emit('ban', {ip: ip, req}))
			.then(doBan => { if (doBan === false) throw 'SKIP' })
			.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'banip', ip], {buffer: true})
				.catch(e => { throw new Error(`F2B-client add-to-jail error: ${e.toString()}`) })
			)
			.then(()=> jailMiddleware.emit('banned', {ip: ip, req}))
			.catch(e => {
				if (e === 'SKIP') return;
				throw e;
			})
	}


	/**
	* Unban an incomming IP address by removing it from the F2B jail
	* @param {string} ip The IP address to unban
	* @returns {Promise} A promise which resolves when the operation has completed
	*
	*/
	jailMiddleware.unban = function expressJailUnban(ip, req) {
		return Promise.resolve()
			.then(()=> jailMiddleware.emit('unban', {ip: ip, req}))
			.then(doBan => { if (doBan === false) throw 'SKIP' })
			.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'unbanip', ip], {buffer: true})
				.catch(e => { throw new Error(`F2B-client remove-from-jail error: ${e.toString()}`) })
			)
			.then(()=> jailMiddleware.emit('unbanned', {ip: ip, req}))
			.catch(e => {
				if (e === 'SKIP') return;
				throw e;
			})
	}


	/**
	* Return all bans in the jail
	*/
	jailMiddleware.bans = function expressJailBans(ip) {
		return Promise.resolve()
			.then(()=> exec([...settings.clientBinary, 'get', settings.jail, 'banip', '--with-time'], {buffer: true})
				.catch(e => { throw new Error(`F2B-client query-jail error: ${e.toString()}`) })
			)
			.then(bans => bans.split(/\n/)
				.map(line => /^(?<ip>[\d\.]+)\s+(?<from>[\d\-\s:]+) \+ (?<time>\d+) = (?<to>[\d\-\s:]+)$/.exec(line)?.groups)
				.filter(Boolean)
				.map(ban => ({
					ip: ban.ip,
					from: new Date(ban.from),
					time: parseInt(ban.time),
					to: new Date(ban.to),
				}))
			)
	};


	/**
	* Query if a given IP exists within the jail
	* This is really just a lazy bans() + filter convenience function
	* @param {string} ip The IP to query for
	*/
	jailMiddleware.hasBan = function expressJailHasBan(ip) {
		return jailMiddleware.bans()
			.then(bans => bans.some(ban => ban.ip == ip))
	};


	eventer.extend(jailMiddleware);
	return jailMiddleware;
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

	clientBinary: ['/usr/bin/sudo', '/usr/bin/fail2ban-client'],
	jail: 'www',
};
