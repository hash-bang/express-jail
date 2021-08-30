var debug = require('debug')('express-jail');
var exec = require('@momsfriendlydevco/exec');
var eventer = require('@momsfriendlydevco/eventer');
var semverGte = require('semver/functions/gte')

/**
* Actual express middleware layer
* @param {Object} [options] Options to adjust behaviour, `expressJail.defaults` is used to populate this
* @returns {ExpressMiddleware} Express compatible middleware function
*
* @emits ban Emitted as `({ip, req?, res?})` before an IP is banned, if the async return is boolean `false` the adding operation is aborted
* @emits banned Emitted as `({ip, req?, res?})` after an IP is banned
*
* @emits unban Emitted as `({ip, req?, res?})` before an IP is unbanned, if the async return is boolean `false` the removal operation is aborted
* @emits unbanned Emitted as `({ip, req?, res?})` after an IP is unbanned
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
		// Fetch + check version {{{
		.then(()=> jailMiddleware.version())
		.then(f2bVersion => settings.minVersion && semverGte(f2bVersion, settings.minVersion) ? true : Promise.reject(`F2B version ${f2bVersion} is lower than required minimum of ${settings.minVersion}`))
		// }}}
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
				return exec([...settings.clientBinary, 'add', settings.jail, 'auto'])
					.catch(e => { throw new Error(`F2B-client jail creation error: ${e.toString()}`) })
			}
		})
		// }}}
		// F2B setup {{{
		.then(()=> jailMiddleware.setup())
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
					return jailMiddleware.ban(req.ip, {req, res})
						.then(()=> res.sendStatus(settings.responseCode))
				} else {
					next();
				}
			})
	};


	/**
	* Setup / configure the F2B jail
	* @returns {Promise} A promise which resolves when the operation has completed
	*/
	jailMiddleware.setup = function expressJailSetup() {
		return Promise.resolve()
			// Setup jail action iptables-multiport if its not already present {{{
			.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'addaction', 'iptables-multiport'])
				.then(()=> Promise.resolve()
					.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'action', 'iptables-multiport', 'actionstart', `iptables -N f2b-${settings.jail}\niptables -A f2b-${settings.jail} -j RETURN\niptables -I INPUT -p tcp -m multiport --dports ${settings.jailPorts} -j f2b-${settings.jail}`])
						.catch(e => { throw new Error(`F2B-client setup-action-start error: ${e.toString()}`) })
					)
					.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'action', 'iptables-multiport', 'actionstop', `iptables -D INPUT -p tcp -m multiport --dports ${settings.jailPorts} -j f2b-${settings.jail}\niptables -F f2b-${settings.jail}\niptables -X f2b-${settings.jail}`])
						.catch(e => { throw new Error(`F2B-client setup-action-stop error: ${e.toString()}`) })
					)
					.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'action', 'iptables-multiport', 'actionflush', `iptables -F f2b-${settings.jail}`])
						.catch(e => { throw new Error(`F2B-client setup-action-flush error: ${e.toString()}`) })
					)
					.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'action', 'iptables-multiport', 'actioncheck', `iptables -n -L INPUT | grep -q 'f2b-${settings.jail}[ \\t]'`])
						.catch(e => { throw new Error(`F2B-client setup-action-check error: ${e.toString()}`) })
					)
					.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'action', 'iptables-multiport', 'actionban', `iptables -I f2b-${settings.jail} 1 -s <ip> -j REJECT --reject-with icmp-port-unreachable`])
						.catch(e => { throw new Error(`F2B-client setup-action-ban error: ${e.toString()}`) })
					)
					.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'action', 'iptables-multiport', 'actionunban', `iptables -D f2b-${settings.jail} -s <ip> -j REJECT --reject-with icmp-port-unreachable`])
						.catch(e => { throw new Error(`F2B-client setup-action-unban error: ${e.toString()}`) })
					)
				)
				.catch(e => {
					if (e === 'Non-zero exit code: 255') return; // Skip already-exists errors
					throw e;
				})
		)
		// }}}
		// Start jail - if not already started {{{
		.then(()=> exec([...settings.clientBinary, 'start', settings.jail]))
		// }}}
	}


	/**
	* Retrieve the Fail2Ban version number
	* @returns {Promise<string>} A promise which resolves when the operation has completed with the F2B version
	*/
	jailMiddleware.version = function expressJailVersion() {
		return Promise.resolve()
			.then(()=> exec([...settings.clientBinary, '--version'], {buffer: true})
				.catch(e => { throw new Error(`F2B-client query-version error: ${e.toString()}`) })
			)
			.then(buf => /^Fail2Ban v(?<version>[\d\.]+).*/m.exec(buf)?.groups.version)
			.then(version => version || Promise.reject('Unable to query Fail2Ban version - is client installed?'))
	}


	/**
	* Ban an incomming IP address by adding it to the F2B jail
	* @param {string} ip The IP address to ban
	* @param {Object} [context] Optional additional named object parameters to pass to emitter
	* @returns {Promise} A promise which resolves when the operation has completed
	*
	*/
	jailMiddleware.ban = function expressJailBan(ip, context) {
		return Promise.resolve()
			.then(()=> jailMiddleware.emit('ban', {ip, ...context}))
			.then(doBan => { if (doBan === false) throw 'SKIP' })
			.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'banip', ip], {buffer: true})
				.catch(e => { throw new Error(`F2B-client add-to-jail error: ${e.toString()}`) })
			)
			.then(()=> jailMiddleware.emit('banned', {ip, ...context}))
			.catch(e => {
				if (e === 'SKIP') return;
				throw e;
			})
	}


	/**
	* Unban an incomming IP address by removing it from the F2B jail
	* @param {string} ip The IP address to unban
	* @param {Object} [context] Optional additional named object parameters to pass to emitter
	* @returns {Promise} A promise which resolves when the operation has completed
	*
	*/
	jailMiddleware.unban = function expressJailUnban(ip, context) {
		return Promise.resolve()
			.then(()=> jailMiddleware.emit('unban', {ip, ...context}))
			.then(doBan => { if (doBan === false) throw 'SKIP' })
			.then(()=> exec([...settings.clientBinary, 'set', settings.jail, 'unbanip', ip], {buffer: true})
				.catch(e => { throw new Error(`F2B-client remove-from-jail error: ${e.toString()}`) })
			)
			.then(()=> jailMiddleware.emit('unbanned', {ip, ...context}))
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
	jailPorts: 'http,https',
	minVersion: '0.11.1',
	setup: true,
};
