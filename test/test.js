var axios = require('axios');
var expect = require('chai').expect;
var express = require('express');
var expressJail = require('..');
var expressLogger = require('express-log-url');

var port = 8181;
var url = `http://localhost:${port}`;
var thisIp = '127.0.0.1'; // This IP address, used when resolving if this client was banned

describe('express-jail', ()=> {

	var app, jail, server;
	before('setup server', finish => {
		app = express();
		app.use(expressLogger);
		app.set('log.indent', '      ');

		jail = expressJail({
			responseCode: 403,
		})
		app.use(jail);

		app.use('/api/foo', (req, res) => res.send({string:'Foo!'}));
		server = app.listen(port, null, finish);
	});

	after('teradown server', ()=> server && server.close());

	before('remove this IP from banlist', ()=> jail.unban(thisIp)
		.catch(()=> false) // Ignore jail not being valid at this stage
	)

	it('should make simple API calls', ()=>
		axios.get(`${url}/api/foo`)
			.then(({data}) => expect(data).be.deep.equal({string:'Foo!'}))
	)

	it('should detect hits to forbidden paths', ()=> {
		var detectedBan = false;
		jail.once('ban', info => detectedBan = true);

		return axios.get(`${url}/.git/HEAD`)
			.then(expect.fail)
			.catch(e => {
				expect(e).to.have.nested.property('response.status', 403);
				expect(detectedBan).to.be.equal(true);
			})
	})

	it('should get the current ban list', ()=>
		jail.bans()
			.then(bans => {
				expect(bans).to.be.an('array');
				bans.forEach(ban => {
					expect(ban).to.have.property('ip');
					expect(ban.ip).to.be.a('string');

					expect(ban).to.have.property('from');
					expect(ban.from).to.be.a('date');

					expect(ban).to.have.property('time');
					expect(ban.time).to.be.a('number');

					expect(ban).to.have.property('to');
					expect(ban.to).to.be.a('date');
				});
			})
	);

	it('should have this IP on the ban list - via jail.bans()', ()=>
		jail.bans()
			.then(bans => {
				expect(bans.some(b => b.ip == thisIp)).to.be.equal(true);
			})
	);

	it('should have this IP on the ban list - via jail.hasBan(ip)', ()=>
		jail.hasBan(thisIp)
			.then(hasBan => {
				expect(hasBan).to.equal(true)
			})
	);

	// NOTE: This is skipped because the method F2B uses to actually ban IP's doesn't work with localhost
	it.skip('subsequent access should timeout', ()=>
		axios.get(`${url}/.git/HEAD`, {timeout: 500})
			.then(expect.fail)
			.catch(e => {
				console.log('TIMEOUT', e);
				expect(e).to.not.have.nested.property('response.status', 403);
			})
	);

	it('should remove the IP from the ban list', ()=>
		jail.unban(thisIp)
	);

	it('should have NOT have this IP on the ban list - via jail.bans()', ()=>
		jail.bans()
			.then(bans => {
				expect(bans.some(b => b.ip == thisIp)).to.be.equal(false);
			})
	);

	it('should have NOT have this IP on the ban list - via jail.hasBan(ip)', ()=>
		jail.hasBan(thisIp)
			.then(hasBan => {
				expect(hasBan).to.equal(false)
			})
	);

});
