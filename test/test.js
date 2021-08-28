var axios = require('axios');
var expect = require('chai').expect;
var express = require('express');
var expressJail = require('..');
var expressLogger = require('express-log-url');

var port = 8181;
var url = `http://localhost:${port}`;

describe('express-fail2ban', ()=> {

	var app, server;
	before('setup dummy server', finish => {
		app = express();
		app.use(expressLogger);
		app.set('log.indent', '      ');
		app.use(expressJail({
			responseCode: 403,
		}));
		app.use('/api/foo', (req, res) => res.send({string:'Foo!'}));
		server = app.listen(port, null, finish);
	});

	after('teradown server', ()=> server && server.close());

	it('should make simple API calls', ()=>
		axios.get(`${url}/api/foo`)
			.then(({data}) => expect(data).be.deep.equal({string:'Foo!'}))
	)

	it('should detect hits to forbidden paths', ()=>
		axios.get(`${url}/.git/HEAD`)
			.then(expect.fail)
			.catch(e => {
				expect(e).to.have.nested.property('response.status', 403);
			})
	)

});
