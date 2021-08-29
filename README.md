express-jail
============
Express middleware which add malicious actors into a [Fail2Ban](https://www.fail2ban.org) jail.

**Notes:**

* This NPM requires `fail2ban` at version `0.11.1` or later to be installed and running to work correctly.
* This module does include a testkit but, due to the way that localhost blocking works on Linux, you will need to use an external facing IP to test it


```javascript
var port = 8080;
var express = require('express');
var expressJail = require('express-jail');

app = express();
app.use(expressJail({
	// Options, if any
}));

// Route setup
app.use('/api/foo', (req, res) => res.send({string:'Foo!'}));
server = app.listen(port);
```


API
===

expressJail(options) - Main Middleware
--------------------------------------
The main middleware factory function of the module.

Called as `(options)` where options is an object which can override the defaults.

Returns an [@momsfriendlydevco/eventer](https://github.com/MomsFriendlyDevCo/eventer) EventEmitter(-like) instance which emits the following:

| Event      | Emitted as             | Description                                                                                                                                    |
|------------|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| `ban`      | `(ip, req?, res?)` | Emitted _before_ the ban cycle concludes can return an async function which could eventually return boolean `false` which will prevent the ban |
| `banned`   | `(ip, req?, res?)` | Emitted _after_ the ban cycle concludes                                                                                                        |
| `unban`    | `(ip)`                 | Emitted when calling `expressJail.unban(ip)`, can return an (eventual) boolean `false` to abort                                                |
| `unbanned` | `(ip)`                 | Emitted when `expressJail.unban(ip)` concluded                                                                                                 |


All emitters can optionally return async Promisables which will be waited on.


expressJail.defaults
--------------------
The default options structure. Can be overridden in each middleware init stage as needed.

| Option         | Type            | Default    | Description                                                         |
|----------------|-----------------|------------|---------------------------------------------------------------------|
| `paths`        | `Array<String>` | See notes  | List of path components to consider malicious                       |
| `responseCode` | `Number`        | `404`      | Initial response code to send before blocking                       |
| `clientBinary` | `Array<Sring>`  | See notes  | Prefix exec paths to access `fail2ban-client`                       |
| `jail`         | `String`        | `"www"`    | Jail name to use within F2B to collect the ban list                 |
| `minVersion`   | `String`        | `"0.11.1"` | Minimum Semver version of F2B to work with, set to falsy to disable |


**Notes:**

* `paths` are pre-populated from a standard list of malicious scans. If you have any to add please file a PR
* `clientBinary` is set to `['/usr/bin/sudo', '/usr/bin/fail2ban-client']` by default. Each argument part should be its own part of the array to be correctly escaped
* `jail` is created before launch if it does not already exist


expressJailInstance.ban(ip)
---------------------------
Can be called manually to ban an IP address.

Returns a Promise which will resolve when the operation has completed.


expressJailInstance.unban(ip)
-----------------------------
Can be called manually to unban an IP address.

Returns a Promise which will resolve when the operation has completed.


expressJailInstance.bans()
--------------------------
Returns a promise which will resolve to a collection of all existing bans in the form `{ip: String, from: Date, time: Number, to: Date}`.


expressJailInstance.hasBan(ip)
------------------------------
Convenience wrapper for `expressJailInstance.bans()` which queries a specific IP address.
Returns a promise which will resolve to a boolean if the provided IP is in the ban list.
