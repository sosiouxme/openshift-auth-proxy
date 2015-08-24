#!/usr/bin/env node

var express        = require('express'),
    sessions       = require('client-sessions'),
    passport       = require('passport'),
    OAuth2Strategy = require('passport-oauth2'),
    BearerStrategy = require('passport-http-bearer'),
    httpProxy      = require('http-proxy'),
    https          = require('https'),
    url            = require('url'),
    urljoin        = require('url-join'),
    request        = require('request'),
    morgan         = require('morgan'),
    parseDuration  = require('parse-duration'),
    fs             = require('fs');

var argv = require('yargs')
  .usage('Usage: $0 [options]')
  .wrap(120)
  .options({
    backend: {
      describe: 'Backend to proxy requests to once authenticated',
      default: process.env.OAP_BACKEND_URL
    }, 'use-backend-host-header': {
      describe: 'Change the host header to the backend URL',
      type: 'boolean',
      default: false
    }, 'listen-port': {
      describe: 'Port to listen on',
      default: Number(process.env.OAP_PROXY_PORT || 3000)
    }, 'auth-mode': {
      describe: 'Proxy auth mode',
      choices:  ['oauth2', 'bearer', 'mutual_tls', 'dummy'],
      default: process.env.OAP_AUTH_MODE || 'oauth2'
    }, 'plugin': {
      describe: 'Plugin for transforming the request/response after authentication',
      choices:  ['user_header', 'kibana_es', 'es', 'none'],
      default: process.env.OAP_PLUGIN || 'user_header'
    }, 'user-header': {
      describe: 'Header for sending user name on the proxied request',
      default: process.env.OAP_REMOTE_USER_HEADER || 'X-Proxy-Remote-User'
    }, 'session-secret': {
      describe: 'File containing secret for encrypted session cookies',
      default: process.env.OAP_SESSION_SECRET_FILE || 'secret/session-secret'
    }, 'session-duration': {
      describe: 'Duration for encrypted session cookies',
      default: parseDuration(process.env.OAP_SESSION_DURATION || '1h')
    }, 'session-active-duration': {
      describe: 'Active duration for encrypted session cookies',
      default: parseDuration(process.env.OAP_SESSION_ACTIVE_DURATION || '5m')
    }, 'session-ephemeral': {
      type: 'boolean',
      describe: 'Delete cookies on browser close',
      default: true
    }, 'callback-url': {
      describe: 'oAuth callback URL',
      default: process.env.OAP_CALLBACK_URL || '/auth/openshift/callback'
    }, 'client-id': {
      describe: 'OAuth client ID',
      default: process.env.OAP_CLIENT_ID
    }, 'client-secret': {
      describe: 'File containing OAuth client secret',
      default: process.env.OAP_CLIENT_SECRET_FILE || 'secret/client-secret'
    }, 'master-url': {
      describe: 'Internal master address proxy will authenticate against',
      default: process.env.OAP_MASTER_URL || 'https://kubernetes.default.svc.cluster.local:8443'
    }, 'public-master-url': {
      describe: 'Public master address for redirecting clients to',
      default: process.env.OAP_PUBLIC_MASTER_URL
    }, 'master-ca': {
      describe: 'CA certificate(s) file to validate connection to the master',
      default: process.env.OAP_MASTER_CA_FILE || 'secret/master-ca'
    }, 'proxy-cert': {
      describe: 'Certificate file to use to listen for TLS',
      default: process.env.OAP_PROXY_CERT_FILE || 'secret/proxy-cert'
    }, 'proxy-key': {
      describe: 'Key file to use to listen for TLS',
      default: process.env.OAP_PROXY_KEY_FILE || 'secret/proxy-key'
    }, 'proxy-tlsopts-file': {
      describe: 'File containing JSON for proxy TLS options',
      default: process.env.OAP_PROXY_TLS_FILE || 'secret/proxy-tls.json'
    }, 'mutual-tls-ca': {
      describe: 'CA cert file to use for validating TLS client certs under "mutual_tls" auth method',
      default: process.env.OAP_PROXY_CA_FILE || 'secret/proxy-ca'
    }, debug: {
      describe: 'Show extra debug information at startup and during operations',
      type: 'boolean',
      default: process.env.OAP_DEBUG
    }
  })
  .check(function(args) {
    // yarg#demand doesn't work if we also provide a default, so check for missing args here
    ["backend", 'proxy-cert', 'proxy-key', 'proxy-tlsopts-file', "session-secret",
     "client-id", "client-secret", 'master-url', 'public-master-url', "master-ca",
     "mutual-tls-ca", 'callback-url'].forEach( function(val) {
      if(args[val] == null || args[val].length == 0) {
        throw("No value specified for parameter " + val);
      }
    });
    if (isNaN(parseFloat(args['listen-port'])) || args['listen-port'] < 1) throw("Invalid listen-port specified");
    return true
  })
  .help('help')
  .epilog('All of these parameters can be set via corresponding environment variables.')
  .argv;

// ---------------------- config --------------------------

//
// read in all the files with secrets, keys, certs
//
var sessionSecret;
try {
  sessionSecret = fs.readFileSync(argv['session-secret'], "utf8");
} catch(err) {
  console.error("error reading session secret: %s", JSON.stringify(e));
} finally { // just ignore if the file is not there
  if (sessionSecret == null ) {
    console.error("generating session secret (will not work with scaled service)");
    sessionSecret = require('base64url')(require('crypto').randomBytes(256)).substring(0, 256);
  }
};
var clientSecret = fs.readFileSync(argv['client-secret'], "utf8").replace(/(\n|\r)/gm,"");
var masterCA = fs.readFileSync(argv['master-ca'], "utf8");
var mutualTlsCa;
try { // it's optional...
  mutualTlsCa = fs.readFileSync(argv['mutual-tls-ca'], "utf8");
} catch(err) {
  if (argv['auth-mode'] === 'mutual_tls') {
    throw "No CA read for mutual TLS. Looked in: " + argv['mutual-tls-ca'];
  } // otherwise, we don't need it
};
var proxyTLS = {};
try { // also optional TLS overrides (ciphersuite etc)
  proxyTLS = fs.readFileSync(argv['proxy-tlsopts-file'], "utf8");
  if (argv.debug) console.log("Read TLS opts from %s: %s", argv['proxy-tlsopts-file'], proxyTLS);
  proxyTLS = eval(proxyTLS);
  if (proxyTLS == null || ! typeof proxyTLS === 'object') {
    throw("TLS opts file did not evaluate to an object");
  }
} catch(e) {
  console.error("Could not read TLS opts from %s; error was: %s", argv['proxy-tlsopts-file'], e);
  proxyTLS = {};
} finally {
  proxyTLS['key'] = fs.readFileSync(argv['proxy-key'], "utf8");
  proxyTLS['cert'] = fs.readFileSync(argv['proxy-cert'], "utf8");
  if (argv.debug) {
    console.log("in finally, proxyTLS is:");
    console.log(proxyTLS);
  }
};
if(argv['debug']) {
  console.log("config values passed in:");
  var arg;
  for (arg in argv) {
    console.log("%s", arg + ": " + argv[arg]);
  }
  ["sessionSecret", "clientSecret", "masterCA", "mutualTlsCa", "proxyTLS"].forEach( function(val) {
    console.log("%s: ", val, eval(val));
  })
}

//
// ensure we validate connections to master w/ master CA
//
var cas = https.globalAgent.options.ca || [];
cas.push(masterCA);
https.globalAgent.options.ca = cas;

// where to get OpenShift user information for current auth
var openshiftUserUrl = urljoin(argv['master-url'], '/oapi/v1/users/~');

//
// ---------------------- passport auth --------------------------
//

//
// set up for passport authentication if it will be needed
//
function noSerialization(user, done) {
  done(null, user);
}

var validateBearerToken = function(accessToken, refreshToken, profile, done) {
  if (argv.debug) console.log("in validateBearerToken: ", accessToken, refreshToken, profile);
  if (!accessToken) {
    if (argv.debug) console.log("no access token, done.");
    done();
  }
  var authOptions = {
    url: openshiftUserUrl,
    headers: {
      authorization: 'Bearer ' + accessToken
    }
  };
  var authReq = request.get(authOptions);
  authReq.on('response', function(authRes) {
    if(argv.debug) console.log("in authReq");
    if (authRes.statusCode != 200) {
      done();
    } else {
      // collect response data, could be chunked
      var data = '';
      authRes.on('data', function (chunk){
        data += chunk;
      });
      authRes.on('end',function(){
        var user = JSON.parse(data);
        done(null, user);
      });
    }
  });
};

var setupOauth = function(app) {
  passport.use(new OAuth2Strategy({
      authorizationURL: urljoin(argv['public-master-url'], '/oauth/authorize'),
      tokenURL: urljoin(argv['master-url'], '/oauth/token'),
      clientID: argv['client-id'],
      clientSecret: clientSecret,
      callbackURL: argv['callback-url']
    },
    validateBearerToken
  ));
  app.use(sessions({
    cookieName: 'openshift-auth-proxy-session',
    requestKey: 'session',
    secret: sessionSecret, // should be a large unguessable string
    duration: parseDuration('' + argv['session-duration']), // how long the session will stay valid in ms
    activeDuration: parseDuration('' + argv['session-active-duration']), // if expiresIn < activeDuration, the session will be extended by activeDuration milliseconds,
    cookie: {
      ephemeral: argv['session-ephemeral']
    }
  }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.get(argv['callback-url'], function(req, res) {
    if(argv['debug']) {
      console.log("in validateBearerToken for req path " + req.path);
    }
    var returnTo = req.session.returnTo;
    passport.authenticate(argv['auth-mode'])(req, res, function() {
      res.redirect(returnTo || '/');
    });
  });
}

var useSession = false;
var ensureAuthenticated = function(req, res, next) {
  if (argv.debug) console.log("in passport.ensureAuthenticated for req path " + req.path);
  if (req.isAuthenticated()) {
    return next();
  }
  if (useSession) {
    req.session.returnTo = req.path;
  }
  passport.authenticate(argv['auth-mode'], {session: useSession})(req, res, next);
}

//
// ---------------------- proxy and handler --------------------------
//

//
// Create the handler for proxy server requests
//
var app = express();
app.use(morgan('combined')) // standard "combined" proxy log output

//
// Implement the configured authentication method handler
//
switch(argv['auth-mode']) {
  case 'oauth2':
    useSession = true;
    setupOauth(app);
    // NO break, should implement bearer too
  case 'bearer':
    passport.use(new BearerStrategy(
      function(token, done) {
        validateBearerToken(token, null, null, done);
      }
    ));
    app.use(passport.initialize());
    passport.serializeUser(noSerialization);
    passport.deserializeUser(noSerialization);
    break;
  case 'mutual_tls':
    if (mutualTlsCa == null) {
      throw "must supply 'mutual-tls-ca' to validate client connection";
    }
    proxyTLS['ca'] = mutualTlsCa;
    proxyTLS['requestCert'] = true;
    proxyTLS['rejectUnauthorized'] = true;
    ensureAuthenticated = function(req, res, next) {
      if (argv.debug) console.log("in mutual_tls.ensureAuthenticated for req path " + req.path);
      if (argv.debug) console.log("client cert is: ", req.connection.getPeerCertificate());
      req.user = { metadata: { name: req.connection.getPeerCertificate().subject['CN'] }};
      return next();
    };
    break;
  case 'dummy':
    ensureAuthenticated = function(req, res, next) {
      if (argv.debug) console.log("in dummy.ensureAuthenticated for req path " + req.path);
      req.user = { metadata: { name: 'dummy'}};
      return next();
    };
    break;
};

//
// Implement the configured request plugin(s)
//
plugins = typeof(argv.plugin) === "string" ? [ argv.plugin ] : argv.plugin;
function pluginHandler(proxyReq, req, res, options) {
  plugins.forEach(function (name){
    switch (name) {
      case 'user_header':
        if (argv.debug) console.log("setting %s header to '%s'",argv['user-header'], req.user.metadata.name);
        proxyReq.setHeader(argv['user-header'], req.user.metadata.name);
	break;
      case 'kibana_es':
        var reqUrl = url.parse(req.url);
	if (reqUrl.pathname.indexOf('/.kibana') == 0) {
	  // need to rewrite to user-specific kibana index
	  reqUrl.pathname = reqUrl.pathname.replace(/^\/\.kibana/, "/.kibana-" + req.user.metadata.name)
          if (argv.debug) console.log("rewriting path to '%s'", url.format(reqUrl));
          proxyReq.path = url.format(reqUrl);
	}
	break;
      case 'es':
	break;
    }
  });
}

//
// Set up the proxy server to delegate to our handlers
//
var proxy = new httpProxy.createProxyServer({
  target: argv.backend,
  changeOrigin: argv['use-backend-host-header'],
  xfwd: true,
  ws: true
});
proxy.on('error', function(e) {
  console.error("proxy error: %s", JSON.stringify(e));
});
proxy.on('proxyReq', pluginHandler);

app.all('*', ensureAuthenticated, function(req, res) {
  proxy.web(req, res);
});

console.log("Starting up the proxy with auth mode '%s' and proxy plugin '%s'.", argv['auth-mode'], argv['plugin'] )
https.createServer(proxyTLS, app).listen(argv['listen-port']);

