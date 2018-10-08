'use strict';

/**
 * Module dependencies.
 */

var RestifyOAuthServer = require('../../');
var InvalidArgumentError = require('oauth2-server/lib/errors/invalid-argument-error');
var NodeOAuthServer = require('oauth2-server');
var restify = require('restify');
var request = require('supertest');
var should = require('should');
var sinon = require('sinon');

/**
 * Test `RestifyOAuthServer`.
 */

describe('RestifyOAuthServer', function() {
  var app;

  beforeEach(function() {
    app = restify.createServer();

    app.use(restify.plugins.queryParser());
    app.use(restify.plugins.bodyParser());

    app.get('/', function(req, res, next) {
        res.json(200, {success: true});
    });
    app.post('/', function(req, res, next) {
        next(false);
    });
  });
  
  afterEach(function() {
    app.close();
  });

  describe('constructor()', function() {
    it('should throw an error if `model` is missing', function() {
      try {
        new RestifyOAuthServer({});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `model`');
      }
    });

    it('should set the `server`', function() {
      var oauth = new RestifyOAuthServer({ model: {} });

      oauth.server.should.be.an.instanceOf(NodeOAuthServer);
    });
  });

  describe('authenticate()', function() {
    it('should return an error if `model` is empty', function(done) {
      var oauth = new RestifyOAuthServer({ model: {} });

      app.use(oauth.authenticate());

      request(app.listen())
        .get('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getAccessToken()`' })
        .end(done);
    });

    it('should authenticate the request', function(done) {
      var tokenExpires = new Date();
      tokenExpires.setDate(tokenExpires.getDate() + 1);

      var token = { user: {}, accessTokenExpiresAt: tokenExpires };
      var model = {
        getAccessToken: function() {
          return token;
        }
      };
      var oauth = new RestifyOAuthServer({ model: model });

      app.use(oauth.authenticate());

      request(app.listen())
        .get('/')
        .set('Authorization', 'Bearer foobar')
        .expect(200)
        .end(done);
    });

    it('should cache the authorization token', function(done) {
      var tokenExpires = new Date();
      tokenExpires.setDate(tokenExpires.getDate() + 1);
      var token = { user: {}, accessTokenExpiresAt: tokenExpires };
      var model = {
        getAccessToken: function() {
          return token;
        }
      };
      var oauth = new RestifyOAuthServer({ model: model });

      app.use(oauth.authenticate());
      
      var spy = sinon.spy(function(req, res, next) {
        req.authorization.oauth.token.should.equal(token);
        next();
      });
      app.use(spy);

      request(app.listen())
        .get('/')
        .set('Authorization', 'Bearer foobar')
        .expect(200, function(err){
            spy.called.should.be.True();
            done(err);
        });
    });
  });

  describe('authorize()', function() {
    it('should cache the authorization code', function(done) {
      var tokenExpires = new Date();
      tokenExpires.setDate(tokenExpires.getDate() + 1);

      var code = { authorizationCode: 123 };
      var model = {
        getAccessToken: function() {
          return { user: {}, accessTokenExpiresAt: tokenExpires };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
        },
        saveAuthorizationCode: function() {
          return code;
        }
      };
      var oauth = new RestifyOAuthServer({ model: model, continueMiddleware: true });

      app.use(oauth.authorize());

      var spy = sinon.spy(function(req, res, next) {
        req.authorization.oauth.code.should.equal(code);
        return next();
      });
      app.use(spy);

      request(app.listen())
        .post('/?state=foobiz')
        .set('Authorization', 'Bearer foobar')
        .send('client_id=12345&response_type=code')
        .expect(302, function(err){
            spy.called.should.be.True();
            done(err);
        });
    });

    it('should return an error', function(done) {
      var model = {
        getAccessToken: function() {
          return { user: {}, accessTokenExpiresAt: new Date() };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
        },
        saveAuthorizationCode: function() {
          return {};
        }
      };
      var oauth = new RestifyOAuthServer({ model: model });

      app.use(oauth.authorize());

      request(app.listen())
        .post('/?state=foobiz')
        .set('Authorization', 'Bearer foobar')
        .send('client_id=12345')
        .expect(400, function(err, res) {
          res.body.error.should.eql('invalid_request');
          res.body.error_description.should.eql('Missing parameter: `response_type`');
          done(err);
        });
    });

    it('should return a `location` header with the code', function(done) {
      var model = {
        getAccessToken: function() {
          return { user: {}, accessTokenExpiresAt: new Date() };
        },
        getClient: function() {
          return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
        },
        saveAuthorizationCode: function() {
          return { authorizationCode: 123 };
        }
      };
      var oauth = new RestifyOAuthServer({ model: model });

      app.use(oauth.authorize());

      request(app.listen())
        .post('/?state=foobiz')
        .set('Authorization', 'Bearer foobar')
        .send('client_id=12345&response_type=code')
        .expect('Location', 'http://example.com/?code=123&state=foobiz')
        .end(done);
    });

    it('should return an error if `model` is empty', function(done) {
      var oauth = new RestifyOAuthServer({ model: {} });

      app.use(oauth.authorize());

      request(app)
        .post('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getClient()`' })
        .end(done);
    });
  });

  describe('token()', function() {
    it('should cache the authorization token', function(done) {
      var token = { accessToken: 'foobar', client: {}, user: {} };
      var model = {
        getClient: function() {
          return { grants: ['password'] };
        },
        getUser: function() {
          return {};
        },
        saveToken: function() {
          return token;
        }
      };
      var oauth = new RestifyOAuthServer({ model: model, continueMiddleware: true });

      app.use(oauth.token());
      var spy = sinon.spy(function(req, res, next) {
        req.authorization.oauth.token.should.equal(token);

        return next();
      });
      app.use(spy);

      request(app.listen())
        .post('/')
        .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
        .expect({ access_token: 'foobar', token_type: 'Bearer' })
        .expect(200, function(err){
          spy.called.should.be.True();
          done(err);
        });
    });

    it('should return an `access_token`', function(done) {
      var model = {
        getClient: function() {
          return { grants: ['password'] };
        },
        getUser: function() {
          return {};
        },
        saveToken: function() {
          return { accessToken: 'foobar', client: {}, user: {} };
        }
      };
      sinon.spy();
      var oauth = new RestifyOAuthServer({ model: model, continueMiddleware: true });

      app.use(oauth.token());
      request(app.listen())
        .post('/')
        .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
        .expect({ access_token: 'foobar', token_type: 'Bearer' })
        .end(done);
    });

    it('should return a `refresh_token`', function(done) {
      var model = {
        getClient: function() {
          return { grants: ['password'] };
        },
        getUser: function() {
          return {};
        },
        saveToken: function() {
          return { accessToken: 'foobar', client: {}, refreshToken: 'foobiz', user: {} };
        }
      };
      var oauth = new RestifyOAuthServer({ model: model });

      app.use(oauth.token());

      request(app.listen())
        .post('/')
        .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
        .expect({ access_token: 'foobar', refresh_token: 'foobiz', token_type: 'Bearer' })
        .end(done);
    });

    it('should return an error if `model` is empty', function(done) {
      var oauth = new RestifyOAuthServer({ model: {} });

      app.use(oauth.token());

      request(app.listen())
        .post('/')
        .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getClient()`' })
        .end(done);
    });
  });
});
