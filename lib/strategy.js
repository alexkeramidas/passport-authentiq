// Load modules.
var OAuth2Strategy = require('passport-oauth2')
    , util = require('util')
    , Profile = require('./profile')
    , InternalOAuthError = require('passport-oauth2').InternalOAuthError
    , APIError = require('./errors/apierror')
    , request = require('request')
    , xtend = require('xtend')
    , jwt = require('jsonwebtoken');


/**
 * `Strategy` constructor.
 *
 * The Authentiq authentication strategy authenticates requests by delegating to
 * Authentiq using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Authentiq application's Client ID
 *   - `clientSecret`  your Authentiq application's Client Secret
 *   - `callbackURL`   URL to which Authentiq will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'aq:name', 'email', 'phone', 'address', 'aq:location', "aq:push" or none.
 *
 * Examples:
 *
 *     passport.use(new AuthentiqStrategy({
 *         clientID: 'Authentiq Client ID',
 *         clientSecret: 'Authentiq Client Secret'
 *         callbackURL: 'https://www.example.net/auth/authentiq/callback',
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
    this.options = xtend({}, options, {
        authorizationURL: options.authorizationURL || 'https://connect.authentiq.io/authorize',
        tokenURL: options.tokenURL || 'https://connect.authentiq.io/token',
        userProfileURL: options.userProfileURL || 'https://connect.authentiq.io/userinfo',
        scopeSeparator: ' ',
        scope: options.scope.indexOf('openid') === -1 ? options.scope += " openid" : options.scope     // append openID if needed
    });

    OAuth2Strategy.call(this, this.options, verify);

    this.name = 'authentiq';

    // this._oauth2.useAuthorizationHeaderforGET(true);

    var self = this;

    var _oauth2_getOAuthAccessToken = this._oauth2.getOAuthAccessToken;
    this._oauth2.getOAuthAccessToken = function (code, params, callback) {
        _oauth2_getOAuthAccessToken.call(self._oauth2, code, params, function (err, accessToken, refreshToken, params) {
            if (err) {
                return callback(err);
            }
            if (!accessToken) {
                return callback({
                    statusCode: 400,
                    data: JSON.stringify(params)
                });
            }

            // We're probably are already clear to continue with the ID token by parsing it but
            //
            // Call the callback with ID token and Access token so that we can call the /userinfo in case something goes wrong

            var tokens = {};
            tokens.accessToken = accessToken;

            if (params.id_token) {
                tokens.idToken = params.id_token;
                callback(null, tokens, refreshToken, params);
            } else {
                callback(null, accessToken, refreshToken, params);
            }
        });
    }
}

util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Authentiq ID.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `authentiq`
 *   - `id`               the user's Authentiq ID
 *   - `displayName`      the user's full name
 *   - `email`            the user's shared email
 *   - `phone`            the user's shared phone
 *   - `address`          the user's shared Address
 *   - `raw`              the users raw data
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */

Strategy.prototype.userProfile = function (accessToken, done) {
    if (accessToken.idToken) {
        var profile = jwt.verify(accessToken.idToken, this.options.clientSecret);
        done(null, profile);
    } else {
        this._oauth2.get(this.options.userProfileURL, accessToken.accessToken, function (err, body, res) {
            var json;

            if (err) {
                if (err.data) {
                    try {
                        json = JSON.parse(err.data);
                    } catch (_) {
                    }
                }

                if (json && json.message) {
                    return done(new APIError(json.message));
                }
                return done(new InternalOAuthError('Failed to fetch user profile', err));
            }

            try {
                json = JSON.parse(body);
            } catch (ex) {
                return done(new Error('Failed to parse user profile'));
            }

            var profile = Profile.parse(json);
            profile.provider = 'authentiq';
            profile._raw = body;
            profile._json = json;
            // return the profile here and let the developer decide what to do with it

            done(null, getProfile(body));
        });
    }
};


function verifyIDToken(idToken) {
    return jwt.verify(idToken, this.options.client_secret);
}

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (options) {
    return {}
};


/**
 * Return extra parameters to be included in the token request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting an access token.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @return {Object}
 * @api protected
 */

OAuth2Strategy.prototype.tokenParams = function (options) {
    return {};
};


/**
 * Parse error response from OAuth 2.0 endpoint.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to parse error responses received from the token endpoint, allowing the
 * most informative message to be displayed.
 *
 * If this function is not overridden, the body will be parsed in accordance
 * with RFC 6749, section 5.2.
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
OAuth2Strategy.prototype.parseErrorResponse = function (body, status) {
    var json = JSON.parse(body);
    if (json.error) {
        return new TokenError(json.error_description, json.error, json.error_uri);
    }
    return null;
};


var obj = '{   "": false,   "phone_number": "+306988544510",   "phone_number_verified": true,   "phone_type": "mobile",   "locale": "en_US",   "nbf": 1493314287,   "middle_name": "G",   "sub": "f2d8248e-d528-5c71-a188-90095c3142ba",   "zoneinfo": "Europe/Athens",   "at_hash": "O9r4OV2NHHLkC3AXQoMrlA",   "given_name": "Alex",   "sid": "8346ea0f-d5df-47ff-a0e0-daf5850386c6",   "iat": 1493314284,   "email": "dev.alexkeramidas@gmail.com",   "_claim_sources": {     "authentiq.io/phone": {       "JWT": "eyJhbGciOiJFZDI1NTE5IiwianRpIjoiSldETUI2TE5aTENEV1A3Nk0yVEYiLCJ0eXAiOiJKV1QiLCJraWQiOiJhT2owWjRIX0pxVmdWckh2TDZDemxJaHVhelFjN2VVdEJoUkdaS3ZIMmY0In0.eyJwaG9uZV9udW1iZXIiOiIrMzA2OTg4NTQ0NTEwIiwicGhvbmVfdHlwZSI6Im1vYmlsZSIsInN1YiI6Ilc5UHpyWDBNT3VaOWRCVXdQLTVaT0sxOVljNDRHQWlvSlFoSDNKc3lEZTQiLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOi8vaWQuYXV0aGVudGlxLmlvLyIsImV4cCI6MTUyNDgxOTczNSwic2NvcGUiOiJwaG9uZSIsImlhdCI6MTQ5MzI4MzczNSwibmJmIjoxNDkzMjgzNDM1LCJwcm9vZiI6InNlbnQgdmVyaWZpY2F0aW9uIGNvZGUifQ.ZIURTlmphXIloJw3KvWlZlEgRHjPVNmNpyQlwamOAYngC0UusZt4iWDwywB_dAg9JbLnOFRIlIaX_qdIO7W0Bg"     },     "authentiq.io/email": {       "JWT": "eyJhbGciOiJFZDI1NTE5IiwianRpIjoiNlNEWFpDSzYzSEs5WVI0Sk1RS1AiLCJ0eXAiOiJKV1QiLCJraWQiOiJyWHVCT2dLMEdQZk5uNGcwT2RJaXZrLTNMakVkV1dUQ2VfSDJ3Z1pzRmRVIn0.eyJzdWIiOiJXOVB6clgwTU91WjlkQlV3UC01Wk9LMTlZYzQ0R0Fpb0pRaEgzSnN5RGU0IiwiaXNzIjoiaHR0cHM6Ly9pZC5hdXRoZW50aXEuaW8vIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImVtYWlsIjoiZGV2LmFsZXhrZXJhbWlkYXNAZ21haWwuY29tIiwiZXhwIjoxNTI0ODE5NzcwLCJzY29wZSI6ImVtYWlsIiwiaWF0IjoxNDkzMjgzNzcwLCJuYmYiOjE0OTMyODM0NzAsInByb29mIjoic2VudCB2ZXJpZmljYXRpb24gY29kZSJ9.7JYmKXDOeC8qeCcGlrd0wkqOn4XbqL5XqfySmsg5_KwIfB3VBSau7XIdNjS3GD8HbIRj33OVvDP1PK10K3ogCA"     }   },   "address": {     "locality": "Larisa",     "country": "Greece",     "formatted": "Agias 22\\nLarisa\\n41221\\nThessaly\\nGreece",     "state": "Thessaly",     "postal_code": "41221",     "street_address": "Agias 22"   },   "aud": "cfdc2f14-cf6f-44b6-a8bb-59594d56c27d",   "family_name": "Keramidas",   "name": "Alex G Keramidas",   "iss": "https://connect.authentiq.io/",   "email_verified": true,   "nonce": null,   "token": "id_token",   "_claim_names": {     "phone_number": "authentiq.io/phone",     "phone_type": "authentiq.io/phone",     "email": "authentiq.io/email",     "phone_number_verified": "authentiq.io/phone",     "email_verified": "authentiq.io/email"   },   "exp": 1493400687,   "auth_time": 1493314284,   "azp": "cfdc2f14-cf6f-44b6-a8bb-59594d56c27d",   "scope": "aq:name phone email address" }';

/**
 * Expose `Strategy` directly from package.
 */

exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports.Strategy = Strategy;