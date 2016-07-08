/**
 * Simple authentication and authorization example with passport, node_acl,
 *  MongoDB and expressjs
 *
 * The example shown here uses local userdata and sessions to remember a
 *  logged in user. Roles are persistent all the way and applied to user
 *  after logging in.
 *
 * Usage:
 *  1. Start this as server
 *  2. Play with the resoures
 *
 *     Login via GET: http://localhost:3500/login?username=bob&password=secret
 *
 *     Logout: http://localhost:3500/logout
 *
 *     Get user info and roles: http://localhost:3500/status
 *
 *     Only visible for users and higher: http://localhost:3500/secret
 *
 *     Manage roles - user is {1, 2}; role is {'guest', 'user', 'admin'}
 *      http://localhost:3500/allow/:user/:role
 *      http://localhost:3500/disallow/:user/:role
 */

var express = require('express');
var mongodb = require('mongodb');
var passport = require( 'passport' );
var node_acl = require('acl');
var localStrategy = require( 'passport-local' ).Strategy;

var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var expressSession = require('express-session');

var app = express();
var acl;

const SESSION_SECRET = "example";

// Some test data. Get this from your database.
var users = [
    { id: 1, username: 'bob', password: 'secret', email: 'bob@example.com' },
    { id: 2, username: 'joe', password: 'birthday', email: 'joe@example.com' }
];

app.use( cookieParser(SESSION_SECRET) );
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(methodOverride('X-HTTP-Method-Override'));
app.use(expressSession(
    {
        secret: SESSION_SECRET,
        cookie: {
            secure: false,   //not require HTTPS to transmit cookie
            maxAge: 2628000000  //ms
        },
        resave: false,  //we call req.session.save() to store session back to store by ourselves.
        saveUninitialized: false,   //A session is uninitialized when it is new but not modified
        rolling: true
    })
);

// Initialize Passport. Also use passport.session() middleware, to support persistent login sessions.
app.use( passport.initialize() );
app.use( passport.session() );

// Error handling
app.use( function( error, request, response, next ) {
    if( ! error ) {
        return next();
    }
    response.send( error.msg, error.errorCode );
});

/*===================Authentication setup====================*/

// Setup session support
passport.serializeUser( function( user, done ) {
    done( null, user.id );
});

passport.deserializeUser( function( id, done ) {
    function find_user_by_id( id, callback ) {

        var index = id - 1;

        if ( users[ index ] ) {
            callback( null, users[ index ] );
        } else {
            var error = new Error( 'User does not exist.' );
            error.status = 404;
            callback( error );
        }
    }

    find_user_by_id( id, function ( error, user ) {
       done( error, user );
    });
});

// Setup strategy (local in this case)
passport.use( new localStrategy(

    function( username, password, done ) {
        process.nextTick( function () {
            function find_by_username( username, callback ) {

                var usersLength = users.length,
                    i;

                for ( i = 0; i < usersLength; i++ ) {
                    var user = users[ i ];
                    if ( user.username === username ) {
                        return callback( null, user );
                    }
                }

                return callback( null, null );
            }

            find_by_username( username, function( error, user ) {

                if ( error ) {
                    return done( error );
                }

                if ( ! user ) {
                    return done( null, false, { message: 'Unknown user ' + username } );
                }

                if ( user.password != password ) {
                    return done( null, false, { message: 'Invalid password' } );
                }

                // Authenticated
                return done( null, user );
            });
        });
    }
));

/*=========================Authorization setup=============================*/
mongodb.connect( 'mongodb://127.0.0.1:27017/acl', authorization_setup );
function authorization_setup( error, db ) {

    var mongoBackend = new node_acl.mongodbBackend( db /*, {String} prefix */ );
    acl = new node_acl(
        mongoBackend,
        logger()
    );

    set_roles();
    set_routes();
}

function set_roles() {

    acl.allow(
        [
            {
                roles: 'admin',
                allows: [
                    { resources: '/secret', permissions: '*' }
                ]
            },
            {
                roles: 'user',
                allows: [
                    { resources: '/secret', permissions: 'get' }
                ]
            },
            {
                roles: 'guest',
                allows: []
            }
        ]
    );

    acl.addRoleParents( 'user', 'guest' );
    acl.addRoleParents( 'admin', 'user' );

    acl.allow('guest', 'blogs', ['view', 'delete']);
}

function set_routes() {

    app.get('/status',
        function(request, response) {
            acl.userRoles( get_loggedin_user_id(request, response), function(error, roles ){
                response.send( 'User: ' + JSON.stringify( request.user ) + ' Roles: ' + JSON.stringify( roles ) );
            });
        }
    );

    app.get('/secret',
        [
            authenticated,
            acl.middleware( 1, get_loggedin_user_id )
        ],
        function(request, response) {
            response.send('Welcome Sir!');
        }
    );

    app.get( '/logout',
        function(request, response) {
            request.logout();
            response.send('Logged out!');
        }
    );

    app.get( '/login',
        passport.authenticate('local',
            {}
        ),
        function(request, response) {
            response.send('Logged in!');
        }
    );

    app.get('/allow/:user/:role',
        function( request, response, next ) {
            acl.addUserRoles(request.params.user, request.params.role);
            response.send(request.params.user + ' is a ' + request.params.role);
        }
    );

    app.get('/disallow/:user/:role',
        function(request, response, next) {
            acl.removeUserRoles(request.params.user, request.params.role);
            response.send(request.params.user + ' is not a ' + request.params.role + ' anymore.');
        }
    );
}

/*============================Utilities============================*/
function get_loggedin_user_id(request, response ) {

    // Since numbers are not supported by node_acl in this case, convert them to strings, so we can use IDs nonetheless.
    return request.user && request.user.id.toString() || false;
}

function logger() {
    return {
        debug: function( msg ) {
            console.log( '-DEBUG-', msg );
        }
    };
}

// Authentication middleware for passport
function authenticated( request, response, next ) {

    if ( request.isAuthenticated() ) {
        return next();
    }
    response.send( 401, 'User not authenticated' );
}

/*=========================Bring server up=========================*/
app.listen( 3500, function() {
    console.log( 'Express server listening on port 3500' );
});
