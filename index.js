const dotenv = require('dotenv').config({ path: process.env.NODE_ENV ? `.env.${process.env.NODE_ENV}` : '.env' });
const path = require('path');
const fs = require('fs');
const fsPromises = fs.promises;
const serve = require('koa-static');
const views = require('koa-views');
const Koa = require('koa');
const Router = require('koa-router');
const app = new Koa();
const router = new Router();
const passport = require('koa-passport');
const SteamStrategy = require('passport-steam').Strategy;
const session = require('koa-session');
const jwt = require('jsonwebtoken');
const { RETURN_URL, REALM, API_KEY, PRIVATE_KEY, PORT, ADMIN_ROLE, ADMIN_STEAM_ID } = process.env;

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Steam profile is serialized
//   and deserialized.
passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(obj, done) {
    done(null, obj);
});

// Use the SteamStrategy within Passport.
//   Strategies in passport require a `validate` function, which accept
//   credentials (in this case, an OpenID identifier and profile), and invoke a
//   callback with a user object.
passport.use(new SteamStrategy({
        returnURL: RETURN_URL,
        realm: REALM,
        apiKey: API_KEY
    },
    function(identifier, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            // To keep the example simple, the user's Steam profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the Steam account with a user record in your database,
            // and return that user instead.
            profile.identifier = identifier;
            return done(null, profile);
        });
    }
));

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(ctx, next) {
    if (ctx.isAuthenticated()) { return next(); }
    ctx.redirect('/auth/login');
}

app.keys = ['newest secret key', 'older secret key'];

app.use(session(app));
app.use(passport.initialize());
app.use(passport.session());

app.use(views(path.join(__dirname, '/views'), { extension: 'ejs' }));

router.get('/auth/login', async (ctx) => {
    if (!ctx.state.user) {
        await ctx.render('index', { user: ctx.state.user });
    }
    else {
        ctx.redirect('/#/login');
    }
});

router.get('/auth/account', ensureAuthenticated, async (ctx) => {
    await ctx.render('account', { user: ctx.state.user });
});

router.get('/auth/logout', async (ctx) => {
    ctx.logout();
    ctx.redirect('/auth/login');
});

router.get('/auth/steam',
    passport.authenticate('steam', { failureRedirect: '/auth/login' }),
    async (ctx) => {
        ctx.redirect('/');
    }
);

router.get('/auth/steam/return',
    passport.authenticate('steam', { failureRedirect: '/auth/login' }),
    async (ctx) => {
        ctx.redirect('/#/login');
    }
);

router.post('/auth/jwt', async (ctx) => {
    await new Promise((resolve, reject) => {
        if (ctx.state.user) {
            if (ctx.state.user.id === ADMIN_STEAM_ID) {
                jwt.sign({ steamid_64: ctx.state.user.id, role: ADMIN_ROLE }, PRIVATE_KEY, { algorithm: 'HS256' }, function(err, token) {
                    if (err) {
                        ctx.status = 500;
                        ctx.body = {
                            status: 'error',
                            message: 'Authentication error.',
                        };
                        resolve();
                    }
                    else {
                        ctx.body = {
                            status: 'success',
                            token,
                        };
                        resolve();
                    }
                });
            }
            else {
                ctx.status = 403;
                ctx.body = {
                    status: 'error',
                    message: 'Unauthorized user.',
                };
                resolve();
            }
        }
        else {
            ctx.status = 401;
            ctx.body = {
                status: 'error',
                message: 'Not logged in.',
            };
            resolve();
        }
    });
});

const server = app
    .use(router.routes())
    .use(router.allowedMethods())
    .listen(PORT, () => {
        console.log(`Server listening on port: ${PORT}`);
    });

module.exports = server;