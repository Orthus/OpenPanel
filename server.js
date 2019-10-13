const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const r = require('rethinkdb');
const path = require('path');
var flash = require('connect-flash');
var bcrypt = require('bcrypt-nodejs');
var passport = require('passport');
var local = require('passport-local').Strategy;
const exec = require('child_process').exec;
const args = process.argv;
const config = require(__dirname + '/config.json');
var fs = require('fs');
var util = require('util');
var http = require('http');
var inspect = require('util').inspect;
var fileUpload = require('express-fileupload')
var Busboy = require('busboy');
var log_file = fs.createWriteStream(__dirname + '/debug.log', {flags : 'w'});
var log_stdout = process.stdout;
var favicon = require('serve-favicon');
console.log = function(d) { //
  log_file.write(util.format(d) + '\n');
  log_stdout.write(util.format(d) + '\n');
};
//
app.use(require('morgan')('combined'));
app.use(require('cookie-parser')());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(require('express-session')({ secret: 'control_the_move', resave: false, saveUninitialized: false }));
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(favicon(path.join(__dirname,'public','images','favicon.ico')));
app.set('view engine', 'ejs');

app.use(fileUpload({
  limits: { fileSize: 50 * 1024 * 1024 },
}));

app.use(fileUpload({
    useTempFiles : true,
    tempFileDir : '/tmp/'
}));

app.use(function (req, res, next) {
  res.locals.login = req.isAuthenticated();
  next();
});

// Config
var webport = config.Port;
var address = config.IP_Address;
var connection = null;
r.connect( {host: config.DB_Address, port: config.DB_Port, db: config.DB_Name}, function(err, conn) {
    if (err) throw err;
    connection = conn;
});
app.listen(webport,address, function(){
  console.log('Server Manager is now listening on ' + webport  + " using db: " + config.DB_Name );
});
var passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy;
passport.use(new local(
  function(username, password, done) {
    r.db(config.DB_Name).table('users').filter(r.row('username').eq(username)).run(connection, function (err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false); }

      user.toArray(function(err, result) {
          if (err) throw err;
          if (result.length == 0) { return done(null, false); }
          if (!bcrypt.compareSync(password, result[0].password)) { return done(null, false); }
          return done(null, result[0]);
      });
    });
  }
));
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function (id, done) {
  r.db(config.DB_Name).table('users').filter(r.row('id').eq(id)).run(connection, function(err, user) {
    if (err) { return done(err); }
    if (!user) { return done(null, false); }
    user.toArray(function(err, result) {
        if (err) throw err;
        return done(null, result[0]);
    });
  });
});

//Site
//Gets
//app.get('/favicon.ico', (req, res) => res.status(204));
// welcome page
app.get('/', function (req, res) {
  active = "Home";
  let displayname;
  let profile;
  if(req.isAuthenticated()){
    displayname=req.user.username;
    let profile;
    profile = user_model(req.user.id);
    id = req.user.id;
  }
  else{
    displayname="null";
    id = "null";
  }
  res.render('template', {username: displayname,profile_pic: profile,authed: req.isAuthenticated(), content:'index', path:'home', result: null, error: null, active: active});
});

app.get('/login', loggedOut, function (req, res) {
  active = "Account";
  let displayname;
  displayname="null";
  res.render('template', {authed: req.isAuthenticated(), content:'login', path:'home', result: null, error: null, active: active});
});

app.get('/register', loggedOut, function (req, res) {
  active = "Home";
  let displayname;
  displayname="null";
  res.render('template', {authed: req.isAuthenticated(), content:'register', path:'home', username: displayname, result: null, error: null, active: active});
});

// home
app.get('/home/:page', loggedIn, function (req, res) {
  active = "Home";
  profile = user_model(req.user.id);
  res.render('template', {authed: req.isAuthenticated(), content:req.params.page, path:'home', username: req.user.username, id: req.user.id, result: null, error: null, active: active});
});

app.get('/account', loggedIn, function (req, res) {
  console.log(req.user.id)
  active = "Account";
  profile = user_model(req.user.id);
  res.render('template', {authed: req.isAuthenticated(), content:'index', path:'account', username: req.user.username, id: req.user.id, result: null, error: null, active: active});
});

app.get('/about', function (req, res) {
  active = "About";
  let displayname;
  if(req.isAuthenticated()){
    displayname=req.user.username;
    profile = user_model(req.user.id);
  }
  else{
    displayname="null";
  }
  res.render('template', {authed: req.isAuthenticated(), content:'index', path:'about',username: displayname, result: null, error: null, active: active});
});
// Settings
app.get('/settings', loggedIn, function (req, res) {
  active = "Settings";
  profile = user_model(req.user.id);
  res.render('template', {authed: req.isAuthenticated(), content:'index', path:'settings', username: req.user.username, id: req.user.id, result: null, error: null, active: active});
});
app.get('/settings/:page', loggedIn, function (req, res) {
  active = "Settings";
  profile = user_model(req.user.id);
  res.render('template', {authed: req.isAuthenticated(), content:req.params.page, path:'settings', username: req.user.username, id: req.user.id, result: null, error: null, active: active});
});
// dashboard

app.get('/dashboard', loggedIn, function (req, res) {
  active = "Dashboard";
  profile = user_model(req.user.id);
  let list = list_all(req.user.id).then(data => {
    let Filtered_data = data;
    console.log("wat");
    res.render('template', {authed: req.isAuthenticated(), content:'index', page:'overview', path:'dashboard', username: req.user.username, id: req.user.id, result: Filtered_data, error: null, active: active});    }).catch(err => {
  });;
});
app.get('/dashboard/:page', loggedIn, function (req, res) {
  active = "Dashboard";
  profile = user_model(req.user.id);
  res.render('template', {authed: req.isAuthenticated(), content:'index', page:req.params.page, path:'dashboard', username: req.user.username, id: req.user.id, result: null, error: null, active: active});
});
//Instance Page
app.get('/Server/:Server_ID', loggedIn, function (req, res) {
  active = "Dashboard";
  profile = user_model(req.user.id);
  let list = list_all(req.user.id).then(data => {
    let Filtered_data = data;
    console.log("wat");
    res.render('template', {authed: req.isAuthenticated(), content:'server_page', path:'Server', username: req.user.username, id: req.user.id, result: Filtered_data, error: null, active: active});    }).catch(err => {
  });;
});
// Create Server
app.get('/submit', loggedIn, function (req, res) {
  res.render('index', {authed: req.isAuthenticated(), result: null, error: null});
});
// navigation search
app.get('/TMR/', function (req, res) {
  let lookup = search(req.query.Server_ID).then(data => {
  res.render('TMR', {authed: req.isAuthenticated(), result: JSON.parse(data), error: null});
  }).catch(err => {
  });;
});
// logout
app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});
// APP Posts
//user
app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login',
      failureFlash: true }), function(req, res) {
        if (req.body.remember) {
          req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // Cookie expires after 30 days
        } else {
          req.session.cookie.expires = false; // Cookie expires at end of session
        }
      res.redirect('/dashboard');
});
app.post('/register', function (req, res) {
  let newusername = req.body.newusername;
  let newpassword = req.body.newpassword
  console.log(newusername + ": " + newpassword);
  adduser(req.body.newusername, req.body.newpassword);
  active = "Home";
  let displayname;
  if(req.isAuthenticated()){
    displayname=req.user.username;
  }
  else{
    displayname="null";
  }
  res.render('template', {authed: req.isAuthenticated(), content:'register', path:'home', username: displayname, result: null, error: null, active: active});
});

// server
app.post('/submit', function (req, res) {
  let send = query();
  res.render('index', {result: null, error:null});
});
app.post('/update/:Server_ID', function (req, res) {
  let send = update();
  res.render('index', {result: null, error:null});
});
app.post('/create_Server', function (req,res) {
  let game = req.body.Game;
  let slots = req.body.Slots;
  let ip = req.body.IP_Address;
  let hostname = req.body.Hostname;
  let name = req.body.ServerName;
  let owner = req.user.id;
  let ram = req.body.RAM_Value ;
  let storage = req.body.Storage_Value;
  let backup = req.body.Backup_Value;
  let send = query(game, slots, ip, hostname, name, owner, ram, storage, backup);
  res.redirect('/dashboard');
  // body...
})
//API
//Gets
app.get('/lookup/:Server_ID', function (req, res) {
  let lookup = search(req.params.Server_ID).then(data => {
  res.json(JSON.parse(data));
  }).catch(err => {
  });;
});
//Posts


// error pages
app.use(function(req, res) {
  res.status(404);
  res.render('template', {authed: req.isAuthenticated(), content:'404', path:'errors', username: displayname, result: null, error: null, active: 'null'});
});
app.use(function(error, req, res, next) {
  console.log(error);
  res.status(500);
  res.render('template', {authed: req.isAuthenticated(), content:'500', path:'errors', username: displayname, result: null, error: null, active: 'null'});
});
// Functions
function query(game, slots, ip, hostname, name, owner, ram, storage, backup){
  return new Promise ( (resolve, reject) => {
	  r.table("servers").insert({
      game: game,
      slots: slots,
      ip: ip,
      hostname: hostname,
      name: name,
      owner: owner,
      ram: ram,
      storage: storage,
      backup: backup,
      status: "OFFLINE",
}).run(connection, function(err, cursor){
		if (err) {
			return reject(err);
		}
  });
  })};


function search(Server_ID){
  return new Promise ( (resolve, reject) => {
    r.table('servers').get(Server_ID).run(connection, function(err, cursor) {
    if (err) throw err;
      var lookup = JSON.stringify(cursor, null, 2);
      return resolve(lookup);
    });
})};


function list_all(id){
  return new Promise ( (resolve, reject) => {
    r.table('servers').filter(function(row) {
  return row('permissions').contains(id);
}).run(connection, function(err, cursor) {
      var lookup = cursor.toArray();
      console.log(lookup);
      return resolve(lookup);
    });    
})};

function user_model(id){
  let profile;
  profile = "../avatars/" + id + ".png";
  return profile;
}
// export
function toCSV(json) {
  json = Object.values(json);
  var csv = "";
  var keys = (json[0] && Object.keys(json[0])) || [];
  csv += keys.join(',') + '\n';
  for (var line of json) {
    csv += keys.map(key => line[key]).join(',') + '\n';
  }
  return csv;
}
// Authentication
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  console.log(req.session);
  if (req.method == 'GET') req.session.returnTo = req.originalUrl;
  res.redirect('/');
}
function ensureUnauthenticated(req, res, next) {
  if (!req.isAuthenticated()) return next();
  console.log(req.session);
  if (req.method == 'GET') req.session.returnTo = req.originalUrl;
  res.redirect('/');
}
function loggedIn(req, res, next) {
    if (req.user) {
        next();
    } else {
        res.redirect('/login');
    }
}
function loggedOut(req, res, next) {
    if (req.user) {
      console.log("no user");
      res.redirect('/');
    } else {
      next();
    }
}
function nameCheck(req, res) {
if (req.isAuthenticated()) return req.user.username;
else {
      return "null";
    }
}
// User
function adduser(newusername, newpassword) {
  r.connect( {host: 'localhost', port: 28015}, function(err, conn) {
      if (err) throw err;
      connection = conn;
  }).then(res => {
             r.db(config.DB_Name).table('users').insert({
            username: newusername,
            password: bcrypt.hashSync(newpassword),
            roll: 0
          }).run(connection, function(err, res) {
            console.log('Created default user: newusername');
          });
    })
}
function displayname(username){
let displayname = username;
let defaultPhrase = "Unknown User";
let phrase = (typeof displayname === "undefined" ? defaultPhrase : displayname);
return displayname;

}