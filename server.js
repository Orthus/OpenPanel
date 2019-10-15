const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const r = require('rethinkdb');
const path = require('path');
const flash = require('connect-flash');
const bcrypt = require('bcrypt-nodejs');
var passport = require('passport');
const local = require('passport-local').Strategy;
const exec = require('child_process').exec;
const args = process.argv;
const config = require(__dirname + '/config.json');
const fs = require('fs');
const util = require('util');
const http = require('http');
const fileUpload = require('express-fileupload')
const log_file = fs.createWriteStream(__dirname + '/debug.log', {flags : 'w'});
const log_stdout = process.stdout;
const favicon = require('serve-favicon');
console.log = function(d) { //
  log_file.write(util.format(d) + '\n');
  log_stdout.write(util.format(d) + '\n');
};
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
const webport = config.Port;
const address = config.IP_Address;
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
  });});});
//
app.get('/', function (req, res) {
  page_processer(req.isAuthenticated(), "Home", "index", "index", "home", "null", req, res);
});
app.get('/login', loggedOut, function (req, res) {
  page_processer(req.isAuthenticated(), "Account", "login", "index", "home", "null", req, res);
});
app.get('/register', loggedOut, function (req, res) {
  page_processer(req.isAuthenticated(), "Account", "register", "index", "home", "null", req, res);
 });
app.get('/account', loggedIn, function (req, res) {
  page_processer(req.isAuthenticated(), "Account", "index", "index", "account", "null", req, res);
});
app.get('/about', function (req, res) {
  page_processer(req.isAuthenticated(), "About", "index", "index", "about", "null", req, res);
});
app.get('/settings', loggedIn, function (req, res) {
  page_processer(req.isAuthenticated(), "Settings", "index", "index", "settings", "null", req, res);
});
app.get('/dashboard', loggedIn, function (req, res) {
  page_processer(req.isAuthenticated(), "Dashboard", "index", "overview", "dashboard", "null", req, res);
});
app.get('/dashboard/:page', loggedIn, function (req, res) {
  page_processer(req.isAuthenticated(), "Dashboard", "index", req.params.page, "dashboard", "null", req, res)
});
app.get('/server/:Server_ID', loggedIn, function (req, res) {
  page_processer(req.isAuthenticated(), "Dashboard", "server_page", req.params.page, "server", req.params.page, req, res)
});
app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});
app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login',
      failureFlash: true }), function(req, res) {
        if (req.body.remember) {
          req.session.cookie.maxAge = 1 * 24 * 60 * 60 * 1000; // Cookie expires after 1 day
        } else {
          req.session.cookie.expires = false;}
      res.redirect('/dashboard');
});
app.post('/register', function (req, res) {
  adduser(req.body.newusername, req.body.newpassword);
  res.render('template', {authed: req.isAuthenticated(), content:'register', path:'home', result: null, error: null, active: "Home"});
});
app.post('/settings', function (req, res) {
  let send = update_settings();
  res.redirect('/settings');
});
app.post('/update/:Server_ID', function (req, res) {
  let send = update();
  res.render('index', {result: null, error:null});
});
app.post('/create_Server', function (req,res) {
  let send = instance_init(req.body.Game, req.body.Slots, req.body.IP_Address, req.body.Hostname, req.body.ServerName, req.user.id, req.body.RAM_Value, req.body.Storage_Value, req.body.Backup_Value);
  res.redirect('/dashboard');
})
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
function page_processer(auth , active, passed_content, passed_page, passed_path, serverid, req, res){
  if(auth){
    let lookup = data_model("users", req.user.id).then(data => {
    let user_obj = JSON.parse(data);
    let list = list_servers(req.user.id).then(data => {
    res.render('template', {authed: auth, content: passed_content, page: passed_page, path: passed_path, user: user_obj, result: data, active: active});
    }).catch(err => {
  });})}
  else{
    let db_object = {theme:"/css/dark.css", id:"null", profile:"../images/avatars/profile.png", username:"null"};
    let stringed_object = JSON.parse(JSON.stringify(db_object, null, 2))
    res.render('template', {authed: auth, content: passed_content, page: passed_page, path: passed_path, user: stringed_object, result: "null", active: active});
  }};
function instance_init(game, slots, ip, hostname, name, owner, ram, storage, backup){
  return new Promise ( (resolve, reject) => {
    let permissions = [owner];
	  r.table("servers").insert({game: game, slots: slots, ip: ip, hostname: hostname, name: name, owner: owner, ram: ram, storage: storage, backup: backup, status: "OFFLINE", permissions: permissions})
    .run(connection, function(err, cursor){
		if (err) {
			return reject(err);
}});})};
function list_servers(id){
  return new Promise ( (resolve, reject) => {
    r.table('servers').filter(function(row) {
  return row('permissions').contains(id);
}).run(connection, function(err, cursor) {
      let lookup = cursor.toArray();
      return resolve(lookup);
});})};
function data_model(table, id){
  return new Promise ( (resolve, reject) => {
  r.table(table).get(id).run(connection, function(err, cursor) {
    if (err) throw err;
    let db_object = cursor;
    if (table == "users"){
      let profile = "../images/avatars/" + id + ".png";
      db_object['profile'] = profile;
      stringed_object = JSON.stringify(db_object, null, 2)
      return resolve(stringed_object);
    } 
    else{return resolve(db_object);}
});})};
function loggedIn(req, res, next) {
    if (req.user) {next();
    } else {
        res.redirect('/login');
}}
function loggedOut(req, res, next) {
    if (req.user) { res.redirect('/');
    } else {
      next();
}}
function adduser(newusername, newpassword) {
            r.db(config.DB_Name).table('users').insert({
            username: newusername,
            password: bcrypt.hashSync(newpassword),
            roll: 0,
            theme: "dark"
          }).run(connection, function(err, res){});
}