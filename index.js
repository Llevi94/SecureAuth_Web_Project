import express from "express";
import bodyParser from "body-parser";
import pg from "pg"; //pgAdmin
import bcrypt from "bcrypt"; //encryption
import passport from "passport"; //passport
import { Strategy } from "passport-local"; //passport.use strategy
import session from "express-session"; //session and cookie
import GoogleStrategy from "passport-google-oauth2"; //google oauth
import env from "dotenv"; //env file

const app = express();
const port = process.env.SERVER_PORT || 3000;
const saltRounds = 10; //encryption rounds
env.config();

app.use(express.static("public"));

//**cookie Auth session */
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // one day cookie
    },
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public")); //static files

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  //db connection
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  ssl: true,
});
db.connect();

const year = new Date().getFullYear();

app.get("/", (req, res) => {
  res.render("home.ejs", { year: year });
});

app.get("/login", (req, res) => {
  res.render("login.ejs", { year: year });
});

app.get("/register", (req, res) => {
  res.render("register.ejs", { year: year });
});

app.get("/close", (req, res) => {
  res.render("home.ejs", { year: year });
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/welcome", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    //session check - if on
    res.render("welcome.ejs", { year: year });
  } else {
    //if off
    res.redirect("/login");
  }
});

/**get req to login or register with google */
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/welcome",
  passport.authenticate("google", {
    successRedirect: "/welcome",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

/**execute the strategy and determine subsequent actions based on its response*/
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/welcome",
    failureRedirect: "/login",
  })
);
//**New User Registration Sign Up */
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    //checks if the email is already registered
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      //already registered
      res.redirect("/login");
    } else {
      //not registered
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        //encryption
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            console.log(err);
            res.redirect("/welcome");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

//**Login with username and password*/
passport.use(
  "local", //Login
  /**verifies user input against the database to ensure accuracy*/
  new Strategy(async function verify(username, password, cb) {
    //passport strategy
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          //comparison between 2 hashes
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

//**connect with google oauth*/
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID, //the client ID
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, //the client secret
      callbackURL: "https://secureauth-ewdg.onrender.com/auth/google/welcome", //the url we choose on the console - where to go after login
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", // user information from the URL
      //callback function in the moment this success
    },
    async (accessToken, refreshToken, profile, cb) => {
      //extracts and stores relevant parts of the user's profile in our database
      console.log(profile);
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]); //check if this email is already signup
        if (result.rows.length === 0) {
          // if not
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          ); //create new user to the db
          cb(null, newUser.rows[0]);// call back function
        } else {
          //Already exists
          cb(null, result.rows[0]); //user info from the db
        }
      } catch {
        cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
