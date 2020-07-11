const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const passport = require('passport')

//User Model
const User = require('../models/User')

//login
router.get('/login', (req, res) => res.render('login'))
//register
router.get('/register', (req, res) => res.render('register'))

//register Handle
router.post('/register', (req, res)=> {
    const { name, email, password, password2} = req.body
    let error = []

    //check required fields
    if(!name || !email || !password || !password2 ){
        error.push({msg: 'Please fill in all the fields'})
    }

    //check password
    if(password !== password2){
        error.push({msg: 'Password do not match'})
    }

    //check password length
    if(password.length < 6 ){
        error.push({msg: 'Password should be at least 6 characters'})
    }

    if(error.length >0){
        res.render('register', {
            error,
            name,
            email,
            password,
            password2
        })
    }else{
        //validation passed

        User.findOne({email:email})
        .then((user) => {
            if(user){
                //user exists
                error.push({msg: 'Email is already registered'})
                res.render('register', {
                    error,
                    name,
                    email,
                    password,
                    password2
                })
            }else{
                const newUser = new User({
                    name,
                    email,
                    password
                })
                //hash password
                bcrypt.genSalt(10, (err, salt) => bcrypt.hash(newUser.password, salt, (err, hash)=>{
                    if(err) throw err

                    //set password to hash
                    newUser.password = hash

                    //save user
                    newUser.save()
                    .then(()=>{
                        req.flash('success_msg', 'You are now registered and can log in')
                        res.redirect('/users/login')
                    })
                    .catch(err => console.log(err))
                }))
            }
        })
    }
})

router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next)
})

router.get('/logout', (req, res) => {
    req.logout()
    req.flash('success_msg', 'You are successfully logout')
    res.redirect('/users/login')
})

module.exports = router