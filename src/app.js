const express = require("express");
const path = require("path");
const app = express();
const hbs = require("hbs");
const bcrypt =require("bcryptjs");
const dotenv = require("dotenv").config();
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cookieparser = require("cookie-parser");
const multer = require("multer");
const mongoose = require("mongoose");
const session = require("express-session");
const flash = require("express-flash");
const MongoDbstore = require("connect-mongo")(session);
const Razorpay = require('razorpay')
const { nanoid } = require("nanoid");
const expressHbs = require('express-handlebars');
const FirebaseStorage = require('multer-firebase-storage')





require("./db/conn");
const User = require("./models/feedback");
const Register = require("./models/register");
const Shop = require("./models/shops");
const Cart = require("./models/addtocart");
const EventDetail = require("./models/Eventdetail");
const VerifiedShop = require("./models/VerifiedShop");
const Cars = require("./models/addcar");
const CarBooking = require("./models/BookedCars")







const {loginrequired} = require("../config/JWT");
const {checkAdmin} = require('../config/authadmin');
const {verifyEmail} = require("../config/verifyemail");
const res = require("express/lib/response");
const { handlebars } = require("hbs");
const { render } = require("express/lib/response");
const { findById } = require("./models/feedback");






const port = process.env.PORT || 3000;
const static_path = path.join(__dirname, "../public");
const templates_path = path.join(__dirname, "../templates/views");
const partials_path = path.join(__dirname, "../templates/partials");



// razorpay integration with shops
let razorPayInstance = new Razorpay({
	key_id: process.env.RAZORPAY_ID,
	key_secret: process.env.RAZORPAY_SECRET
})

let mongoStore = new MongoDbstore({
    mongooseConnection: mongoose.connection,
    collection: "sessions"
})


app.use(session({
    secret: process.env.COOKIE_SECRET,
    resave:false,
    store:mongoStore,
    saveUninitialized:false,
    cookie:{ maxAge: 1000 * 60 * 60 * 24}
}));

app.use(flash());
app.use(express.json());
app.use(express.urlencoded({extended:false}));
app.use(express.static(static_path));
app.use(cookieparser());
app.set("view engine", "hbs");
app.set("views", templates_path);
hbs.registerPartials(partials_path);
app.use(function(req, res, next){
    res.locals.session = req.session;
    next();
})
app.use((req,res,next)=>{
    res.locals.message = req.session.message;
    delete req.session.message
    next();
})
handlebars.registerHelper("divide", function(thing1, thing2) {
    return thing1 / thing2;
});
handlebars.registerHelper('ifCond', function(v1, v2, options) {
    if(v1 === v2) {   
    return options.fn(this);
      
    }
    return options.inverse(this);
})
handlebars.registerHelper('checkIf', function(v1, v2, options) {
    if(v1 != v2) {   
    return options.fn(this);
      
    }
    return options.inverse(this);
})





app.get("/",(req, res) => {
    let loggedin = req.cookies.jwt || null
    res.render("index1",{loggedin:loggedin})
});
app.get("/profile",loginrequired,(req,res)=>{
    EventDetail.find({user: req.user}, function(err, data){
        if(err){
            return res.write("Error!")
        }
        else{
            CarBooking.find({user:req.user}, function(err,doc){
                if(err){
                    return res.write("Error!")
                }
                else{
                    
                    var cart;
                    doc.forEach(function(order){
                        cart = new Cart(order.cart);
                        order.items = cart.generateArray();
                    })
                    res.render("profile",{
                        data:data,
                        user:req.user,
                        doc:doc
                    })
                }    
            })
        }
        
        
    }).clone().populate('user', '-Email -Password -tokens -isVerified -emailToken -Date').exec()
    
})
app.get('/mybookings',loginrequired,(req,res)=>{
    EventDetail.find({user: req.user}, function(err, data){
        if(err){
            return res.write("Error!")
        }
        else{
            CarBooking.find({user:req.user}, function(err,doc){
                if(err){
                    return res.write("Error!")
                }
                else{
                    
                    var cart;
                    doc.forEach(function(order){
                        cart = new Cart(order.cart);
                        order.items = cart.generateArray();
                    })
                    res.render("MyBookings",{
                        data:data,
                        doc:doc
                    })
                }    
            })
        }
        
        
    }).clone().populate('user', '-Email -Password -tokens -isVerified -emailToken -Date').exec()
})
app.get("/logout",loginrequired, async(req,res)=>{
    try {
        res.clearCookie("jwt")
        req.user.tokens = req.user.tokens.filter((currentelem)=>{
            return currentelem.token != req.token
        })
        await req.user.save();
        res.redirect("/login")
    } catch (error) {
        res.status(500).send(error)
    }
})
app.get("/register", (req, res) => {
    res.render("register");
});
app.get("/login", (req, res) => {
    res.render("login");
});
app.get("/partner",loginrequired, (req, res) => {
    res.render("partner");
});


// admin setup

// user
app.get("/admin-manageuser",checkAdmin,(req,res)=>{
    Register.find((err, data)=>{
        if(!err){
            res.render("manageuser", {
                title: "User",
                user: data
            });

        }
    }).lean()
    
})
app.get("/delete/:id",checkAdmin,(req,res)=>{
    Register.findByIdAndRemove(req.params.id,(err, data)=>{
        if(!err){
            res.redirect("/admin-manageuser");
        }
        else{
            console.log("Error in delete:"+ err);
        }
    })
    
})

//Shop Management
app.get("/Verify-Shop",checkAdmin, (req,res)=>{
    res.render("VerifiedShops")
})
app.get("/addCars",checkAdmin, (req,res)=>{
    res.render("AddCars")
})
app.get("/admin-manageAllShops",checkAdmin,(req,res)=>{
    Shop.find((err,data)=>{
        if(!err){
            res.render("AllShops",{
                title: "All Shops",
                allshop: data
            })
        }
    }).clone().populate('user', '-Password -tokens -isVerified -emailToken -Date').exec()
})
app.get("/delete/unverified/shop/:id",checkAdmin,(req,res)=>{
    Shop.findByIdAndRemove(req.params.id,(err, data)=>{
        if(!err){
            res.redirect("/admin-manageAllShops");
        }
        else{
            console.log("Error in delete:"+ err);
        }
    })
    
})
app.get("/admin-manageShops",checkAdmin,(req,res)=>{
    VerifiedShop.find((err, data)=>{
        if(!err){
            res.render("manageShops", {
                title: "Services",
                shop: data
            });

        }
    }).lean()
})
app.get("/delete-shop/:id",checkAdmin,(req,res)=>{
    VerifiedShop.findByIdAndRemove(req.params.id,(err, data)=>{
        if(!err){
            res.redirect("/admin-manageShops");
        }
        else{
            console.log("Error in delete:"+ err);
        }
    })
    
})


// Car Management
app.get("/admin-manageCars",checkAdmin,(req,res)=>{
    Cars.find((err, data)=>{
        if(!err){
            res.render("ManageCars", {
                title: "Services",
                shop: data
            });

        }
    }).lean()
})
app.get("/delete-Cars/:id",checkAdmin,(req,res)=>{
    Cars.findByIdAndRemove(req.params.id,(err, data)=>{
        if(!err){
            res.redirect("/admin-manageCars");
        }
        else{
            console.log("Error in delete:"+ err);
        }
    })
    
})

// Bookings Management
app.get("/admin-manageBookings",checkAdmin,(req,res)=>{
    EventDetail.find((err, data) =>{
        if(err){
            console.log("Error in retriving data :" + err);
           
        }
        else{
            CarBooking.find((err,doc)=>{
               if(err){
                console.log("Error in retriving data :" + err);
           
               } 
               else{
                var cart;
                doc.forEach(function(order){
                    cart = new Cart(order.cart);
                    order.items = cart.generateArray();
                })
                res.render("ManageBookings", {
                    title: "Bookings",
                    bookings: data,
                    cars: doc
                });

            }
            }).clone().populate('user', '-Password -tokens -isVerified -emailToken -Date').exec()
            
            
        }
    }).clone().populate('user', '-Password -tokens -isVerified -emailToken -Date').exec()
        
    })

// Manage FeedBacks
app.get("/admin-managefeedbacks",checkAdmin,(req,res)=>{
        User.find((err, data)=>{
            if(err){
                console.log("Error in retriving data :" + err);
    
            }
            else{
                res.render("managefeedbacks", {
                    title: "Feedbacks",
                    feedback: data
                });

            }
    }).lean()
})
app.get("/delete-feedback/:id",checkAdmin,(req,res)=>{
    User.findByIdAndRemove(req.params.id,(err, data)=>{
        if(!err){
            res.redirect("/admin-managefeedbacks");
        }
        else{
            console.log("Error in delete:"+ err);
        }
    })    
})


// cart handling
app.get("/services",loginrequired,(req, res) => {
function isMatching(a, b)
{
  return new RegExp("\\b(" + a.match(/\w+/g).join('|') + ")\\b", "gi").test(b);
}
let str1 = req.user.address

    VerifiedShop.find((err, data) =>{
        if(err){
            console.log("Error in retriving data :" + err);
           
        }
        else{
            EventDetail.find((err,doc)=>{
               if(err){
                console.log("Error in retriving data :" + err);
           
               } 
               else{
                let arrayToReturn = []
                data.forEach(element => {
                    if(isMatching(str1,element.address)){
                        arrayToReturn.push(element)
                    }                                        
                });
                // console.log(arrayToReturn)
                res.render("services",{
                    services: arrayToReturn,
                    doc:doc,
                    user:req.user
                });

            }
            })
            
            
        }
    })
});

app.get("/Cars",loginrequired, (req, res) => {
    Cars.find((err, data) =>{
        if(err){
            console.log("Error in retriving data :" + err);
           
        }
        else{
            CarBooking.find((err,doc)=>{
               if(err){
                console.log("Error in retriving data :" + err);
           
               } 
               else{
                var cart;
                doc.forEach(function(order){
                    cart = new Cart(order.cart);
                    order.items = cart.generateArray();
                })
                res.render("Cars",{
                    services: data,
                    doc:doc,
                    user:req.user
                });

            }
            })
            
            
        }
    })
});
app.get('/add-to-cart/:id', (req,res)=>{
    var serviceId = req.params.id;
    var cart = new Cart(req.session.cart ? req.session.cart :{items: {}});

    Cars.findById(serviceId, function(err, shop){
        if(err){
            return res.redirect("/Cars");
        }
        cart.add(shop, shop.id);
        req.session.cart = cart;
        res.redirect("/Cars")
        req.session.message={
            type: 'Success',
            intro: 'Car Added to List'
        }
    })
})
app.get("/reduce/:id", (req,res)=>{
    var serviceId = req.params.id;
    var cart = new Cart(req.session.cart ? req.session.cart:{});

    cart.reduceByOne(serviceId);
    req.session.cart = cart;
    res.redirect("/cart");
})
app.get("/remove/:id", (req,res)=>{
    var serviceId = req.params.id
    var cart = new Cart(req.session.cart ? req.session.cart:{});
    cart.removeItem(serviceId);
    req.session.cart = cart;
    res.redirect('/cart');
})
app.get("/cart",loginrequired, (req,res) =>{
    if(!req.session.cart){
        return res.render("cart",{services: null})
    }
    var cart = new Cart(req.session.cart);
    res.render("cart", {services: cart.generateArray(), totalPrice: cart.totalPrice})
})
app.get("/EventDetail",loginrequired, (req,res)=>{
    if(!req.session.cart){
        return res.redirect("/cart");
    }
    var cart = new Cart(req.session.cart);
    res.render("deliverydetail",{total: cart.totalPrice});
})


// handling single service booking
app.get('/book/:id',loginrequired, (req,res)=>{
    var serviceId = req.params.id;
    VerifiedShop.findById(serviceId, function(err, shop){
        if(err){
            return res.redirect("/services");
        }
        res.render("SingleBooking",{services: shop})
    })
})
app.post("/bookNow/:id",loginrequired, async(req,res)=>{
    var serviceId = req.params.id;
    VerifiedShop.findById(serviceId,function(err, shop){
        if(err){
            res.status(500).send(err)
        }
    params = {
        amount: shop.price * 100,
        currency: "INR",
        receipt: nanoid(),
        payment_capture: "1"
        }
        razorPayInstance.orders.create(params)
        .then(async (response) => {
        const razorpayKeyId = process.env.RAZORPAY_ID     
        const book = new EventDetail({
            user:req.user,
            cart:shop,
            name:req.body.name,
            email:req.body.email,
            phone:req.body.phone,
            event_date:req.body.event_date,
            event_type:req.body.event_type,
            from_address:req.body.from_address,
            to_address:req.body.to_address,
            orderId: response.id,
            receiptId: response.receipt,
            amount: response.amount,
            currency: response.currency,
            createdAt: response.created_at,
            order_status:req.body.order_status,
            status: response.status
        })
         try{
           await book.save()
           res.status(201).render("Single-checkout", {
                razorpayKeyId: razorpayKeyId,
                book : book
            });
        }
        catch(error){
        res.status(500).send(error)
        }
}).catch((err) => {
        if (err) throw err;
    })

})
    
})

app.post('/Booking/verify', async function(req, res, next) {
	body=req.body.razorpay_order_id + "|" + req.body.razorpay_payment_id;
	let crypto = require("crypto");
	let expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_SECRET)
							.update(body.toString())
							.digest('hex');

	
	if(expectedSignature === req.body.razorpay_signature) {
		
		await EventDetail.findOneAndUpdate(
			{ orderId: req.body.razorpay_order_id },
			{
				paymentId: req.body.razorpay_payment_id,
				signature: req.body.razorpay_signature,
				status: "paid"
			},
			{ new: true },
			function(err, doc) {
				// Throw er if failed to save
				if(err){
					throw err
				}
				// Render payment success page, if saved succeffully
				res.render('success', {
					shopData: doc
				})
			}
		).clone();
	} else {
		res.render('fail')
	}
});



// Guest house Booking
app.get('/Resortbooking/:id',loginrequired, (req,res)=>{
    var serviceId = req.params.id;
    VerifiedShop.findById(serviceId, function(err, shop){
        if(err){
            return res.redirect("/services");
        }
        res.render("GuestHouse",{services: shop})
    })
})
app.post("/BookResort/:id",loginrequired, async(req,res)=>{
    var serviceId = req.params.id;
    VerifiedShop.findById(serviceId,function(err, shop){
        if(err){
            res.status(500).send(err)
        }
    params = {
        amount: shop.price * 100,
        currency: "INR",
        receipt: nanoid(),
        payment_capture: "1"
        }
        razorPayInstance.orders.create(params)
        .then(async (response) => {
        const razorpayKeyId = process.env.RAZORPAY_ID     
        const book = new EventDetail({
            user:req.user,
            cart:shop,
            name:req.body.name,
            email:req.body.email,
            phone:req.body.phone,
            event_date:req.body.event_date,
            event_type:req.body.event_type,
            from_address:req.body.from_address,
            to_address:req.body.to_address,
            orderId: response.id,
            receiptId: response.receipt,
            amount: response.amount,
            currency: response.currency,
            createdAt: response.created_at,
            status: response.status
        })
         try{
           await book.save()
           res.status(201).render("Resort-checkout", {
                razorpayKeyId: razorpayKeyId,
                book : book
            });
        }
        catch(error){
        res.status(500).send(error)
        }
}).catch((err) => {
        if (err) throw err;
    })

})
    
})
app.post('/ResortBooking/verify', async function(req, res, next) {
	body=req.body.razorpay_order_id + "|" + req.body.razorpay_payment_id;
	let crypto = require("crypto");
	let expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_SECRET)
							.update(body.toString())
							.digest('hex');

	
	if(expectedSignature === req.body.razorpay_signature) {
		
		await EventDetail.findOneAndUpdate(
			{ orderId: req.body.razorpay_order_id },
			{
				paymentId: req.body.razorpay_payment_id,
				signature: req.body.razorpay_signature,
				status: "paid"
			},
			{ new: true },
			function(err, doc) {
				// Throw er if failed to save
				if(err){
					throw err
				}
				// Render payment success page, if saved succeffully
				res.render('success', {
					shopData: doc
				})
			}
		).clone();
	} else {
		res.render('fail')
	}
});



// Product Detail page
app.get("/ShopDetail/:id",loginrequired,(req,res)=>{
    var serviceId = req.params.id;
    VerifiedShop.findById(serviceId, function(err, shop){
        if(err){
            return res.redirect("/services");
        }
        res.render("shopdetail",{services: shop})
    })
})
app.get("/CarDetail/:id",loginrequired,(req,res)=>{
    var serviceId = req.params.id;
    Cars.findById(serviceId, function(err, shop){
        if(err){
            return res.redirect("/Cars");
        }
        res.render("cardetail",{services: shop})
    })
})






// mail sender
var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth:{
        user: 'business.bandbajabarat@gmail.com',
        pass : 'Suraj@123' 
    },
    tls:{
        rejectUnauthorized:false
    }
})



// register new user
app.post("/register", async (req,res) =>{
    
    try{
        const Password = req.body.Password;
        const cPassword = req.body.ConfirmPassword;
        if(Password === cPassword){
            const registerEmployee = new Register({

                            
                Name : req.body.Name,
                Email : req.body.Email,
                emailToken: crypto.randomBytes(64).toString('hex'),
                isVerified: false,
                Password : Password,
                ConfirmPassword : cPassword,
                address: req.body.address,
                termsprivacy:req.body.termsprivacy
            })

            const token = await registerEmployee.generateAuthToken();
            console.log("the token part" + token)

            res.cookie("jwt", token, {
                expires: new Date(Date.now() + 1000*60*60*24),
                httpOnly:true
            });
        
            await registerEmployee.save();

            // send varifiction mail to user
            var maiOptions = {
                from:' "verify You email" <noreply@gmail.com>',
                to: registerEmployee.Email,
                subject: 'BandBajaBarat -verify your email',
                html: `<h2> ${registerEmployee.Name}! Thanks for registering </h2>
                <h4> Please verify your email to continue... </h4>
                <a href="http://${req.headers.host}/verify-email?token=${registerEmployee.emailToken}"> Click here to verify</a>`
            }


            // sending mail
            transporter.sendMail(maiOptions, function(error, info){
                if(error){
                    console.log(error);
                    req.session.message = {
                        type: 'Warning',
                        intro: 'Oops! Something went wrong'
                    }
                }
                else{
                    console.log("Verfication email is sent to your gmail account");
                    

                }
            })
            req.session.message={
                type: 'Success',
                intro: 'Verification email is sent to your gmail'
            }
            res.redirect("/login")
            


        }else if(Password != cPassword){
            req.session.message = {
                type: 'Warning',
                intro: 'Password not matching!'
            }
            res.redirect("/register")
           
        }
    } catch (error){
        req.session.message={
            type: 'Warning',
            intro: 'Email already exists'
        }
        res.redirect("/register")
    }
});


app.get('/verify-email', async (req, res)=>{
    try{
        const token = req.query.token;
        const registerEmployee = await Register.findOne({ emailToken: token});
        if(registerEmployee){
            registerEmployee.emailToken = null
            registerEmployee.isVerified = true
            await registerEmployee.save();
            res.redirect('login');
        }
        else{
            res.redirect("/register");
            console.log("email is not verified");
        }
    }catch(err){
        console.log(err); 
    }
})









// check login
app.post("/login",verifyEmail, async (req, res) => {
    try{
     const email = req.body.email;
     const password = req.body.password;
    
    const useremail = await Register.findOne({Email:email});
    const isMatch = await bcrypt.compare(password, useremail.Password);
    const token = await useremail.generateAuthToken();
    
    res.cookie("jwt", token, {
        expires: new Date(Date.now() + 1000*60*60*24),
        httpOnly:true,
        secure:true
    });

    if(isMatch){
            res.redirect("/");
        

}else{
    req.session.message={
        type: 'Warning',
        intro: 'Invalid login details'
    }
    res.redirect("/login")
}
   } catch(error){
    res.status(400).send("Invalid");
       
   }
});

// change user address
app.post("/address/change", (req,res)=>{
    Register.updateOne({_id:req.body.userId},{address:req.body.address},(err,data)=>{
        if(err){
            res.redirect('/profile')
        }
        res.redirect('/profile')
    })
})


// feedback
app.post("/index1", async (req, res) =>{
    try{
        const userData = new User(req.body);
        await userData.save();
        res.redirect("/");
    } catch(error){
        res.status(500).send(error);
    }

})



const storage = FirebaseStorage({
    bucketName: process.env.FIREBASE_BUCKET_URL,
        credentials: {
          clientEmail: process.env.CLIENT_Email,
          projectId: process.env.FIREBASE_project_Id,
          privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        },
        directoryPath:'uploads',
        public:true
        
})
var upload = multer({
    storage: storage,
    limits:{
        fileSize: 1024*1024*1
    }
    
});
var multipleUpload = upload.fields([{name: "img_proof" ,maxCount: 1}, {name: "Banner_img",maxCount: 1}, {name:"passbook_img",maxCount: 1}]);






// add shops
app.post("/partner",multipleUpload,loginrequired, async (req, res) =>{
    params = {
		amount: 999 * 100,
		currency: "INR",
		receipt: nanoid(),
		payment_capture: "1"
	}
    razorPayInstance.orders.create(params)
    .then(async (response) => {
		const razorpayKeyId = process.env.RAZORPAY_ID
    
        const shopData = new Shop({
            user:req.user,
            name:req.body.name,
            email:req.body.email,
            phone:req.body.phone,
            img_proof:req.files.img_proof[0].originalname,
            address:req.body.address,
            shop_name:req.body.shop_name,
            price:req.body. price,
            type:req.body.type,
            Banner_img:req.files.Banner_img[0].originalname,
            what_includes:req.body.what_includes,
            bank_name:req.body.bank_name,
            branch:req.body.branch,
            ac_no:req.body.ac_no,
            ifsc:req.body.ifsc,
            holder_name:req.body.holder_name,
            passbook_img:req.files.passbook_img[0].originalname,
            isVerified: false,
            orderId: response.id,
			receiptId: response.receipt,
			amount: response.amount,
			currency: response.currency,
			createdAt: response.created_at,
			status: response.status

        });
    try{
        await shopData.save();
        res.status(201).render("checkout", {
            razorpayKeyId: razorpayKeyId,
			shopData : shopData
        });
    } catch(err){
        if (err) throw err;
    }
}).catch((err) => {
    if (err) throw err;
})

})


app.post('/verify', async function(req, res, next) {
	body=req.body.razorpay_order_id + "|" + req.body.razorpay_payment_id;
	let crypto = require("crypto");
	let expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_SECRET)
							.update(body.toString())
							.digest('hex');

	
	if(expectedSignature === req.body.razorpay_signature) {
		
		await Shop.findOneAndUpdate(
			{ orderId: req.body.razorpay_order_id },
			{
				paymentId: req.body.razorpay_payment_id,
				signature: req.body.razorpay_signature,
				status: "paid"
			},
			{ new: true },
			function(err, doc) {
				// Throw er if failed to save
				if(err){
					throw err
				}
				// Render payment success page, if saved succeffully
				res.render('success', {
					shopData: doc
				})
			}
		).clone();
	} else {
		res.render('fail')
	}
});





//cart checkout

app.post("/EventDetail",loginrequired, async (req, res) =>{
    if(!req.session.cart){
        return res.redirect("/cart");
    }
    var cart = new Cart(req.session.cart);

    params = {
		amount: cart.totalPrice * 100 ,
		currency: "INR",
		receipt: nanoid(),
		payment_capture: "1"
	}
    razorPayInstance.orders.create(params)
    .then(async (response) => {
		const razorpayKeyId = process.env.RAZORPAY_ID
        const eventData = new CarBooking({
            user:req.user,
            cart: cart,
            name:req.body.name,
            email:req.body.email,
            phone:req.body.phone,
            event_date:req.body.event_date,
            event_type:req.body.event_type,
            from_address:req.body.from_address,
            to_address:req.body.to_address,
            orderId: response.id,
			receiptId: response.receipt,
			amount: response.amount,
			currency: response.currency,
			createdAt: response.created_at,
            order_status:req.body.order_status,
			status: response.status
        })



    try{
        await eventData.save()
        res.status(201).render("cart-checkout", {
            razorpayKeyId: razorpayKeyId,
			eventData : eventData
        });
        
    } catch(err){
        if (err) throw err;
    }
    }).catch((err) => {
        if (err) throw err;
    })

})

app.post('/cart-verify', async function(req, res, next) {
	body=req.body.razorpay_order_id + "|" + req.body.razorpay_payment_id;
	let crypto = require("crypto");
	let expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_SECRET)
							.update(body.toString())
							.digest('hex');

	
	if(expectedSignature === req.body.razorpay_signature) {
		
		await CarBooking.findOneAndUpdate(
			{ orderId: req.body.razorpay_order_id },
			{
				paymentId: req.body.razorpay_payment_id,
				signature: req.body.razorpay_signature,
				status: "paid"
			},
			{ new: true },
			function(err, doc) {
				// Throw er if failed to save
				if(err){
					throw err
				}
				// Render payment success page, if saved succeffully
				res.render('success', {
					shopData: doc
				})
                req.session.cart = null;
			}
		).clone();
	} else {
		res.render('fail')
	}
});





// post request to add shops from admin
var singleupload = multer({
    storage:storage, 
    limits:{
        fileSize: 1024*1024*5
    }
}).single('shop_image');

app.post("/Verify-Shop",singleupload,async(req,res)=>{
    try{
        const verifiedData = new VerifiedShop({
            name:req.body.name,
            email:req.body.email,
            phone:req.body.phone,
            price:req.body.price,
            type:req.body.type,
            address:req.body.address,
            what_includes:req.body.what_includes,
            shop_image:req.file.originalname,
            username:req.body.username,
            password:req.body.password
        });
        await verifiedData.save();
        res.status(201).render("VerifiedShops");
    } catch(error){
        res.status(500).send(error);
    }
})

// Car post request
var carupload = multer({
    storage:storage, 
    limits:{
        fileSize: 1024*1024*5
    }
}).single('Car_image');

app.post("/addCars",carupload,async(req,res)=>{
    try{
        const CarData = new Cars({
            name:req.body.name,
            email:req.body.email,
            phone:req.body.phone,
            price:req.body.price,
            address:req.body.address,
            Car_image:req.file.originalname
        });
        await CarData.save();
        res.redirect("/addCars");
    } catch(error){
        res.status(500).send(error);
    }
})

// post request for status change
app.post("/bookingStatus/change", (req,res)=>{
    EventDetail.updateOne({_id:req.body.orderId},{order_status:req.body.order_status},(err,data)=>{
        if(err){
            res.redirect('/admin-manageBookings')
        }
        res.redirect('/admin-manageBookings')
    })
})
app.post("/subadmin/bookingStatus/change", (req,res)=>{
    EventDetail.updateOne({_id:req.body.orderId},{order_status:req.body.order_status},(err,data)=>{
        if(err){
            res.redirect('/subadmin/login')
        }
        res.status(201).send('Status Updated')
    })
})
app.post("/CarbookingStatus/change", (req,res)=>{
    CarBooking.updateOne({_id:req.body.orderId},{order_status:req.body.order_status},(err,data)=>{
        if(err){
            res.redirect('/admin-manageBookings')
        }
        res.redirect('/admin-manageBookings')
    })
})
// booking cancellation

app.get('/cancelBooking/:id',loginrequired,(req,res)=>{
     user = req.user
    CarBooking.findById(req.params.id,(err,data)=>{
        if(!err){
            var maiOptions = {
                from:`Cancel Booking ${user.Email}`,
                to: '<business.bandbajabarat@gmail.com>',
                subject: 'Booking Cancellation request',
                html: `<p>Please cancel my booking with id: ${data._id}</p>
                <p>Requested from user: ${user.Email}</p>
                <p>Of date: ${data.event_date}</p>`
            }

        }
        transporter.sendMail(maiOptions, function(error, info){
            if(error){
                console.log(error);
                req.session.message = {
                    type: 'Warning',
                    intro: 'Oops! Something went wrong'
                }
            }
            else{
                console.log("Verfication email is sent to your gmail account");
            }
        })
        res.redirect('/mybookings')

    })
})
app.get('/cancelServiceBooking/:id',loginrequired,(req,res)=>{
     user = req.user
    EventDetail.findById(req.params.id,(err,data)=>{
        if(!err){
            var maiOptions = {
                from:`Cancel Booking ${user.Email}`,
                to: data.cart.email,
                subject: 'Booking Cancellation request',
                html: `<p>Please cancel my booking with id: ${data._id}</p>
                <p>Requested from user: ${user.Email}</p>
                <p>Of date: ${data.event_date}</p>`
            }

        }
        transporter.sendMail(maiOptions, function(error, info){
            if(error){
                console.log(error);
                req.session.message = {
                    type: 'Warning',
                    intro: 'Oops! Something went wrong'
                }
            }
            else{
                console.log("email is sent to your gmail account");
            }
        })
        res.redirect('/mybookings')

    })
})






// Search
app.get('/autocomplete/',(req,res,next)=>{
    var regex = new RegExp(req.query["term"], 'i');
    var shopFilter = VerifiedShop.find({name:regex},{'name':1}).sort({"updated_at":-1}).sort({"created_at":-1}).limit(20);
    shopFilter.exec(function(err,data){
        var result = [];
        if(!err){
            if(data && data.length && data.length>0){
                data.forEach(user=>{
                    let obj ={
                        id:user._id,
                        label: user.name
                    };
                    result.push(obj);
                })
            }
            res.jsonp(result);
        }

    })
})

app.get('/subadmin/login',(req,res)=>{
    res.render('AdminLogin')
})
app.post("/subadmin/login", async (req, res) => {
    try{
     const username = req.body.username;
     const password = req.body.password;
    
    const useremail = await VerifiedShop.findOne({username:username});
    const isMatch = await bcrypt.compare(password, useremail.password);
    

    if(isMatch){
      await  EventDetail.find((err, data) =>{
            if(!err){
                res.render("SubadminBookings",{
                    data:data,
                    user:useremail
                });
    
            }
        }).clone().populate('user', '-Password -tokens -isVerified -emailToken -Date').exec()

}else{
    req.session.message={
        type: 'Warning',
        intro: 'Invalid login details'
    }
    res.redirect("/subadmin/login")
}
   } catch(error){
    res.status(400).send("Invalid");
       
   }
});
// privacy policy &tems
app.get('/privacy&policy',(req,res)=>{
    res.render('privacy')
})
app.get('/terms&conditions',(req,res)=>{
    res.render('terms')
})

app.listen(port, ()=>{
    console.log(`server is running at port no ${port}`);
});


