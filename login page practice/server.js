const express = require('express');
const path =  require('path');
const app =  express( );
const bodyParser = require('body-parser');
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwtlib = require('jsonwebtoken')

const JWT_SECRET = 'sdjkfh8923yhjdksbfma@#*(&@*!^#&@bhjb2qiuhesdbhjdsfg839ujkdhfjk'

const port = 8000;

mongoose.connect('mongodb://127.0.0.1:27017/login-app-db',{
    useNewUrlParser: true,
	useUnifiedTopology: true,
	useCreateIndex: true
})
app.use('/', express.static(path.join(__dirname, 'static')));
app.use(bodyParser.json());

app.post('/api/change-password', async (req, res) => {
	const { token, newpassword: plainTextPassword } = req.body

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	try {
		const user = jwtlib.verify(token, JWT_SECRET)

		const _id = user.id

		const password = await bcrypt.hash(plainTextPassword, 10)

		await User.updateOne(
			{ _id },
			{
				$set: { password }
			}
		)
		res.json({ status: 'ok' })
	} catch (error) {
		console.log(error)
		res.json({ status: 'error', error: ';))' })
	}
})

app.post('/api/login', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}

	if (await bcrypt.compare(password, user.password)) {
		// the username, password combination is successful

		const token = jwtlib.sign(
			{
				id: user._id,
				username: user.username
			},
			JWT_SECRET
		)

		return res.json({ status: 'ok', data: token })
	}

	res.json({ status: 'error', error: 'Invalid username/password' })
})





app.post('/api/register',async(req,res)=>{
    console.log(req.body)
const { username , password: plainTextPassword}= req.body;
if (!username || typeof username !== 'string') {
    return res.json({ status: 'error', error: 'Invalid username' })
}

if (!plainTextPassword || typeof plainTextPassword !== 'string') {
    return res.json({ status: 'error', error: 'Invalid password' })
}

if (plainTextPassword.length < 5) {
    return res.json({
        status: 'error',
        error: 'Password too small. Should be atleast 6 characters'
    })
}
const password= await bcrypt.hash(plainTextPassword, 10);

try {
    const response = await User.create({
        username,
        password
    })
    console.log('User created successfully: ', response)
} catch (error) {
    if (error.code === 11000) {
        // duplicate key
        return res.json({ status: 'error', error: 'Username already in use' })
    }
    throw error
    // console.log(JSON.stringify(error))
}
res.json({ status: 'ok' })

})


// app.post('/users', async (req, res) => {
// 	const { token } = req.body

// 		try {
// 		const user = jwt.verify(token, JWT_SECRET)

// 		const _id = user.id

// 		// const password = await bcrypt.hash(plainTextPassword, 10)

// 		await User.find(
// 			{ _id },
// 			{
// 				$set: { password }
// 			}
// 		)
// 		res.json({ status: 'ok' })
// 	} catch (error) {
// 		console.log(error)
// 		res.json({ status: 'error', error: ';))' })
// 	}
// })



app.listen(port , (req,res)=>{
    console.log(`server is running on ${port}` )
})



