const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const task = require('./tasks')
const Task = require('./tasks')

const userSchema = new mongoose.Schema(
    {
        name:{
            type: String,
            require: true,
            trim:true
        },
        email:{
            type: String,
            unique:true,
            required: true,
            trim:true,
            lowercase:true,
            validate(value){
                if(!validator.isEmail(value)){
                    throw new Error ('Email is invalid.')
                }
            }
        },
        password:{
            type:String, 
            required:true,
            minlength:7,
            trim:true,
            validate(value){
                if(value.toLowerCase().includes('password')){
                    throw new Error ('Password cannot contaion "password".')
                }
            }
        },
        age:{
            type: Number,
            default:0,
            validate(value){
                if(value < 0){
                    throw new Error ('Age must be a positive number.')
                }
            }
        },
       tokens: [{
           token: String,
            // required:true
       }],
      avatar: {
          type:Buffer
      }
    },
    {
        timestamps: true
    })




userSchema.virtual('tasks',{
    ref: 'Task',
    localField:'_id',
    foreignField:'owner'
})

userSchema.methods.toJSON = function (){
    const user = this
    const userObject = user.toObject()

    delete userObject.password
    delete userObject.tokens
    delete userObject.avatar

    return userObject
}   

userSchema.methods.generateAuthToken = async function (){
    const user = this
    const token = jwt.sign( { _id:user._id.toString() },process.env.JWT_SECRET)
    user.tokens = user.tokens.concat({token})
    await user.save()
    return token
}

userSchema.statics.findByCredentials = async (email, password) =>{
    const user = await User.findOne( {email} )  
    if(!user){
        throw new Error ('Unable to login')
    }

    const isMatched = await bcrypt.compare(password, user.password)
    if(!isMatched){
        throw new Error ('Unable to login')
    }
 return user
}


//Hash the plain text password before saving
userSchema.pre('save',async function(next){
    const user = this
   // console.log('this is before  saving')
   if(user.isModified('password')){
       user.password = await bcrypt.hash(user.password,8)
   }
    next() 
})

//Deletes the task when user is removed
userSchema.pre('remove', async function(next){
    const user = this
    await Task.deleteMany({owner:user._id})
    next()
})

const User = mongoose.model('User' ,userSchema)

module.exports = User