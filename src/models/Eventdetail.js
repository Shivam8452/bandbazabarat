const mongoose = require("mongoose");
const eventDetailSchema = new mongoose.Schema({
	user:{
        type:mongoose.Schema.Types.ObjectId,
		ref:"Register",
        required:true
	},
	cart:{
		type:Object,
		required:true

	},
	name:{
		type:String,
		required:true
	},
	email:{
		type:String,
		required:true,
	},
	phone:{
		type:Number,
		required:true
	},
	event_date:{
		type:String,
		required:true,
	},
	event_type:{
		type:String,
		required:true
	},
	from_address:{
		type:String,
		required:true
	},
	to_address:{
		type:String,
	},
	orderId: {
		type: String,
		required: true
	},
	receiptId: {
		type: String
	},
	paymentId: {
		type: String,
	},
	signature: {
		type: String,
	},
	amount: {
		type: Number
	},
	currency: {
		type: String
	},
	createdAt: {
		type: Date,
		default:Date.now()
	},
	order_status:{
		type:String,
		default:'Booked'
	},
	status: {
		type: String
	}
})

const EventDetail = new mongoose.model("EventDetail" , eventDetailSchema);
module.exports = EventDetail;