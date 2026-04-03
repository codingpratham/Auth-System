import express, { type Request, type Response } from "express"

const app = express()

app.get("/health",(req:Request,res:Response)=>{
    res.send("OK")
})

app.listen(3000,()=>{
    console.log("port is listened on the 3000");
    
})