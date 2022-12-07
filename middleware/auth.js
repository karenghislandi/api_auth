const jwt =require("jsonwebtoken");

const validaToken=(req,res,next)=>{

    const authHader= req.headers["authorization"]
    const token= authHader && authHader.split(" ")[1];

    
    if(!token){
        return res.status(401).json({msg: "Acesso negado!"})
    }

    try{
        const secret=process.env.JWT_SECRET
        jwt.verify(token,secret)
        next()

    }catch(error){
        res.status(401).json({msg: "Token invalido"})

    }
    }
    

   

module.exports = validaToken;
