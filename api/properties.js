const { createClient } = require("@supabase/supabase-js");
const jose = require("jose").default;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const JWT_SECRET = process.env.JWT_SECRET || "propertydesk123";

function corsHeaders(res){
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
}

async function verifyJWT(token){
  try{
    const { payload } = await jose.jwtVerify(token, new TextEncoder().encode(JWT_SECRET));
    return payload;
  }catch{
    return null;
  }
}

module.exports = async function handler(req,res){
  corsHeaders(res);
  if(req.method==="OPTIONS") return res.status(200).end();

  const authHeader = req.headers.authorization;
  if(!authHeader) return res.status(401).json({error:"No token"});
  const token = authHeader.split(" ")[1];
  const payload = await verifyJWT(token);
  if(!payload) return res.status(401).json({error:"Invalid token"});
  const isAdmin = payload.role==="ADMIN";

  try{
    if(req.method==="GET"){
      const { data, error } = await supabase.from("properties").select("*").order("project");
      if(error) throw error;
      const today = new Date();
      data.forEach(p=>{
        if(p.end_date){
          const diff = (new Date(p.end_date)-today)/(1000*60*60*24);
          if(diff<=60 && diff>=0) p.status="Expiring";
        }
        if(!isAdmin){
          delete p.owner_name;
          delete p.owner_phone;
        }
      });
      return res.json({role: payload.role, properties:data});
    }

    if(!isAdmin) return res.status(403).json({error:"Forbidden"});

    if(req.method==="POST"){
      const { error } = await supabase.from("properties").insert([req.body]);
      if(error) throw error;
      return res.json({success:true});
    }

    if(req.method==="PUT"){
      const id = req.body.id;
      if(!id) return res.status(400).json({error:"Missing id"});
      const { error } = await supabase.from("properties").update(req.body).eq("id", id);
      if(error) throw error;
      return res.json({success:true});
    }

    return res.status(404).json({error:"Not found"});
  }catch(e){
    console.error("Properties error:", e);
    return res.status(500).json({error:"Internal server error"});
  }
};
