const { createClient } = require("@supabase/supabase-js");
const jose = require("jose");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || "propertydesk123";

function setCORS(res){
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,PUT,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers","Content-Type,Authorization");
}

async function verifyJWT(token){
  try{
    const { payload } = await jose.jwtVerify(
      token,
      new TextEncoder().encode(JWT_SECRET)
    );
    return payload;
  }catch{
    return null;
  }
}

module.exports = async function handler(req,res){
  setCORS(res);
  if(req.method==="OPTIONS") return res.status(200).end();

  const auth = req.headers.authorization;
  if(!auth) return res.status(401).json({error:"No token"});
  const token = auth.split(" ")[1];
  const user = await verifyJWT(token);
  if(!user) return res.status(401).json({error:"Invalid token"});

  const isAdmin = user.role === "ADMIN";

  // ---------- GET ----------
  if(req.method==="GET"){
    const { data, error } = await supabase
      .from("properties")
      .select("*")
      .order("project");

    if(error) return res.status(500).json({error:error.message});

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

    return res.json({ role:user.role, properties:data });
  }

  // ---------- ADMIN ONLY ----------
  if(!isAdmin) return res.status(403).json({error:"Forbidden"});

  // ---------- POST ----------
  if(req.method==="POST"){
    const { error } = await supabase.from("properties").insert([req.body]);
    if(error) return res.status(500).json({error:error.message});
    return res.json({success:true});
  }

  // ---------- PUT ----------
  if(req.method==="PUT"){
    const { id, ...rest } = req.body;
    const { error } = await supabase
      .from("properties")
      .update(rest)
      .eq("id", id);
    if(error) return res.status(500).json({error:error.message});
    return res.json({success:true});
  }

  res.status(405).json({error:"Method not allowed"});
};
